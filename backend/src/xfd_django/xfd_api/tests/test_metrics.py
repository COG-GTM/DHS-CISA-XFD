"""Streamlined tests for metrics aggregation, upsert, and CSV export."""
# Standard Python Libraries
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from typing import List, Tuple

# Third-Party Libraries
import pytest
from xfd_api.api_methods.export_customer_metrics import (
    _default_fieldnames,
    export_customer_metrics,
)
from xfd_api.tasks import metrics as metrics_mod
from xfd_mini_dl.models import CustomerMetrics, Organization, Role, User, UserType

pytestmark = pytest.mark.django_db(
    transaction=True, databases=["default", "mini_data_lake"]
)


# ---------- Shared fixtures & helpers ----------


@pytest.fixture
def clock(monkeypatch) -> Tuple[datetime, datetime, date]:
    """Freeze time consistently for metrics + CSV, and return (start_dt, end_dt, target_date)."""
    fixed = datetime(2025, 9, 4, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(metrics_mod.dj_timezone, "now", lambda: fixed)
    monkeypatch.setattr("django.utils.timezone.now", lambda: fixed)
    return metrics_mod._yesterday_utc()  # (start_dt, end_dt, target_date)


@pytest.fixture
def python_avg_pending(monkeypatch):
    """
    Monkeypatch for _collect_mean_wait_time_for_pending_users.

    Computes average whole days in Python and return a decimal, matching the CustomerMetrics.DecimalField.
    """

    def _impl(end_dt_inner):
        end_date = end_dt_inner.date()
        region_expr = metrics_mod._region_int_from_char("region_id")

        rows = (
            User.objects.filter(invite_pending=True, created_at__lte=end_dt_inner)
            .annotate(region_num=region_expr)
            .values("region_num", "created_at")
        )

        buckets = {}
        for r in rows:
            region = r["region_num"]
            days = (end_date - r["created_at"].date()).days
            buckets.setdefault(region, []).append(days)

        out = {}
        for region, vals in buckets.items():
            if not vals:
                continue
            avg_days = Decimal(sum(vals)) / Decimal(len(vals))
            out[region] = {"pending_count": len(vals), "avg_wait": avg_days}
        return out

    monkeypatch.setattr(metrics_mod, "_collect_mean_wait_time_for_pending_users", _impl)


def run_task():
    """Invoke the daily metrics job with the usual (event, context) no-ops."""
    return metrics_mod.collect_and_upsert_customer_metrics({}, {})


def force_created_at(user: User, ts: datetime) -> User:
    """Set created_at precisely (bypasses auto_now_add)."""
    User.objects.filter(pk=user.pk).update(created_at=ts)
    user.refresh_from_db()
    return user


def value_in_days(value) -> float:
    """Normalize timedelta/Decimal/float/int to a float days value."""
    if hasattr(value, "total_seconds"):
        return value.total_seconds() / 86400.0
    return float(value)


def parse_csv(csv_bytes: bytes) -> Tuple[List[str], List[List[str]]]:
    """Return (header, rows) from a CSV bytes blob."""
    lines = [line for line in csv_bytes.decode("utf-8").splitlines() if line.strip()]
    header = lines[0].split(",") if lines else []
    rows = [ln.split(",") for ln in lines[1:]]
    return header, rows


# ---------- Tests ----------


def test_creates_rows_for_all_regions_including_null(clock):
    """Test that all regions are generated, even if empty."""
    start_dt, end_dt, target_date = clock

    result = run_task()
    rows = CustomerMetrics.objects.filter(date=target_date).order_by("region")
    expected_count = len(metrics_mod.REGIONS)

    assert result["date"] == target_date
    assert rows.count() == expected_count

    # Spot-check a few empty regions
    for region in (None, 1, 10):
        cm = rows.get(region=region)
        assert cm.active_orgs_without_users == 0
        assert cm.external_active_orgs == 0
        assert cm.external_retired_orgs == 0
        assert cm.external_users == 0
        assert cm.cisa_users == 0
        assert cm.users_without_org == 0
        assert cm.users_created == 0
        assert cm.users_approved == 0
        assert cm.users_invite_pending == 0
        assert cm.active_users == 0
        assert cm.mean_approval_time is None


def test_active_orgs_and_external_org_filters(clock):
    """Test active_orgs_without_users, external_active_orgs, external_retired_orgs."""
    # Region '1'
    ext_active = Organization.objects.create(
        acronym="EXT1", retired=False, region_id="1", name="External Active 1"
    )
    Organization.objects.create(
        acronym="DHS_ABC", retired=False, region_id="1", name="DHS Active"
    )
    Organization.objects.create(
        acronym="EXT_RET", retired=True, region_id="1", name="External Retired"
    )

    u = User.objects.create(
        first_name="A",
        last_name="B",
        full_name="A B",
        email="a@example.org",
        user_type=UserType.STANDARD,
        region_id="1",
    )
    Role.objects.create(user=u, organization=ext_active)

    _, _, target_date = clock
    run_task()

    cm = CustomerMetrics.objects.get(date=target_date, region=1)
    assert cm.active_orgs_without_users == 1
    assert cm.external_active_orgs == 1
    assert cm.external_retired_orgs == 1


def test_external_and_cisa_users(clock):
    """Test external_users and cisa_users counts."""
    # Region '2'
    User.objects.create(
        first_name="Ext",
        last_name="User",
        full_name="Ext User",
        email="vendor@example.com",
        user_type=UserType.STANDARD,
        region_id="2",
    )
    User.objects.create(
        first_name="Dhs",
        last_name="User",
        full_name="Dhs User",
        email="someone@dhs.gov",
        user_type=UserType.STANDARD,
        region_id="2",
    )
    User.objects.create(
        first_name="Admin",
        last_name="User",
        full_name="Admin User",
        email="admin@vendor.com",
        user_type=UserType.GLOBAL_ADMIN,
        region_id="2",
    )
    User.objects.create(
        first_name="Cisa",
        last_name="User",
        full_name="Cisa User",
        email="person@cisa.dhs.gov",
        user_type=UserType.STANDARD,
        region_id="2",
    )

    _, _, target_date = clock
    run_task()

    cm = CustomerMetrics.objects.get(date=target_date, region=2)
    assert cm.external_users == 1
    assert cm.cisa_users == 1


def test_users_without_org_and_active_users_30d(clock):
    """Test users_without_org and active_users (last_logged_in within 30 days)."""
    start_dt, end_dt, target_date = clock
    threshold = end_dt - timedelta(days=30)

    # Region '3'
    User.objects.create(
        first_name="No",
        last_name="Org",
        full_name="No Org",
        email="noorg@example.com",
        user_type=UserType.STANDARD,
        region_id="3",
        last_logged_in=end_dt - timedelta(days=5),
    )
    u_with_org = User.objects.create(
        first_name="Has",
        last_name="Org",
        full_name="Has Org",
        email="hasorg@example.com",
        user_type=UserType.STANDARD,
        region_id="3",
        last_logged_in=threshold - timedelta(seconds=1),
    )
    org = Organization.objects.create(
        acronym="EXT3", retired=False, region_id="3", name="Org 3"
    )
    Role.objects.create(user=u_with_org, organization=org)

    run_task()
    cm = CustomerMetrics.objects.get(date=target_date, region=3)
    assert cm.users_without_org == 1
    assert cm.active_users == 1


def test_users_created_and_approved_window_bounds(clock):
    """Test users_created and users_approved with boundary conditions."""
    start_dt, end_dt, target_date = clock

    # inside window
    u_in = User.objects.create(
        first_name="New",
        last_name="User",
        full_name="New User",
        email="new@ex.com",
        user_type=UserType.STANDARD,
        region_id="4",
        date_approved=start_dt + timedelta(hours=1),
    )
    force_created_at(u_in, start_dt + timedelta(minutes=1))

    # exactly at end_dt -> excluded by "< end_dt"
    u_end = User.objects.create(
        first_name="Late",
        last_name="User",
        full_name="Late User",
        email="late@ex.com",
        user_type=UserType.STANDARD,
        region_id="4",
        date_approved=end_dt,
    )
    force_created_at(u_end, end_dt)

    # before start_dt -> excluded
    u_old = User.objects.create(
        first_name="Old",
        last_name="User",
        full_name="Old User",
        email="old@ex.com",
        user_type=UserType.STANDARD,
        region_id="4",
        date_approved=start_dt - timedelta(seconds=1),
    )
    force_created_at(u_old, start_dt - timedelta(seconds=1))

    run_task()
    cm = CustomerMetrics.objects.get(date=target_date, region=4)
    assert cm.users_created == 1
    assert cm.users_approved == 1


def test_pending_count_and_mean_approval_time(clock, python_avg_pending):
    """Test users_invite_pending and mean_approval_time calculations."""
    start_dt, end_dt, target_date = clock

    # Region '5': mean([2,4]) = 3.0 days
    u1 = User.objects.create(
        first_name="P1",
        last_name="User",
        full_name="P1 User",
        email="p1@ex.com",
        user_type=UserType.STANDARD,
        region_id="5",
        invite_pending=True,
    )
    force_created_at(u1, end_dt - timedelta(days=2))

    u2 = User.objects.create(
        first_name="P2",
        last_name="User",
        full_name="P2 User",
        email="p2@ex.com",
        user_type=UserType.STANDARD,
        region_id="5",
        invite_pending=True,
    )
    force_created_at(u2, end_dt - timedelta(days=4))

    run_task()
    cm = CustomerMetrics.objects.get(date=target_date, region=5)

    assert cm.users_invite_pending == 2
    assert cm.mean_approval_time is not None
    assert abs(value_in_days(cm.mean_approval_time) - 3.0) < 1e-6


def test_idempotent_update_or_create(clock):
    """Test that running the task twice updates existing rows, doesn't duplicate."""
    _, _, target_date = clock

    first = run_task()
    second = run_task()

    expected = len(metrics_mod.REGIONS)
    assert CustomerMetrics.objects.filter(date=target_date).count() == expected
    assert first["created"] == expected and first["updated"] == 0
    assert second["created"] == 0 and second["updated"] == expected


def test_export_csv_default_fieldnames_filters_yesterday_only(clock):
    """Test export_customer_metrics with default fields and yesterday filtering."""
    _, _, target_date = clock
    run_task()

    # Add older rows to prove filtering = yesterday only
    older_date = target_date - timedelta(days=2)
    CustomerMetrics.objects.create(date=older_date, region=None)
    CustomerMetrics.objects.create(date=older_date, region=1)

    filename, csv_bytes = export_customer_metrics()
    assert filename == f"cyhy_dashboard_customer_metrics_{target_date.isoformat()}.csv"

    header, rows = parse_csv(csv_bytes)
    assert header == _default_fieldnames(CustomerMetrics)
    assert len(rows) == len(metrics_mod.REGIONS)


def test_export_csv_with_explicit_fields_and_values(clock):
    """Test export_customer_metrics with explicit fields and known values."""
    _, _, target_date = clock
    run_task()

    cols = ("date", "region", "users_invite_pending")
    filename, csv_bytes = export_customer_metrics(fieldnames=cols)
    assert filename.endswith(f"{target_date.isoformat()}.csv")

    header, rows = parse_csv(csv_bytes)
    assert header == list(cols)
    assert len(rows) == len(metrics_mod.REGIONS)

    for idx in (0, len(rows) - 1):
        assert rows[idx][0] == target_date.isoformat()
        assert rows[idx][2] == "0"


def test_export_csv_raises_on_missing_date_field_candidates(clock):
    """Test export_customer_metrics raises ValueError if no date field candidates exist."""
    run_task()
    with pytest.raises(ValueError):
        export_customer_metrics(
            date_field_candidates=("does_not_exist", "also_missing")
        )
