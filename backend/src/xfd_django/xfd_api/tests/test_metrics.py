"""Test metrics aggregation and upsert logic."""
# Standard Python Libraries
from datetime import datetime, timedelta, timezone

# Third-Party Libraries
import pytest
from xfd_api.tasks import metrics as metrics_mod
from xfd_mini_dl.models import CustomerMetrics, Organization, Role, User, UserType


@pytest.fixture
def frozen_now(monkeypatch):
    """
    Freeze metrics.dj_timezone.now() so _yesterday_utc() is stable.

    We pick 2025-09-04 12:00:00Z, so target_date is 2025-09-03.
    """
    fixed = datetime(2025, 9, 4, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(metrics_mod.dj_timezone, "now", lambda: fixed)
    monkeypatch.setattr("django.utils.timezone.now", lambda: fixed)
    return fixed


def _force_created_at(user, ts):
    # update() bypasses auto_now_add logic
    User.objects.filter(pk=user.pk).update(created_at=ts)
    user.refresh_from_db()
    return user


def _yesterday_window_from_metrics():
    start_dt, end_dt, target_date = metrics_mod._yesterday_utc()
    return start_dt, end_dt, target_date


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_creates_rows_for_all_regions_including_null(frozen_now):
    """Test that rows are created for all regions, including null region."""
    start_dt, end_dt, target_date = _yesterday_window_from_metrics()

    result = metrics_mod.collect_and_upsert_customer_metrics({}, {})
    rows = CustomerMetrics.objects.filter(date=target_date).order_by("region")
    expected_count = len(metrics_mod.REGIONS)

    assert result["date"] == target_date
    assert rows.count() == expected_count
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


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_active_orgs_and_external_org_filters(frozen_now):
    """Test that active organizations and external organization filters are applied correctly."""
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

    start_dt, end_dt, target_date = _yesterday_window_from_metrics()
    metrics_mod.collect_and_upsert_customer_metrics({}, {})

    cm = CustomerMetrics.objects.get(date=target_date, region=1)
    assert cm.active_orgs_without_users == 1
    assert cm.external_active_orgs == 1
    assert cm.external_retired_orgs == 1


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_external_and_cisa_users(frozen_now):
    """Test that external and CISA users are correctly counted during metrics aggregation."""
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

    start_dt, end_dt, target_date = _yesterday_window_from_metrics()
    metrics_mod.collect_and_upsert_customer_metrics({}, {})

    cm = CustomerMetrics.objects.get(date=target_date, region=2)
    assert cm.external_users == 1
    assert cm.cisa_users == 1


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_users_without_org_and_active_users_30d(frozen_now):
    """Test that users without organizations and active users within the last 30 days are correctly counted."""
    start_dt, end_dt, target_date = _yesterday_window_from_metrics()
    threshold = end_dt - timedelta(days=30)

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

    metrics_mod.collect_and_upsert_customer_metrics({}, {})

    cm = CustomerMetrics.objects.get(date=target_date, region=3)
    assert cm.users_without_org == 1
    assert cm.active_users == 1


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_users_created_and_approved_window_bounds(frozen_now):
    """Test that users created and approved within the specified time window are correctly counted."""
    start_dt, end_dt, target_date = _yesterday_window_from_metrics()

    u_in = User.objects.create(
        first_name="New",
        last_name="User",
        full_name="New User",
        email="new@ex.com",
        user_type=UserType.STANDARD,
        region_id="4",
        date_approved=start_dt + timedelta(hours=1),
    )
    _force_created_at(u_in, start_dt + timedelta(minutes=1))

    u_end = User.objects.create(
        first_name="Late",
        last_name="User",
        full_name="Late User",
        email="late@ex.com",
        user_type=UserType.STANDARD,
        region_id="4",
        date_approved=end_dt,
    )
    _force_created_at(u_end, end_dt)

    u_old = User.objects.create(
        first_name="Old",
        last_name="User",
        full_name="Old User",
        email="old@ex.com",
        user_type=UserType.STANDARD,
        region_id="4",
        date_approved=start_dt - timedelta(seconds=1),
    )
    _force_created_at(u_old, start_dt - timedelta(seconds=1))

    metrics_mod.collect_and_upsert_customer_metrics({}, {})

    cm = CustomerMetrics.objects.get(date=target_date, region=4)
    assert cm.users_created == 1
    assert cm.users_approved == 1


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_pending_count_and_mean_approval_time(frozen_now):
    """Test that the pending user count and mean approval time are calculated correctly."""
    start_dt, end_dt, target_date = _yesterday_window_from_metrics()

    u1 = User.objects.create(
        first_name="P1",
        last_name="User",
        full_name="P1 User",
        email="p1@ex.com",
        user_type=UserType.STANDARD,
        region_id="5",
        invite_pending=True,
    )
    _force_created_at(u1, end_dt - timedelta(days=2))

    u2 = User.objects.create(
        first_name="P2",
        last_name="User",
        full_name="P2 User",
        email="p2@ex.com",
        user_type=UserType.STANDARD,
        region_id="5",
        invite_pending=True,
    )
    _force_created_at(u2, end_dt - timedelta(days=4))

    metrics_mod.collect_and_upsert_customer_metrics({}, {})

    cm = CustomerMetrics.objects.get(date=target_date, region=5)
    assert cm.users_invite_pending == 2
    assert cm.mean_approval_time is not None
    assert abs(cm.mean_approval_time.total_seconds() - 3 * 24 * 3600) < 1.0


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_idempotent_update_or_create(frozen_now):
    """Test that the metrics aggregation and upsert logic is idempotent."""
    start_dt, end_dt, target_date = _yesterday_window_from_metrics()

    first = metrics_mod.collect_and_upsert_customer_metrics({}, {})
    second = metrics_mod.collect_and_upsert_customer_metrics({}, {})

    expected_rows = len(metrics_mod.REGIONS)
    assert CustomerMetrics.objects.filter(date=target_date).count() == expected_rows
    assert first["created"] == expected_rows
    assert first["updated"] == 0
    assert second["created"] == 0
    assert second["updated"] == expected_rows
