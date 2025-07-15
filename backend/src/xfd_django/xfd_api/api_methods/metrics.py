"""API methods for Admin Metrics dashboard."""
# Standard Python Libraries
from datetime import timedelta

# Third-Party Libraries
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone
from xfd_mini_dl.models import ScanResult

default_window = 7


def scan_daily_status_counts(scan_id: str, window_days: int, current_user):
    """Get daily HTTP status counts for a specific scan over a given time window."""
    cutoff = (timezone.now() - timedelta(days=window_days or default_window)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    return (
        ScanResult.objects.filter(scan_id=scan_id, logged_at__gte=cutoff)
        .annotate(date=TruncDate("ingested_at"))
        .values("http_status", "date")
        .annotate(count=Count("id"))
        .order_by("http_status", "date")
    )


def scans_org_count_by_status(window_days, current_user):
    """List scans and count distinct orgs for each http status in a given time window."""
    cutoff = (timezone.now() - timedelta(days=window_days or default_window)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    return (
        ScanResult.objects.filter(logged_at__gte=cutoff)
        .values("scan_id", "http_status")
        .annotate(count=Count("organization", distinct=True))
        .order_by("scan_id", "http_status")
    )
