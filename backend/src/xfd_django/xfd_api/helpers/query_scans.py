"""Helper function to fetch scans, prefetch related organizations/tags, and annotate each scan with metrics."""
# Standard Python Libraries
from datetime import timedelta
from typing import Optional

# Third-Party Libraries
from django.db.models import Count, Q
from django.utils import timezone
from xfd_mini_dl.models import Scan

# Query this number of days back unless a value is provided in the function call.
default_window = 7


def query_scans(scan_id: Optional[str], window_days: int = default_window):
    """
    Fetch a scan or all scans.

    Prefetch related organizations/tags and count the number of organizations with
    results for each scan within a specified time window.
    """
    cutoff = timezone.now() - timedelta(days=window_days)

    scan_qs = Scan.objects.prefetch_related("organizations", "tags").annotate(
        orgs_with_results=Count(
            "scan_results__organization",
            filter=Q(scan_results__ingested_at__gte=cutoff),
            distinct=True,
        )
    )

    return scan_qs.get(id=scan_id) if scan_id else scan_qs.all()
