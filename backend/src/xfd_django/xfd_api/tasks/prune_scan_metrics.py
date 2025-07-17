"""Scheduled task to prune scan metrics older than retention period."""
# Standard Python Libraries
from datetime import timedelta
import logging
import os

# Third-Party Libraries
from django.utils import timezone
from xfd_mini_dl.models import ScanResult

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
LOGGER = logging.getLogger(__name__)

# TODO: Add to parameter store
# Retention period for storing scan metrics in days
RETENTION_PERIOD = int(os.getenv("SCAN_METRICS_RETENTION_PERIOD", "90"))


def handler(command_options=None):
    """Prune scan metrics older than retention period."""
    cutoff = timezone.now() - timedelta(days=RETENTION_PERIOD)
    deleted, _ = ScanResult.objects.filter(scanned_at__lt=cutoff).delete()
    LOGGER.info(
        "[prune_scan_metrics] Deleted %d records older than %s.",
        deleted,
        cutoff.date().isoformat(),
    )
