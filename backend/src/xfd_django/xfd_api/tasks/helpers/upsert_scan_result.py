"""Helper function that upserts the timestamp of the latest result for each scan per organization."""
# Standard Python Libraries
import logging

# Third-Party Libraries
from django.utils import timezone
from xfd_mini_dl.models import Organization, Scan, ScanResult

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
LOGGER = logging.getLogger(__name__)


def upsert_scan_result(scan_id, organization_id, http_status=200):
    """Upsert timestamp of latest result saved for each organization per scan."""
    # Initialize scan and org variables for use in exception handling
    scan = scan_id
    org = organization_id
    try:
        scan_result = ScanResult.objects.filter(
            scan_id=scan_id, organization_id=organization_id, status=http_status
        ).first()
        org = Organization.objects.filter(id=organization_id).first().name
        scan = Scan.objects.filter(id=scan_id).first().name

        if scan_result:
            scan_result.latest_result_at = timezone.now()
            scan_result.save()
            LOGGER.info(
                "Updated latest result timestamp for scan: {}, organization: {}, and http status {}.".format(
                    scan, org, http_status
                )
            )
        else:
            ScanResult.objects.create(
                scan_id=scan_id,
                organization_id=organization_id,
                latest_result_at=timezone.now(),
                http_status=http_status,
            )
            LOGGER.info(
                "Inserted new latest result timestamp for scan: {}, organization: {}, and http status: {}.".format(
                    scan, org, http_status
                )
            )

    except Exception as e:
        LOGGER.error(
            "Error upserting latest result timestamp for scan: {}, organization: {}, and http status: {}.\n{}".format(
                scan, org, http_status, str(e)
            )
        )
