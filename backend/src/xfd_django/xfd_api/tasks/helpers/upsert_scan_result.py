"""Helper function that upserts the timestamp of the latest result for each scan per organization."""

# Third-Party Libraries
from django.utils import timezone
from xfd_mini_dl.models import ScanResult


def upsert_scan_result(scan_id, organization_id):
    """Upsert timestamp of latest result saved for each organization per scan."""
    try:
        scan_result = ScanResult.objects.filter(
            scan_id=scan_id, organization_id=organization_id
        ).first()

        if scan_result:
            scan_result.latest_result_at = timezone.now()
            scan_result.save()
            print(
                "Updated timestamp for scan_id: {} and organization_id: {}.".format(
                    scan_id, organization_id
                )
            )
        else:
            ScanResult.objects.create(
                scan_id=scan_id,
                organization_id=organization_id,
                latest_result_at=timezone.now(),
            )
            print(
                "Inserted new scan result for scan_id: {} and organization_id: {}.".format(
                    scan_id, organization_id
                )
            )

    except Exception as e:
        print(
            "Error upserting scan result for scan_id: {} and organization_id: {}: {}".format(
                scan_id, organization_id, str(e)
            )
        )
