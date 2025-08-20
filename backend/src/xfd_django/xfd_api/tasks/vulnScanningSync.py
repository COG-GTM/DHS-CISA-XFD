"""Task for synchronizing vulnerability scanning data.

This module handles fetching, processing, and saving vulnerability scans,
port scans, hosts, and tickets from Redshift into the Django models.
"""

# Standard Python Libraries
import logging
import os

# Third-Party Libraries
from xfd_api.tasks.refresh_material_views import handler as refresh_materialized_views
from xfd_api.tasks.syncdb_task import synchronize
from xfd_api.tasks.utils.datetime_utils import freeze_window
from xfd_api.tasks.utils.mdl_insert_utils import fill_cidr_live_ips_bulk_update
from xfd_api.tasks.utils.vs_host_scans import create_daily_host_summary
from xfd_api.tasks.utils.vs_port_scans import (
    create_port_scan_service_summaries,
    create_port_scan_summary,
    fetch_port_scans_from_redshift,
)
from xfd_api.tasks.utils.vs_requests import fetch_orgs_from_redshift
from xfd_api.tasks.utils.vs_send_orgs_to_dmz import send_organizations_to_dmz
from xfd_api.tasks.utils.vs_tickets import fetch_tickets_from_redshift
from xfd_api.tasks.utils.vs_vuln_scans import (
    create_vuln_scan_summary,
    fetch_vuln_scans_from_redshift,
)
from xfd_api.utils.scan_utils.alerting import ScanExecutionError
from xfd_mini_dl.models import NMIServiceGroup, RiskyServiceGroup

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
    filename="vuln_scanning_sync.log",
)
LOGGER = logging.getLogger(__name__)
IS_LOCAL = os.getenv("IS_LOCAL")
SCAN_NAME = "VulnScanningSync"

VS_PULL_DATE_RANGE = os.getenv("VS_PULL_DATE_RANGE", "2")


def handler(event):
    """Handle execution of the vulnerability scanning sync task.

    This function serves as the entry point for triggering the synchronization
    process. It calls the `main` function and returns the appropriate response
    based on the execution outcome.

    Args:
        event (dict): The event data that triggers the function.

    Returns:
        dict: Response containing the status code and message.
    """
    print("VS_PULL_DATE_RANGE: ", VS_PULL_DATE_RANGE)
    try:
        main()
        return {"status_code": 200, "body": "VS Sync completed successfully"}
    except Exception as e:
        raise ScanExecutionError(SCAN_NAME, str(e), event) from e


def main():  # pylint: disable=R0915
    """Execute the vulnerability scanning synchronization task."""
    LOGGER.info("Started VulnScanningSync scan...")

    LOGGER.info("Running syncdb")
    synchronize(target_app_label="xfd_mini_dl")

    # Use fixed window + deterministic keyset on (time, _id)
    ps_start_dt, ps_end_dt = freeze_window(int(VS_PULL_DATE_RANGE))
    LOGGER.info("Frozen port-scan window: [%s .. %s)", ps_start_dt, ps_end_dt)

    # Load request data
    org_id_dict = fetch_orgs_from_redshift()
    # org_id_dict = fetch_org_id_dict_fast()

    # Process Vulnerability Scans
    fetch_vuln_scans_from_redshift(ps_start_dt, ps_end_dt, org_id_dict)

    # # Process Host Scans
    create_daily_host_summary(org_id_dict)

    LOGGER.info("Prefetching risky and NMI service groups...")
    # Prefetch risky service groups
    risky_service_groups = {
        rsg.service_name: rsg.group for rsg in RiskyServiceGroup.objects.all()
    }

    # Prefetch NMI service groups
    nmi_service_groups = {
        nsg.service_name: nsg.group for nsg in NMIServiceGroup.objects.all()
    }

    # Port Scans (Chunked)
    fetch_port_scans_from_redshift(
        org_id_dict, risky_service_groups, nmi_service_groups, ps_start_dt, ps_end_dt
    )

    # # Fill CIDR live IPs
    fill_cidr_live_ips_bulk_update()

    # # Send organizations to the DMZ MDL
    send_organizations_to_dmz()

    # Process Tickets (Chunked)
    fetch_tickets_from_redshift(
        org_id_dict, risky_service_groups, nmi_service_groups, ps_start_dt, ps_end_dt
    )

    # REFRESH MATERIALIZED VIEWS BEFORE CREATING SUMMARIES
    LOGGER.info("Refreshing materialized views before creating summaries...")
    # Create or refresh materialized views
    result = refresh_materialized_views({})
    LOGGER.info(result)
    LOGGER.info("Finished refreshing materialized views")

    # Create summaries with individual error handling
    LOGGER.info("Creating port scan summary...")
    try:
        create_port_scan_summary()
        LOGGER.info("Finished port scan summary")
    except Exception as e:
        LOGGER.error("Failed to create port scan summary: %s", e, exc_info=True)

    LOGGER.info("Creating port scan service summaries...")
    try:
        create_port_scan_service_summaries()
        LOGGER.info("Finished port scan service summaries")
    except Exception as e:
        LOGGER.error(
            "Failed to create port scan service summaries: %s", e, exc_info=True
        )

    LOGGER.info("Creating vulnerability scan summary...")
    try:
        create_vuln_scan_summary()
        LOGGER.info("Finished vulnerability scan summary")
    except Exception as e:
        LOGGER.error(
            "Failed to create vulnerability scan summary: %s", e, exc_info=True
        )
