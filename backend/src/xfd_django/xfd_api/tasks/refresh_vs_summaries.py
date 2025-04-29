"""Run Summary population methods via a scan."""  # Standard Python Libraries
# Standard Python Libraries
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
LOGGER = logging.getLogger(__name__)
# Third-Party Libraries
from xfd_api.tasks.vulnScanningSync import (
    create_daily_host_summary,
    create_port_scan_service_summaries,
    create_port_scan_summary,
    create_vuln_scan_summary,
    enforce_latest_flag_port_scan,
)


def handler(event):
    """Retrieve and save NIST update alerts from the DMZ."""
    try:
        try:
            LOGGER.info("Flagging latest port scans.")
            enforce_latest_flag_port_scan()

        except Exception as e:
            LOGGER.error("error flagging latest port scans: %s", e)
        try:
            LOGGER.info("Creating Host summaries.")
            create_daily_host_summary()

        except Exception as e:
            LOGGER.error("error saving host summary: %s", e)

        try:
            LOGGER.info("Creating Port summaries.")
            create_port_scan_summary()

        except Exception as e:
            LOGGER.error("error saving Port summary: %s", e)
        try:
            LOGGER.info("Creating port service summaries.")
            create_port_scan_service_summaries()

        except Exception as e:
            LOGGER.error("error saving port service summary: %s", e)

        try:
            LOGGER.info("Creating VS summaries.")
            create_vuln_scan_summary()

        except Exception as e:
            LOGGER.error("error saving VS summary: %s", e)
        return {
            "statusCode": 200,
            "body": "DMZ NIST update completed successfully.",
        }
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}
