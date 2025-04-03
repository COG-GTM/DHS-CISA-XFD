"""
Process recent WAS scans and insert findings.
 Retrieve recent scans and, for each scan ID, fetch findings and insert them.
"""
# Standard Python Libraries
import json
import logging
import os

# Third-Party Libraries
import requests

# Setup logging
LOGGER = logging.getLogger(__name__)

from dmz_mini_dl.models import WasFindings as MDL_WasFindings
pe_api_url = os.environ.get("PE_API_URL")
pe_api_key = os.environ.get("PE_API_KEY")


def api_was_finding_insert(finding_dict):
    """
    Insert a was finding record into the was_finding table.

    On conflict, update the old record with the new data

    Args:
        finding_dict: Dictionary of column names and values to be inserted

    Return:
        Status on if the record was inserted successfully
    """
    try:

        defaults={
            'finding_type': finding_dict.finding_type,
            'webapp_id': finding_dict.webapp_id,
            'webapp_url': finding_dict.webapp_url,
            'webapp_name': finding_dict.webapp_name,
            'was_org_id': finding_dict.was_org_id,
            'name': finding_dict.name,
            'owasp_category': finding_dict.owasp_category,
            'severity': finding_dict.severity,
            'times_detected': finding_dict.times_detected,
            'cvss_v3_attack_vector': finding_dict.cvss_v3_attack_vector,
            'base_score': finding_dict.base_score,
            'temporal_score': finding_dict.temporal_score,
            'fstatus': finding_dict.fstatus,
            'last_detected': finding_dict.last_detected,
            'first_detected': finding_dict.first_detected,
            'potential': finding_dict.potential,
            'cwe_list': finding_dict.cwe_list,
            'wasc_list': finding_dict.wasc_list,
            'last_tested': finding_dict.last_tested,
            'fixed_date': finding_dict.fixed_date,
            'is_ignored': finding_dict.is_ignored,
            'is_remediated': True if finding_dict.fstatus == "FIXED" else False,
            'url': finding_dict.url,
            'qid': finding_dict.qid,
            'response': finding_dict.response
        }

        try:
            mdl_was_finding_object, mdl_created = MDL_WasFindings.objects.update_or_create(
                finding_uid=finding_dict.finding_uid,
                defaults=defaults,
            )
        except Exception:
            LOGGER.info("Failed to insert WAS finding to MDL: %s", finding_dict.finding_uid)

        if created:
            LOGGER.info("Created new WAS finding record for %s", finding_dict.was_org_id)
            return {
                "message": "New WAS finding created.",
                "was_finding_obj": was_finding_object,
            }
        else:
            LOGGER.info("Updated WAS finding record for %s", finding_dict.was_org_id)
            return {
                "message": "WAS finding updated.",
                "was_finding_obj": was_finding_object,
            }
    except Exception as e:
        LOGGER.warning(e)
        LOGGER.info("Failed to insert or update WAS finding for %s", finding_dict.was_org_id)
        return {"message": "An error occurred while processing the WAS finding."}
