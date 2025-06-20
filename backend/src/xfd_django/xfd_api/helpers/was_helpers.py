"""
Process recent WAS scans and insert findings.
 Retrieve recent scans and, for each scan ID, fetch findings and insert them.
"""
# Standard Python Libraries
import json
import logging
import os
from datetime import datetime, timedelta, timezone

# Third-Party Libraries
import requests
from retry import retry

# Setup logging
LOGGER = logging.getLogger(__name__)

from xfd_mini_dl.models import WasFindings as MDL_WasFindings

class InvalidQualysCall(Exception):
    """Raise When qualys returns an error."""
    pass
class InvalidApiCall(Exception):
    """Raise when the API call is invalid or no data is returned."""
    pass

def convert_timestamp_to_date(timestamp: str) -> str:
    """Convert an ISO 8601 timestamp to a date string in YYYY-MM-DD format."""
    date_object = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
    formatted_date = date_object.strftime("%Y-%m-%d")
    return formatted_date

def api_was_finding_insert_or_update(finding_dict):
    """
    Insert a was finding record into the was_finding table.

    On conflict, update the old record with the new data

    Args:
        finding_dict: Dictionary of column names and values to be inserted

    Return:
        Status on if the record was inserted successfully
    """
    try:
        was_remediated_flag = finding_dict.get("fstatus") == "FIXED"
        potential_flag     = str(finding_dict.get("potential", False)).lower() == "true"
        ignored_flag       = str(finding_dict.get("is_ignored", False)).lower() == "true"

        defaults = {
            "finding_uid":         finding_dict.get("finding_uid"),
            "finding_type":        finding_dict.get("finding_type"),
            "webapp_id":           finding_dict.get("webapp_id"),
            "webapp_url":          finding_dict.get("webapp_url"),
            "webapp_name":         finding_dict.get("webapp_name"),
            "was_org_id":          finding_dict.get("was_org_id"),
            "name":                finding_dict.get("name"),
            "owasp_category":      finding_dict.get("owasp_category"),
            "severity":            finding_dict.get("severity"),
            "times_detected":      finding_dict.get("times_detected"),
            "cvss_v3_attack_vector": finding_dict.get("cvss_v3_attack_vector"),
            "base_score":          finding_dict.get("base_score"),
            "temporal_score":      finding_dict.get("temporal_score"),
            "fstatus":             finding_dict.get("fstatus"),
            "last_detected":       finding_dict.get("last_detected"),
            "first_detected":      finding_dict.get("first_detected"),
            "potential":           potential_flag,
            "cwe_list":            finding_dict.get("cwe_list", []),
            "wasc_list":           finding_dict.get("wasc_list", []),
            "last_tested":         finding_dict.get("last_tested"),
            "fixed_date":          finding_dict.get("fixed_date"),
            "is_ignored":          ignored_flag,
            "is_remediated":       was_remediated_flag,
            "url":                 finding_dict.get("url"),
            "qid":                 finding_dict.get("qid"),
            "response":            finding_dict.get("response"),
        }

        try:
            mdl_was_finding_object, mdl_created = MDL_WasFindings.objects.update_or_create(
                finding_uid=finding_dict.get("finding_uid"),
                defaults=defaults,
            )
        except Exception:
            LOGGER.info("Failed to insert WAS finding to MDL: %s", finding_dict.get("finding_uid"))

        if mdl_created:
            LOGGER.info("Created new WAS finding record for %s", finding_dict.get("was_org_id"))
            return {
                "message": "New WAS finding created.",
                "was_finding_obj": mdl_was_finding_object,
            }
        else:
            LOGGER.info("Updated WAS finding record for %s", finding_dict.get("was_org_id"))
            return {
                "message": "WAS finding updated.",
                "was_finding_obj": mdl_was_finding_object,
            }
    except Exception as e:
        LOGGER.warning(e)
        LOGGER.info("Failed to insert or update WAS finding for %s", finding_dict.get("was_org_id"))
        return {"message": "An error occurred while processing the WAS finding."}

def getFindingsFromId(idStr, block=0):
    """Get all findings from a given ID."""
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=14)
    start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    if block == 0:
        offset = 1
    else:
        offset = block * 1000
    """Get all findings from a given ID."""
    endPoint = "https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/search/was/finding"
    headers = {
        "Content-Type": "application/json",
        "accept": "application/json",
        "Authorization": auth_string
        # 'user' : username,
        # 'password' : password
    }
    data = {
        "ServiceRequest": {
            "preferences": {
                "limitResults": 1000,
                "startFromOffset": offset,
                "verbose": "true",
            },
            "filters": {
                "Criteria": [
                    {"field": "webApp.tags.name", "operator": "EQUALS", "value": idStr},
                    # {
                    #     "field" : "type",
                    #     "operator" : "EQUALS",
                    #     "value" : "VULNERABILITY"
                    # },
                    {
                        "field": "lastTestedDate",
                        "operator": "GREATER",
                        "value": start_date_str,
                    },
                ]
            },
        }
    }
    we = qualys_call(endPoint, headers, data)
    try:
        findings = we["ServiceResponse"]["data"]
    except KeyError:
        LOGGER.info("No Findings Found for: " + idStr)
        return []
    findingsList = []
    findingCount = 0
    for x in findings:
        if x["Finding"].get("lastDetectedDate", None):
            last_detected = convert_timestamp_to_date(
                x["Finding"].get("lastDetectedDate", None)
            )
        else:
            last_detected = None
        if x["Finding"].get("firstDetectedDate", None):
            first_detected = convert_timestamp_to_date(
                x["Finding"].get("firstDetectedDate", None)
            )
        else:
            first_detected = None
        if x["Finding"].get("lastTestedDate", None):
            last_tested = convert_timestamp_to_date(
                x["Finding"].get("lastTestedDate", None)
            )
        else:
            last_tested = None
        if x["Finding"].get("fixedDate", None):
            fixed_date = convert_timestamp_to_date(x["Finding"].get("fixedDate", None))
        else:
            fixed_date = None

        findingsList.append(
            {
                "finding_uid": x["Finding"].get("uniqueId", None),
                "finding_type": x["Finding"].get("type", None),
                "webapp_id": int(x["Finding"].get("webApp", {}).get("id", 0)),
                "webapp_url": x["Finding"].get("webApp", {}).get("url", None),  # new
                "webapp_name": x["Finding"].get("webApp", {}).get("name", None),  # new
                "was_org_id": idStr,
                "name": x["Finding"]["name"],
                "owasp_category": x["Finding"]
                .get("owasp", {})
                .get("list", [{}])[0]
                .get("OWASP", {})
                .get("name", "None"),
                "severity": x["Finding"].get("severity", None),
                "times_detected": x["Finding"].get("timesDetected", None),
                "cvss_v3_attack_vector": x["Finding"]
                .get("cvssV3", {})
                .get("attackVector", None),  # new
                "base_score": x["Finding"].get("cvssV3", {}).get("base", 0),
                "temporal_score": x["Finding"].get("cvssV3", {}).get("temporal", 0),
                "fstatus": x["Finding"].get("status", None),
                "last_detected": last_detected,
                "first_detected": first_detected,
                "potential": x["Finding"].get("potential", False),
                "cwe_list": x["Finding"].get("cwe", {}).get("list", []),  # new
                "wasc_list": list(
                    map(
                        lambda d: d.get("WASC", {}),
                        x["Finding"].get("wasc", {}).get("list", []),
                    )
                ),  # new
                "last_tested": last_tested,
                "fixed_date": fixed_date,
                "is_ignored": x["Finding"].get("isIgnored", None),
                "url": x["Finding"].get("url", None),
                "qid": x["Finding"].get("qid", None),
                "response": x["Finding"]
                .get("resultList", {})
                .get("list", [{}])[0]
                .get("Result", {})
                .get("payloads", {})
                .get("list", [{}])[0]
                .get("PayloadInstance", {})
                .get("response", None),
            }
        )

    for finding in findingsList:
        api_was_finding_insert_or_update(finding)
        findingCount += 1

    if we["ServiceResponse"]["hasMoreRecords"] == "true":
        findingCount += getFindingsFromId(idStr, block + 1)
    return findingCount

@retry((InvalidApiCall, InvalidQualysCall), tries=3, delay=2, backoff=2)
def qualys_call(link, header, data):
    """Make a call to Qualys API."""
    response = requests.post(link, headers=header, data=json.dumps(data))
    if response.status_code == 401:
        logging.error("Qualys returned 401 Unauthorized. "
                      "Check your username/password and API access.")
        response.raise_for_status()

    if response.status_code != 200:
        LOGGER.error("Error Code: %s", response.status_code)
        raise InvalidQualysCall
    responseJson = json.loads(response.text)
    if responseJson["ServiceResponse"]["responseCode"] != "SUCCESS":
        LOGGER.error(responseJson["ServiceResponse"]["responseCode"])
        raise InvalidApiCall
    return responseJson

def qualys_post_call(link, header, data, validate=True):
    """Make a call to Qualys API."""
    response = requests.request("POST", link, headers=header, data=json.dumps(data))
    if not validate:
        return json.loads(response.json())
    if response.status_code != 200:
        LOGGER.error("Error Code: %s", response.status_code)
        LOGGER.error(f"Request Headers: {response.request.headers}")
        LOGGER.error(response.text)
        raise InvalidQualysCall
    responseJson = json.loads(response.text)
    if responseJson["ServiceResponse"]["responseCode"] != "SUCCESS":
        LOGGER.info(responseJson["ServiceResponse"]["responseCode"])
        raise InvalidApiCall
    return responseJson