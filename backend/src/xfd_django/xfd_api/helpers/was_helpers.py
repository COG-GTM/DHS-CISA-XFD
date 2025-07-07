"""
Process recent WAS scans and insert findings.

 Retrieve recent scans and, for each scan ID, fetch findings and insert them.
"""

# Standard Python Libraries
import base64
from datetime import date, datetime, timedelta
import json
import logging
import os
from statistics import median
import time

# Third-Party Libraries
from django.db.models import Count
import requests
from requests.auth import HTTPBasicAuth
from retry import retry
from xfd_mini_dl.models import WasFindings, WasScanSummary

# Setup logging
LOGGER = logging.getLogger(__name__)
DEFAULT_REQUEST_TIMEOUT_SECONDS = 10
READ_TIMEOUT = 135

username = os.environ.get("QUALYS_USERNAME")
password = os.environ.get("QUALYS_PASSWORD")

credentials = f"{username}:{password}"
auth_string = "Basic " + base64.b64encode(credentials.encode("utf-8")).decode("utf-8")

# Third-Party Libraries
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
        potential_flag = str(finding_dict.get("potential", False)).lower() == "true"
        ignored_flag = str(finding_dict.get("is_ignored", False)).lower() == "true"

        defaults = {
            "finding_uid": finding_dict.get("finding_uid"),
            "finding_type": finding_dict.get("finding_type"),
            "webapp_id": finding_dict.get("webapp_id"),
            "webapp_url": finding_dict.get("webapp_url"),
            "webapp_name": finding_dict.get("webapp_name"),
            "was_org_id": finding_dict.get("was_org_id"),
            "name": finding_dict.get("name"),
            "owasp_category": finding_dict.get("owasp_category"),
            "severity": finding_dict.get("severity"),
            "times_detected": finding_dict.get("times_detected"),
            "cvss_v3_attack_vector": finding_dict.get("cvss_v3_attack_vector"),
            "base_score": finding_dict.get("base_score"),
            "temporal_score": finding_dict.get("temporal_score"),
            "fstatus": finding_dict.get("fstatus"),
            "last_detected": finding_dict.get("last_detected"),
            "first_detected": finding_dict.get("first_detected"),
            "potential": potential_flag,
            "cwe_list": finding_dict.get("cwe_list", []),
            "wasc_list": finding_dict.get("wasc_list", []),
            "last_tested": finding_dict.get("last_tested"),
            "fixed_date": finding_dict.get("fixed_date"),
            "is_ignored": ignored_flag,
            "is_remediated": was_remediated_flag,
            "url": finding_dict.get("url"),
            "qid": finding_dict.get("qid"),
            "response": finding_dict.get("response"),
        }

        try:
            (
                mdl_was_finding_object,
                mdl_created,
            ) = MDL_WasFindings.objects.update_or_create(
                finding_uid=finding_dict.get("finding_uid"),
                defaults=defaults,
            )
        except Exception:
            LOGGER.info(
                "Failed to insert WAS finding to MDL: %s",
                finding_dict.get("finding_uid"),
            )

        if mdl_created:
            LOGGER.info(
                "Created new WAS finding record for %s", finding_dict.get("was_org_id")
            )
            return {
                "message": "New WAS finding created.",
                "was_finding_obj": mdl_was_finding_object,
            }
        else:
            LOGGER.info(
                "Updated WAS finding record for %s", finding_dict.get("was_org_id")
            )
            return {
                "message": "WAS finding updated.",
                "was_finding_obj": mdl_was_finding_object,
            }
    except Exception as e:
        LOGGER.warning(e)
        LOGGER.info(
            "Failed to insert or update WAS finding for %s",
            finding_dict.get("was_org_id"),
        )
        return {"message": "An error occurred while processing the WAS finding."}


def fetch_for(acronym):
    """
    Create a wrapper around getFindingsFromId that measures its duration.

    and captures any exception so the pool doesn’t die.
    Returns a tuple:
      (acronym, finding_count_or_None, elapsed_seconds, exception_or_None)
    """
    start = time.perf_counter()
    try:
        count = getFindingsFromId(acronym)
        return acronym, count, time.perf_counter() - start, None
    except Exception as exc:
        return acronym, None, time.perf_counter() - start, exc


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


def check_qualys_alive(username: str, password: str) -> bool:
    """Check if the Qualys API is reachable."""
    url = "https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/search/was/finding"
    try:
        qualys_alive = requests.get(
            url, auth=HTTPBasicAuth(username, password), timeout=10
        )
        return qualys_alive.status_code == 200
    except requests.RequestException as e:
        LOGGER.error("Health‐check failed: %s", e)
        return False


@retry((InvalidApiCall, InvalidQualysCall), tries=3, delay=2, backoff=2)
def qualys_call(link, header, data):
    """Make a call to Qualys API."""
    try:
        response = requests.post(
            link,
            headers=header,
            data=json.dumps(data),
            timeout=(DEFAULT_REQUEST_TIMEOUT_SECONDS, READ_TIMEOUT),
        )
    except requests.exceptions.Timeout as timeout_error:
        LOGGER.error(
            "Qualys API request timed out after %s seconds: %s",
            DEFAULT_REQUEST_TIMEOUT_SECONDS,
            timeout_error,
        )
        raise InvalidApiCall from timeout_error
    if response.status_code == 401:
        logging.error(
            "Qualys returned 401 Unauthorized. "
            "Check your username/password and API access."
        )
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


def populate_was_scan_summaries(days_back: int = 365) -> None:
    """
    For each of the last `days_back` days,.

    aggregate WasFindings into WasScanSummary.
    """
    today_date = date.today()
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    for day_offset in range(days_back):
        window_end = today_date - timedelta(days=day_offset)
        window_start = window_end - timedelta(days=20)
        _process_day_window(window_start, window_end, severities)


def _process_day_window(
    window_start: date, window_end: date, severities: list[str]
) -> None:
    """
    Aggregate WasFindings in [window_start, window_end).

     into a WasScanSummary row.
    """
    findings_qs = WasFindings.objects.filter(
        last_detected__gte=window_start,
        last_detected__lt=window_end,
    )

    LOGGER.info("Processing findings from %s to %s", window_start, window_end)
    LOGGER.info("Here are your findings: %s", findings_qs.count())

    # 1) Number of assets scanned
    scan_identifiers = [
        str(uid) for uid in findings_qs.values_list("finding_uid", flat=True).distinct()
    ]
    assets_scanned_count = findings_qs.values("webapp_id").distinct().count()
    LOGGER.info("Found %s assets scanned", assets_scanned_count)
    # 3) Unique & total vulnerabilities by severity
    unique_vuln: dict[str, int] = {}
    total_vuln: dict[str, int] = {}
    for level in severities:
        subset = findings_qs.filter(severity__iexact=level)
        unique_vuln[level] = subset.values("finding_uid").distinct().count()
        total_vuln[level] = subset.count()
    LOGGER.info("Got to Unique Vulnerabilities: %s", unique_vuln)

    # 4) Hosts with risky services
    # TODO: Uncomment when risky services are implemented

    # LOGGER.info("Got to risky services")
    # risky_services_host_count = (
    #     findings_qs.filter(is_risky_service=True).values("webapp_id").distinct().count()
    # )
    # LOGGER.info("Found %s hosts with risky services", risky_services_host_count)

    # 5) Age metrics
    LOGGER.info("Got to Age Metrics")
    SEVERITY_MAP: dict[str, str] = {
        "1": "INFO",
        "2": "LOW",
        "3": "MEDIUM",
        "4": "HIGH",
        "5": "CRITICAL",
    }
    age_lists: dict[str, list[int]] = {code: [] for code in SEVERITY_MAP.keys()}
    try:
        for finding in findings_qs:
            severity_code = finding.severity
            if finding.first_detected and severity_code in age_lists:
                days_old = (window_end - finding.first_detected).days
                age_lists[severity_code].append(days_old)
            else:
                LOGGER.warning(
                    "Skipping age calc for finding %s: unexpected severity %r",
                    finding.finding_uid,
                    finding.severity,
                )

        LOGGER.info("Computed age_lists: %s", age_lists)

    except Exception as exc:
        LOGGER.exception(
            "Error computing age metrics for window %s → %s: %s",
            window_start,
            window_end,
            exc,
        )
        # fallback to empty numeric buckets
        age_lists = {code: [] for code in SEVERITY_MAP}

    LOGGER.info("The Age Lists: %s", age_lists)
    max_age_days_critical = max(age_lists.get("CRITICAL", [0]), default=0)
    max_age_days_high = max(age_lists.get("HIGH", [0]), default=0)
    median_age_days_by_severity = {
        SEVERITY_MAP[code].lower(): (
            median(vals) if (vals := age_lists.get(code)) else 0
        )
        for code in SEVERITY_MAP
    }
    LOGGER.info("Max age (CRITICAL): %s", max_age_days_critical)
    LOGGER.info("Max age (HIGH):     %s", max_age_days_high)
    LOGGER.info("Median age by severity: %s", median_age_days_by_severity)

    # 6) KEV metrics
    kev_counts_by_severity: dict[str, int] = {code: 0 for code in SEVERITY_MAP.keys()}
    max_age_days_kevs = None

    try:
        kev_qs = findings_qs.filter(is_kev=True)

        # per‐severity loop with its own try/except
        for code, label in SEVERITY_MAP.items():
            try:
                kev_counts_by_severity[code] = kev_qs.filter(
                    severity__iexact=label
                ).count()
            except Exception as exc:
                LOGGER.warning(
                    "Skipping KEV count for severity code %r (%s): %s", code, label, exc
                )

        # compute max age of any KEV vuln
        if kev_qs.exists():
            oldest = kev_qs.order_by("first_detected").first().first_detected
            if oldest:
                max_age_days_kevs = (window_end - oldest).days

    except Exception as exc:
        LOGGER.exception(
            "Error computing KEV metrics for window %s →  %s: %s",
            window_start,
            window_end,
            exc,
        )
        # on total failure, leave everything at zero/None
        kev_counts_by_severity = {code: 0 for code in SEVERITY_MAP.keys()}
        max_age_days_kevs = None

    # finally, if you need human‐readable keys instead of numeric codes:
    kev_counts_by_severity = {
        SEVERITY_MAP[code].lower(): count
        for code, count in kev_counts_by_severity.items()
    }

    LOGGER.info("KEV counts by severity: %s", kev_counts_by_severity)
    LOGGER.info("Max age days KEVs: %s", max_age_days_kevs)

    # 7) Host-vuln buckets
    host_counts = findings_qs.values("webapp_id").annotate(
        vuln_count=Count("finding_uid")
    )
    hosts_with_1_to_5_vulns_count = sum(
        1 for h in host_counts if 1 <= h["vuln_count"] <= 5
    )
    hosts_with_6_to_9_vulns_count = sum(
        1 for h in host_counts if 6 <= h["vuln_count"] <= 9
    )
    hosts_with_10_or_more_vulns_count = sum(
        1 for h in host_counts if h["vuln_count"] >= 10
    )

    # 8) Hosts with any vuln above INFO
    hosts_with_vulnerability_above_info_count = (
        findings_qs.exclude(severity__iexact="INFO")
        .values("webapp_id")
        .distinct()
        .count()
    )

    # 9) OWASP category counts
    owasp_category_counts = dict(
        findings_qs.values_list("owasp_category").annotate(count=Count("finding_uid"))
    )

    # 10) Vulnerability type counts
    vulnerability_type_counts = dict(
        findings_qs.values_list("finding_type").annotate(count=Count("finding_uid"))
    )

    # 11) Special types
    information_gathered_count = findings_qs.filter(
        finding_type="INFORMATION_GATHERED"
    ).count()
    sensitive_content_count = findings_qs.filter(
        finding_type="SENSITIVE_CONTENT"
    ).count()
    try:
        LOGGER.info(
            "I got to the TRY: Upserting WasScanSummary for %s to %s",
            window_start,
            window_end,
        )
        unique_by_label = {
            SEVERITY_MAP[code].lower(): unique_vuln.get(code, 0)
            for code in SEVERITY_MAP
        }
        total_by_label = {
            SEVERITY_MAP[code].lower(): total_vuln.get(code, 0) for code in SEVERITY_MAP
        }
        summary_record, was_created = WasScanSummary.objects.update_or_create(
            start_date=window_start,
            end_date=window_end,
            was_org_id=(findings_qs.first().was_org_id if findings_qs.exists() else ""),
            defaults={
                "assets_scanned_count": assets_scanned_count,
                "scan_identifier": scan_identifiers,
                **{
                    f"unique_vulnerabilities_{lbl}": cnt
                    for lbl, cnt in unique_by_label.items()
                },
                **{
                    f"total_vulnerabilities_{lbl}": cnt
                    for lbl, cnt in total_by_label.items()
                },
                # TODO: Uncomment when risky services are implemented
                # "risky_services_host_count": risky_services_host_count,
                "max_age_days_critical": max_age_days_critical,
                "max_age_days_high": max_age_days_high,
                "median_age_days_by_severity": median_age_days_by_severity,
                "kev_counts_by_severity": kev_counts_by_severity,
                "max_age_days_kevs": max_age_days_kevs,
                "hosts_with_1_to_5_vulns_count": hosts_with_1_to_5_vulns_count,
                "hosts_with_6_to_9_vulns_count": hosts_with_6_to_9_vulns_count,
                "hosts_with_10_or_more_vulns_count": hosts_with_10_or_more_vulns_count,
                "hosts_with_vulnerability_above_info_count": hosts_with_vulnerability_above_info_count,
                "owasp_category_counts": owasp_category_counts,
                "vulnerability_type_counts": vulnerability_type_counts,
                "information_gathered_count": information_gathered_count,
                "sensitive_content_count": sensitive_content_count,
            },
        )
    except Exception as exc:
        LOGGER.exception("Error upserting WasScanSummary: %s", exc)
        raise

    LOGGER.info(
        "%s WasScanSummary %s→%s (created=%s, pk=%s)",
        "Created" if was_created else "Updated",
        window_start,
        window_end,
        was_created,
        summary_record.pk,
    )
