import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

def safe_json_loads(raw_text: Optional[str]) -> Optional[Any]:
    """Parse JSON if present; sanitize obvious malformed backslashes first."""
    if not raw_text:
        return None
    cleaned = raw_text.replace("\\https://", "https://").replace("\\http://", "http://")
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None

def pick_english_description(descriptions: Optional[List[Dict[str, Any]]]) -> Optional[str]:
    """Choose first English description.value, fallback to first value."""
    if not descriptions:
        return None
    for description_item in descriptions:
        if str(description_item.get("lang", "")).lower().startswith("en"):
            value = description_item.get("value")
            if value:
                return str(value)
    # fallback
    value = descriptions[0].get("value") if descriptions and isinstance(descriptions[0], dict) else None
    return str(value) if value else None

def extract_references(references: Optional[List[Dict[str, Any]]]) -> List[str]:
    """Return list of reference URLs as strings."""
    urls: List[str] = []
    if not references:
        return urls
    for reference in references:
        url_value = reference.get("url")
        if url_value:
            urls.append(str(url_value))
    return urls

def extract_cvss(metrics: Optional[List[Dict[str, Any]]]) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Return (version, vector, base_score, base_severity, source_type).
    Prefer CVSS v4.0 if present, fallback to v3.1/v3.0.
    """
    if not metrics:
        return None, None, None, None, None

    cvss_v4 = None
    cvss_v3 = None

    for metric in metrics:
        cvss_v4_candidate = metric.get("cvssV4_0")
        if cvss_v4_candidate:
            cvss_v4 = cvss_v4_candidate
            break

    if not cvss_v4:
        for metric in metrics:
            cvss_v31_candidate = metric.get("cvssV3_1")
            if cvss_v31_candidate:
                cvss_v3 = cvss_v31_candidate
                break
        if not cvss_v3:
            for metric in metrics:
                cvss_v30_candidate = metric.get("cvssV3_0")
                if cvss_v30_candidate:
                    cvss_v3 = cvss_v30_candidate
                    break

    if cvss_v4:
        return (
            str(cvss_v4.get("version", "4.0")),
            str(cvss_v4.get("vectorString", "")),
            str(cvss_v4.get("baseScore", "")),
            str(cvss_v4.get("baseSeverity", "")),
            "v4",
        )
    if cvss_v3:
        return (
            str(cvss_v3.get("version", "3.x")),
            str(cvss_v3.get("vectorString", "")),
            str(cvss_v3.get("baseScore", "")),
            str(cvss_v3.get("baseSeverity", "")),
            "v3",
        )
    return None, None, None, None, None

def extract_ssvc(adp_items: Optional[List[Dict[str, Any]]]) -> Dict[str, Optional[str]]:
    """
    From containers_adp[*].metrics[*].other.content.options (array of single-key dicts),
    pick Exploitation / Automatable / Technical Impact.
    Also pull provider shortName, title, content.version, content.timestamp, providerMetadata.dateUpdated.
    If multiple ADP items exist, caller should already have filtered to the latest per CVE.
    """
    result: Dict[str, Optional[str]] = {
        "exploitation": None,
        "automatable": None,
        "technical_impact": None,
        "adp_provider": None,
        "adp_title": None,
        "ssvc_version": None,
        "ssvc_timestamp": None,
        "adp_date_updated": None,
    }
    if not adp_items:
        return result

    adp_item = adp_items[0]  # latest already chosen in SQL
    result["adp_provider"] = str(adp_item.get("providerMetadata", {}).get("shortName") or "")
    result["adp_title"] = str(adp_item.get("title") or "")

    metrics_list = adp_item.get("metrics") or []
    for metric_item in metrics_list:
        other = metric_item.get("other") or {}
        if str(other.get("type") or "").lower() != "ssvc":
            continue
        content = other.get("content") or {}
        result["ssvc_version"] = str(content.get("version") or "")
        result["ssvc_timestamp"] = str(content.get("timestamp") or "")
        options_list = content.get("options") or []
        for option_item in options_list:
            # option_item is like {"Exploitation": "none"} etc.
            for option_key, option_value in option_item.items():
                key_normalized = str(option_key).strip().lower().replace(" ", "_")
                if key_normalized == "exploitation":
                    result["exploitation"] = str(option_value)
                elif key_normalized == "automatable":
                    result["automatable"] = str(option_value)
                elif key_normalized == "technical_impact":
                    result["technical_impact"] = str(option_value)
        break  # only the first SSVC block
    result["adp_date_updated"] = str(adp_item.get("providerMetadata", {}).get("dateUpdated") or "")
    return result

def parse_iso8601(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    # no regex; rely on fromisoformat tolerant variant where possible
    try:
        # Handle 'Z' suffix
        if value.endswith("Z"):
            value = value.replace("Z", "+00:00")
        return datetime.fromisoformat(value)
    except ValueError:
        return None

def newdata_set(cve_object, field_name: str, value):
    if value is not None:
        setattr(cve_object, field_name, value)
        return True
    return False