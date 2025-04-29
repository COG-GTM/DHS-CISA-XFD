"""CVE Sync scan hitting new FastAPI endpoint."""
# --- Standard Libraries ---
# Standard Python Libraries
import datetime
import hashlib
import json
import logging
import os
from urllib.parse import urljoin

# Third-Party Libraries
# --- Third-Party Libraries ---
import django
import requests

# --- Django setup ---
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

# Third-Party Libraries
# --- Your CVE model import ---
from xfd_mini_dl.models import Cve as CveModel

# --- Constants & Logging ---
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
LOGGER = logging.getLogger(__name__)

SALT = os.getenv("CHECKSUM_SALT", "default_salt")
HEADERS = {
    "X-API-KEY": os.getenv("DMZ_API_KEY"),
    "Content-Type": "application/json",
}

# e.g. “https://api.staging-cd.crossfeed.cyber.dhs.gov/sync”
base_url = os.getenv("DMZ_SYNC_ENDPOINT", "").rstrip("/")

if base_url.endswith("/sync"):
    # drop “/sync” and append “/cves”
    CVE_API_URL = base_url.rsplit("/", 1)[0] + "/dmz_sync/cves"
else:
    # fallback: join “/cves” onto whatever they provided
    CVE_API_URL = urljoin(base_url + "/", "dmz_sync/cves")


def validate_response_checksum(response):
    """Validate the checksum from the API."""
    try:
        data = response.json()
        received = response.headers.get("X-Salted-Checksum")
        if not received:
            LOGGER.warning("No checksum header")
            return False

        serialized = json.dumps(data, default=str, sort_keys=True)
        calc = hashlib.sha256((SALT + serialized).encode()).hexdigest()
        return received == calc
    except Exception as e:
        LOGGER.error("Error validating checksum: %s",e)
        return False


def save_cves_to_db(cve_list):
    """
    Upsert each CVE dict into the local DB.

    Matches your corrected Cve model with ArrayFields.
    """
    for item in cve_list:
        # parse ISO timestamps
        try:
            pub = datetime.datetime.fromisoformat(item["published_at"])
        except Exception:
            pub = None
        try:
            mod = datetime.datetime.fromisoformat(item["modified_at"])
        except Exception:
            mod = None

        defaults = {
            "name": item.get("name"),
            "published_at": pub,
            "modified_at": mod,
            "status": item.get("status"),
            "description": item.get("description"),
            # CVSS v2
            "cvss_v2_source": item.get("cvss_v2_source"),
            "cvss_v2_type": item.get("cvss_v2_type"),
            "cvss_v2_version": item.get("cvss_v2_version"),
            "cvss_v2_vector_string": item.get("cvss_v2_vector_string"),
            "cvss_v2_base_score": item.get("cvss_v2_base_score"),
            "cvss_v2_base_severity": item.get("cvss_v2_base_severity"),
            "cvss_v2_exploitability_score": item.get("cvss_v2_exploitability_score"),
            "cvss_v2_impact_score": item.get("cvss_v2_impact_score"),
            # CVSS v3
            "cvss_v3_source": item.get("cvss_v3_source"),
            "cvss_v3_type": item.get("cvss_v3_type"),
            "cvss_v3_version": item.get("cvss_v3_version"),
            "cvss_v3_vector_string": item.get("cvss_v3_vector_string"),
            "cvss_v3_base_score": item.get("cvss_v3_base_score"),
            "cvss_v3_base_severity": item.get("cvss_v3_base_severity"),
            "cvss_v3_exploitability_score": item.get("cvss_v3_exploitability_score"),
            "cvss_v3_impact_score": item.get("cvss_v3_impact_score"),
            # CVSS v4
            "cvss_v4_source": item.get("cvss_v4_source"),
            "cvss_v4_type": item.get("cvss_v4_type"),
            "cvss_v4_version": item.get("cvss_v4_version"),
            "cvss_v4_vector_string": item.get("cvss_v4_vector_string"),
            "cvss_v4_base_score": item.get("cvss_v4_base_score"),
            "cvss_v4_base_severity": item.get("cvss_v4_base_severity"),
            "cvss_v4_exploitability_score": item.get("cvss_v4_exploitability_score"),
            "cvss_v4_impact_score": item.get("cvss_v4_impact_score"),
            # ArrayFields
            "weaknesses": item.get("weaknesses"),
            "reference_urls": item.get("reference_urls"),
            "cpe_list": item.get("cpe_list"),
            # dve_score left untouched (payload doesn’t include it)
        }

        try:
            CveModel.objects.update_or_create(id=item["id"], defaults=defaults)
        except Exception as e:
            LOGGER.error("Error saving CVE %s: %s", item["id"], e)


def handler(command_options=None):
    """Fetch all CVEs and save them locally."""
    try:
        LOGGER.info("Starting CVE sync…")
        resp = requests.post(CVE_API_URL, headers=HEADERS, timeout=60)
        resp.raise_for_status()

        if not validate_response_checksum(resp):
            LOGGER.error("Checksum mismatch!")
            return {"statusCode": 500, "body": "Checksum mismatch"}

        body = resp.json()
        if body.get("status") != "ok":
            LOGGER.error("API returned bad status: %s", body)
            return {"statusCode": 500, "body": "Bad status"}

        payload = body.get("payload", [])
        LOGGER.info("Fetched %s CVEs", len(payload))
        save_cves_to_db(payload)
        LOGGER.info("CVE sync completed successfully")
        return {"statusCode": 200, "body": "CVE sync successful"}

    except Exception as e:
        LOGGER.error("Sync error: %s", e)
        return {"statusCode": 500, "body": str(e)}
