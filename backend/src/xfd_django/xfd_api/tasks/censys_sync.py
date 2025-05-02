"""Censys Sync scan hitting DMZ API endpoint."""

# Standard Python Libraries
import datetime
import hashlib
import json
import logging
import os
from urllib.parse import urljoin

# Third-Party Libraries
import django
from django.utils import timezone
import requests
from xfd_api.helpers.date_time_helpers import calculate_days_back
from xfd_mini_dl.models import DataSource, Ip, Organization, SubDomains
from xfd_api.tasks.shodan_sync import validate_response_checksum

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

# Constants
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
LOGGER = logging.getLogger(__name__)
SALT = os.getenv("CHECKSUM_SALT", "default_salt")
HEADERS = {
    "X-API-KEY": os.getenv("DMZ_API_KEY"),
    "Content-Type": "application/json",
}

base_url = os.getenv("DMZ_SYNC_ENDPOINT", "").rstrip("/")
if base_url.endswith("/sync"):
    api_url = base_url.rsplit("/", 1)[0] + "/dmz_sync/censys_sync"
else:
    api_url = urljoin(base_url + "/", "dmz_sync/censys_sync")
API_URL = api_url


def handler(command_options):
    """Retrieve and save Censys subdomains from commercial via sync."""
    try:
        organization_name = command_options.get("organizationName")
        organization_id = command_options.get("organizationId")
        if not organization_name or not organization_id:
            return {"statusCode": 400, "body": "Organization name or id not provided."}

        org = Organization.objects.filter(id=organization_id).first()
        if not org:
            return {"statusCode": 404, "body": "Organization not found"}

        LOGGER.info("Running Censys Sync for org: %s", organization_name)

        data_source, _ = DataSource.objects.get_or_create(
            name="Censys",
            defaults={
                "description": "Censys certificate sync",
                "last_run": timezone.now().date(),
            },
        )

        since_date = calculate_days_back(15)
        page = 1
        per_page = 200
        done = False

        while not done:
            payload = {
                "acronym": org.acronym,
                "page": page,
                "page_size": per_page,
                "since_date": since_date,
            }

            response = requests.post(API_URL, headers=HEADERS, json=payload, timeout=60)
            response.raise_for_status()

            if not validate_response_checksum(response):
                return {"statusCode": 500, "body": "Checksum validation failed"}

            body = response.json()
            if body.get("status") != "ok":
                raise Exception("Censys sync failed: {}".format(body))

            result = body.get("payload", {})
            current_page = result.get("current_page", 1)
            total_pages = result.get("total_pages", 1)
            subdomains = result.get("data", {}).get("censys_subdomains", [])

            LOGGER.info("Syncing page %s of %s: %s subdomains", current_page, total_pages, len(subdomains))

            save_censys_subdomains_to_db(subdomains, org, data_source)

            if current_page >= total_pages:
                done = True
            else:
                page += 1

        return {"statusCode": 200, "body": "Censys sync completed successfully."}

    except Exception as e:
        LOGGER.error(e)
        return {"statusCode": 500, "body": str(e)}


def save_censys_subdomains_to_db(subdomain_array, org, data_source):
    """Save Censys subdomain data into the local database."""
    for sub in subdomain_array:
        try:
            SubDomains.objects.update_or_create(
                organization=org,
                sub_domain=sub["sub_domain"].lower(),
                defaults={
                    "last_seen": sub.get("last_seen", timezone.now()),
                    "current": True,
                    "from_root_domain": sub.get("from_root_domain"),
                    "enumerate_subs": sub.get("enumerate_subs", False),
                    "subdomain_source": "censys",
                    "data_source": data_source,
                    "identified": sub.get("identified", False),
                },
            )
        except Exception as e:
            LOGGER.error("Error saving Censys subdomain: %s", e)
