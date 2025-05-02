"""CredentialSync scan."""
# Standard Python Libraries
import datetime
import os
import time

# Third-Party Libraries
import django
from django.conf import settings
from django.utils import timezone
import logging
from xfd_api.helpers.date_time_helpers import calculate_days_back
from xfd_api.helpers.data_pull_history import update_query_timestamp, get_last_queried
from xfd_api.helpers.dmz_sync_helper import query_api
from xfd_mini_dl.models import (
    CredentialBreaches,
    CredentialExposures,
    DataSource,
    Organization,
    SubDomains
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
LOGGER = logging.getLogger(__name__)

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

# Constants
MAX_RETRIES = 3  # Max retries for failed tasks
TIMEOUT = 60  # Timeout in seconds for waiting on task completion

headers = settings.DMZ_API_HEADER

unknown_data_source, uds_created = DataSource.objects.get_or_create(
    name="Unknown",
    defaults={
        "description": "Unable to link to one of our data sources.",
        "last_run": timezone.now().date(),  # Sets the current date and time
    },
)

def handler(event):
    """Retrieve and save credential breaches and exposures from the DMZ."""
    try:
        is_lz = os.getenv("IS_DMZ", "0") == "0"
        is_local = os.getenv("IS_LOCAL", "true") == "true"

        if not is_lz and not is_local:
            LOGGER.warning("Scan can only be run in the LZ or locally. Exitting now.")
            return {
                "statusCode": 200,
                "body": "ASM DMZ Sync pull cannot run outside the LZ.",
            }
        main()
        return {
            "status_code": 200,
            "body": "DMZ credential breaches and exposures sync completed successfully.",
        }
    except Exception as e:
        return {"status_code": 500, "body": str(e)}


def main():
    """Fetch and save DMZ credential breaches and exposures."""
    try:
        # all_orgs = Organization.objects.all()
        # For testing
        all_orgs = Organization.objects.filter(acronym__in=['USAGM', 'DHS'])
        
        # since_timestamp_str = calculate_days_back(15)

        for org in all_orgs:
            since_timestamp = get_last_queried(Organization,'credential_sync')

            if since_timestamp:
                since_timestamp_str = since_timestamp.isoformat()
            else:
                since_timestamp_str = calculate_days_back(15)
            start_pulling_time = datetime.datetime.now(datetime.timezone.utc)
            print(
                "Processing organization: {acronym}, {name}".format(
                    acronym=org.acronym, name=org.name
                )
            )
            done = False
            acronym = org.acronym
            page_size = 10
            page_number = 1

            while not done:
                response = query_api("/dmz_sync/cred_sync", acronym, since_timestamp_str, page_size, page_number)
                if response:
                    total_pages = process_response(response, org)
                    # save_findings_to_db(cred_exposures_array, cred_breaches_array, org)
                else:
                    LOGGER.error("Failed to query DMZ Cred Sync API for %s.", acronym)
                    continue
                page_number += 1
                if page_number <= total_pages:
                    done = True

            update_query_timestamp(start_pulling_time)


            

        
        
    except Exception as e:
        print("Scan failed to complete: {error}".format(error=e))


def process_response(response, org):
    """Save credential exposure and breach data to the mini datalake using Django ORM."""

    data = response.json()

    cred_breaches_array = data.get("credential_breaches", [])

    if cred_breaches_array:
        breach_dict = {}
        data_source_dict = {}
        for breach in cred_breaches_array:
            try:
                if not data_source_dict.get(
                    breach.get("data_source_name", "Unknown"), None
                ):
                    (
                        data_source_dict[breach.get("data_source_name", "Unknown")],
                        created,
                    ) = DataSource.objects.get_or_create(
                        name=breach.get("data_source_name", "Unknown"),
                        defaults={
                            "description": "Credentials and Breaches identified by {source}".format(
                                source=breach.get("data_source_name", "Unknown")
                            ),
                            "last_run": timezone.now().date(),
                        },
                    )

                if not breach_dict.get(breach.get("breach_name"), None):
                    (
                        breach_dict[breach.get("breach_name")],
                        created,
                    ) = CredentialBreaches.objects.get_or_create(
                        breach_name=breach.get("breach_name"),
                        defaults={
                            "description": breach.get("description"),
                            "exposed_cred_count": breach.get("exposed_cred_count"),
                            "breach_date": datetime.datetime.fromisoformat(
                                breach.get("breach_date")
                            ).date(),
                            "added_date": breach.get("added_date"),
                            "modified_date": breach.get("modified_date"),
                            "data_classes": breach.get("data_classes"),
                            "password_included": breach.get("password_included"),
                            "is_verified": breach.get("is_verified"),
                            "is_fabricated": breach.get("is_fabricated"),
                            "is_sensitive": breach.get("is_sensitive"),
                            "is_retired": breach.get("is_retired"),
                            "is_spam_list": breach.get("is_spam_list"),
                            "data_source": data_source_dict[
                                breach.get("data_source_name", "Unknown")
                            ],
                        },
                    )
            except Exception as e:
                print("Error saving Cred Breaches: {error}".format(error=e))

    cred_exposures_array = data.get("credential_exposures", [])
    if cred_exposures_array:
        for exposure in cred_exposures_array:
            try:
                if exposure.get("root_domain") != exposure.get("sub_domain_string"):
                    root_obj, rd_created = SubDomains.objects.get_or_create(
                        sub_domain=exposure.get("root_domain"),
                        organization=org,
                        defaults={
                            "is_root_domain": True,
                            "enumerate_subs": False,
                            "identified":True,
                            "current": True,
                            "data_source": data_source_dict[
                                exposure.get("data_source_name", "Unknown")
                            ],
                        },
                    )
                else:
                    root_obj = None
                sub_obj, sd_created = SubDomains.objects.get_or_create(
                    sub_domain=exposure.get("sub_domain"),
                    organization=org,
                    defaults={
                        "root_domain": root_obj,
                        "is_root_domain": exposure.get("root_domain") == exposure.get("sub_domain_string"),
                        "data_source": data_source_dict[exposure.get("data_source_name", "Unknown")],
                        "last_seen": datetime.datetime.now(datetime.timezone.utc),
                        "current": True,
                        "identified": True,
                        "from_root_domain": exposure.get("root_domain"),
                        "enumerate_subs": False,
                        "subdomain_source": exposure.get("data_source_name", "Unknown")
                    },
                )
                if sd_created:
                    sub_obj.current=True
                    sub_obj.last_seen=datetime.datetime.now(datetime.timezone.utc)
                    sub_obj.save()
                CredentialExposures.objects.update_or_create(
                    breach_name=exposure.get("breach_name"),
                    email=exposure.get("email"),
                    defaults={
                        "root_domain": exposure.get("root_domain"),
                        "sub_domain_string": exposure.get("sub_domain"),
                        "modified_date": exposure.get("modified_date"),
                        "name": exposure.get("name"),
                        "login_id": exposure.get("login_id"),
                        "phone": exposure.get("phone"),
                        "password": exposure.get("password"),
                        "hash_type": exposure.get("hash_type"),
                        "intelx_system_id": exposure.get("intelx_system_id"),
                        "organization": org,
                        "credential_breaches": breach_dict[exposure.get("breach_name")],
                        "data_source": data_source_dict[
                            exposure.get("data_source_name", "Unknown")
                        ],
                        "sub_domain": sub_obj,
                    },
                )
            except Exception as e:
                print("Error saving Credential Exposure: {error}".format(error=e))
