"""Push Xpanse data from LZ to DMZ."""
# Standard Python Libraries
import json
import logging
import os

# Standalone Django Setup
import sys

# Third-Party Libraries
from django.db.models import Model, Prefetch, QuerySet
from django.forms.models import model_to_dict
import requests

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)

# Third-Party Libraries
import django
from django.conf import settings

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")

settings.DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": "crossfeed",
        "USER": "crossfeed",
        "PASSWORD": "password",
        "HOST": "127.0.0.1",
        "PORT": "5432",
        "TEST": {
            "NAME": "crossfeed_test",
        },
    },
    "mini_data_lake": {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": "crossfeed_mini_datalake",
        "USER": "crossfeed",
        "PASSWORD": "password",
        "HOST": "127.0.0.1",
        "PORT": "5432",
        "TEST": {
            "NAME": "mini_data_lake_test",
        },
    },
    "mini_data_lake_secondary": {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": "crossfeed_mini_datalake_secondary",
        "USER": "crossfeed",
        "PASSWORD": "password",
        "HOST": "127.0.0.1",
        "PORT": "5432",
    },
}

django.setup()
# Standalone Django Setup

# Third-Party Libraries
from xfd_api.utils.chunk import chunk_list_by_bytes
from xfd_api.utils.csv_utils import create_checksum
from xfd_mini_dl.models import XpanseAlerts, XpanseBusinessUnits, XpanseServicesMdl

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
LOGGER = logging.getLogger(__name__)


def handler(event):
    """Run main scan function"""
    try:
        is_dmz = os.getenv("IS_DMZ", "0") == "1"
        is_local = os.getenv("IS_LOCAL", "1") == "1"
        if not is_dmz and not is_local:
            LOGGER.warning("Scan can only be run in the DMZ or locally. Exitting now.")
            return {
                "statusCode": 200,
                "body": "DMZ Shodan Vulnerabilities and Asset cannot run outside the DMZ.",
            }
        main(event)
        return {
            "statusCode": 200,
            "body": "DMZ Shodan Vulnerabilities and Asset sync completed successfully.",
        }
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}


def main():
    business_units = (
        XpanseBusinessUnits.objects.filter(alerts__isnull=False)
        .prefetch_related(
            Prefetch(
                "alerts",
                queryset=XpanseAlerts.objects.prefetch_related(
                    Prefetch(
                        "services",
                        queryset=XpanseServicesMdl.objects.prefetch_related(
                            "sub_domains", "cves"
                        ),
                    )
                ),
            )
        )
        .distinct()
    )

    business_units_list = []
    for business_unit in business_units:
        # business_unit = model_to_dict(business_unit)
        alerts = [model_to_dict(alert) for alert in business_unit.alerts.all()]
        for alert in alerts:
            services_list = []
            services = alert.get("services", [])
            for service in services:
                sub_domains_list = []
                cves_list = []
                service_dict = model_to_dict(service)
                sub_domains = service_dict.get("sub_domains", [])
                for sub_domain in sub_domains:
                    sub_domains_list.append(model_to_dict(sub_domain))
                cves = service_dict.get("cves", [])
                for cve in cves:
                    cves_list.append(model_to_dict(cve))
                service_dict["cves"] = cves_list
                service_dict["sub_domains"] = sub_domains_list
                services_list.append(service_dict)
            alert["services"] = services_list
            del alert["business_units"]
        business_unit_dict = model_to_dict(business_unit)
        business_unit_dict["alerts"] = alerts
        business_units_list.append(business_unit_dict)

    serialized_and_shaped_data = chunk_list_by_bytes(business_units_list, 2097152)
    for chunk in serialized_and_shaped_data:
        bounds = chunk["bounds"]
        data = json.dumps(chunk["chunk"], indent=4, default=str)
        payload = {"data": data}
        checksum = create_checksum(data)
        headers = {
            "x-checksum": checksum,
            "x-cursor": f"{bounds['start']}-{bounds['end']}",
            "Content-Type": "application/json",
            "Authorization": "53dba5cfcdd1d088fa92206db733b425",
        }
        response = requests.post(
            "http://localhost:3000/xpanse_sync", json=payload, headers=headers
        )
        if response.status_code == 200:
            print("Succesfully synced data to DMZ")
        else:
            print(
                f"Failed to sync data to DMZ: {response.status_code} - {response.text}"
            )


if __name__ == "__main__":
    main()
