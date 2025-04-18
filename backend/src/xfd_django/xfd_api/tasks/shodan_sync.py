"""Updated Shodan Sync scan hitting new FastAPI endpoint."""
# Standard Python Libraries
import os
from urllib.parse import urljoin

# Third-Party Libraries
import django
from django.utils import timezone
import requests
from xfd_api.helpers.date_time_helpers import calculate_days_back
from xfd_mini_dl.models import DataSource, Ip, Organization, ShodanAssets, ShodanVulns

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

# Constants
HEADERS = {
    "Authorization": os.getenv("DMZ_API_KEY"),
}
# Assume DMZ_SYNC_ENDPOINT is something like 'https://api.staging-cd.crossfeed.cyber.dhs.gov/sync'
base_url = os.getenv("DMZ_SYNC_ENDPOINT", "").rstrip("/")

# Replace the final segment `/sync` with `/dmz_sync/shodan_sync`
if base_url.endswith("/sync"):
    api_url = base_url.rsplit("/", 1)[0] + "/dmz_sync/shodan_sync"
else:
    api_url = urljoin(base_url + "/", "dmz_sync/shodan_sync")
API_URL = os.getenv("DMZ_SYNC_ENDPOINT")


def handler(command_options):
    """Retrieve and save Shodan assets/vulns from commercial via sync."""
    try:
        organization_name = command_options.get("organizationName")
        organization_id = command_options.get("organizationId")
        if not organization_name or not organization_id:
            return {"statusCode": 400, "body": "Organization name or id not provided."}

        orgs_to_sync = Organization.objects.filter(id=organization_id)
        if not orgs_to_sync.exists():
            return {"statusCode": 500, "body": "Organization not found."}
        organization = orgs_to_sync.first()

        print("Running Shodan Sync on organization: {}".format(organization_name))

        shodan_datasource, _ = DataSource.objects.get_or_create(
            name="Shodan",
            defaults={
                "description": "Shodan is the world's first search engine for Internet-connected devices.",
                "last_run": timezone.now().date(),
            },
        )

        since_date = calculate_days_back(15)

        page = 1
        per_page = 200
        done = False

        while not done:
            payload = {
                "acronym": organization.acronym,
                "page": page,
                "page_size": per_page,
                "since_date": since_date,
            }

            response = requests.post(API_URL, headers=HEADERS, json=payload, timeout=60)
            response.raise_for_status()
            body = response.json()

            if body.get("status") != "ok":
                raise Exception("Shodan sync returned non-ok status: {}".format(body))

            result = body.get("payload", {})
            total_pages = result.get("total_pages", 1)
            current_page = result.get("current_page", 1)
            assets = result.get("data", {}).get("shodan_assets", [])
            vulns = result.get("data", {}).get("shodan_vulns", [])

            print(
                "Syncing page {} of {}: {} assets, {} vulns".format(
                    current_page, total_pages, len(assets), len(vulns)
                )
            )
            save_findings_to_db(assets, vulns, organization, shodan_datasource)

            if current_page >= total_pages:
                done = True
            else:
                page += 1

        return {"statusCode": 200, "body": "Shodan sync completed successfully."}

    except Exception as e:
        return {"statusCode": 500, "body": str(e)}


def save_findings_to_db(shodan_asset_array, shodan_vuln_array, org, data_source):
    """Save Shodan assets and vulns data to the mini datalake using Django ORM."""
    for asset in shodan_asset_array:
        ip_instance = Ip.objects.filter(
            ip=asset.get("ip_string"), organization=org
        ).first()
        try:
            ShodanAssets.objects.update_or_create(
                timestamp=asset.get("timestamp"),
                ip=ip_instance,
                port=asset.get("port"),
                protocol=asset.get("protocol"),
                organization=org,
                defaults={
                    "ip_string": asset.get("ip_string"),
                    "organization_name": asset.get("organization_name"),
                    "product": asset.get("product"),
                    "server": asset.get("server"),
                    "tags": asset.get("tags"),
                    "domains": asset.get("domains"),
                    "hostnames": asset.get("hostnames"),
                    "isp": asset.get("isp"),
                    "asn": asset.get("asn"),
                    "country_code": asset.get("country_code"),
                    "location": asset.get("location"),
                    "data_source": data_source,
                },
            )
        except Exception as e:
            print("Error saving Shodan Asset: {}".format(e))

    for vuln in shodan_vuln_array:
        ip_instance = Ip.objects.filter(
            ip=vuln.get("ip_string"), organization=org
        ).first()
        try:
            ShodanVulns.objects.update_or_create(
                timestamp=vuln.get("timestamp"),
                ip=ip_instance,
                port=vuln.get("port"),
                protocol=vuln.get("protocol"),
                organization=org,
                defaults={
                    "ip_string": vuln.get("ip_string"),
                    "organization_name": vuln.get("organization_name"),
                    "cve": vuln.get("cve"),
                    "severity": vuln.get("severity"),
                    "cvss": vuln.get("cvss"),
                    "summary": vuln.get("summary"),
                    "product": vuln.get("product"),
                    "attack_vector": vuln.get("attack_vector"),
                    "av_description": vuln.get("av_description"),
                    "attack_complexity": vuln.get("attack_complexity"),
                    "ac_description": vuln.get("ac_description"),
                    "confidentiality_impact": vuln.get("confidentiality_impact"),
                    "ci_description": vuln.get("ci_description"),
                    "integrity_impact": vuln.get("integrity_impact"),
                    "ii_description": vuln.get("ii_description"),
                    "availability_impact": vuln.get("availability_impact"),
                    "ai_description": vuln.get("ai_description"),
                    "tags": vuln.get("tags"),
                    "domains": vuln.get("domains"),
                    "hostnames": vuln.get("hostnames"),
                    "isp": vuln.get("isp"),
                    "asn": vuln.get("asn"),
                    "type": vuln.get("type"),
                    "name": vuln.get("name"),
                    "potential_vulns": vuln.get("potential_vulns"),
                    "mitigation": vuln.get("mitigation"),
                    "server": vuln.get("server"),
                    "is_verified": vuln.get("is_verified"),
                    "banner": vuln.get("banner"),
                    "version": vuln.get("version"),
                    "cpe": vuln.get("cpe"),
                    "data_source": data_source,
                },
            )
        except Exception as e:
            print("Error saving Shodan Vuln: {}".format(e))
