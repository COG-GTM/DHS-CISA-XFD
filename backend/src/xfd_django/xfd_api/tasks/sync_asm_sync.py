"""ASMsync scan."""
# Standard Python Libraries
import datetime
import json
import logging
import os
import time
import requests
import hashlib

# Third-Party Libraries
import django
from django.conf import settings
from django.db.models import Q
from django.utils import timezone
import requests
from pydantic import BaseModel
from typing import Optional, List
import uuid

from django.db.models import Prefetch
from django.core.paginator import Paginator
from xfd_api.helpers.link_ips_from_subs import connect_ips_from_subs
from xfd_api.helpers.link_subs_from_ips import connect_subs_from_ips
from xfd_api.helpers.shodan_dedupe import dedupe
from xfd_mini_dl.models import (
    Cidr,
    CidrOrgs,
    DataSource,
    Ip,
    IpsSubs,
    Organization,
    SubDomains,
)

logging.basicConfig(
    level=logging.INFO, 
    format="%(levelname)s: %(message)s"
)
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
    """Query ASM data for API endpoint."""
    try:
        is_lz = os.getenv("IS_DMZ", "0") == "0"
        is_local = os.getenv("IS_LOCAL", "true") == "true"
        LOGGER.info(is_lz)
        LOGGER.info(is_local)
        if not is_lz and not is_local:
            LOGGER.warning("Scan can only be run in the LZ or locally. Exitting now.")
            return {
                "statusCode": 200,
                "body": "ASM DMZ Sync pull cannot run outside the LZ.",
            }
        main(event)
        return {
            "statusCode": 200,
            "body": "ASM DMZ Sync completed successfully.",
        }
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}


def main(event):
    """Run ASM Sync API test owned by each stakeholder."""
    try:
        # orgs_to_sync = Organization.objects.all()
        orgs_to_sync = Organization.objects.filter(acronym__in=["USAGM", "DHS"])

        get_data_sources()
        
        for org in orgs_to_sync:
            LOGGER.info('Pulling ASM data for %s', org.acronym)
        # orgs_to_sync = Organization.objects.filter(acronym__in=event.organization.id)
            acronym = org.acronym
            page_size=10
            page_number=1
            date_x_days_ago = datetime.datetime.now() - datetime.timedelta(days=15)
            last_seen_after = date_x_days_ago.strftime('%Y-%m-%d')
            response = query_api(acronym, last_seen_after, page_size, page_number)

            if response:
                total_pages = process_response(response, org)
            else:
                LOGGER.error('Failed to query DMZ ASM Sync API.')
                continue
            page_number +=1
            while page_number <= total_pages:
                response = query_api(acronym, last_seen_after, page_size, page_number)

                if response:
                    total_pages = process_response(response, org)
                    page_number +=1
                else:
                    LOGGER.error('Failed to query DMZ ASM Sync API.')
                    break

            LOGGER.info('Completed pulling ASM data for %s', org.acronym)

        
    except Exception as e:
        LOGGER.error('Error Running test: %s', e)

def get_data_sources():
    """Pull and save data sources."""

    url = os.getenv("DMZ_URL") +"/dmz_sync/data_sources"
    headers = {
        'X-API-KEY': os.environ.get("DMZ_API_KEY"),
        'Content-Type': 'application/json'
    }
    response = requests.request("GET", url, headers=headers, timeout=29)
    if response.status_code == 200:
        data_sources = response.json()
        for data_source in data_sources:
            DataSource.objects.get_or_create(
                name=data_source.get('name'),
                defaults={
                    'description':data_source.get('description'),
                    'last_run': data_source.get('last_run')
                }
            )

def query_api(acronym,  last_seen_after, page_size=50, page_number=1):
    """Pull ASM sync data from the DMZ."""
    url = os.getenv("DMZ_URL") + "/dmz_sync/asm_sync"

    payload = json.dumps({
        "page": page_number,
        "page_size": page_size,
        "acronym": acronym,
        "since_date": last_seen_after
    })
    headers = {
        'X-API-KEY': os.environ.get("DMZ_API_KEY"),
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload, timeout=29)
    retry_count, max_retries, time_delay = 1, 10, 5
    while response.status_code != 200 and retry_count <= max_retries:
        if response.status_code:
            LOGGER.info(
                "Retrying MDL AMS_Sync endpoint (code %d), attempt %d of %d (url: %s)",
                response.status_code,
                retry_count,
                max_retries,
                url,
            )
        time.sleep(time_delay)
        response = requests.request(
            "POST", url, headers=headers, data=payload, timeout=29
        )
        retry_count += 1
        if retry_count > max_retries:

            LOGGER.warning('Failed to retrieve page %s', page_number)
            return None

    # Validate checksum by passing the response object
    is_valid = validate_response_checksum(response)

    if is_valid:
        LOGGER.info("✅ Checksum is valid!")
        return response
    else:
        LOGGER.warning("❌ Checksum validation failed!")
        return None

    # print(response.text)

    
def validate_response_checksum(response):
    """Validate the checksum from an API response."""
    SALT = os.getenv('CHECKSUM_SALT')  # Use the same salt as in the original API

    try:
        # Extract response JSON
        response_data = response.json()
        
        # Extract checksum from response headers
        received_checksum = response.headers.get("X-Salted-Checksum")
        if not received_checksum:
            LOGGER.warning("❌ No checksum found in headers!")
            return False

        # Recompute the checksum
        response_serialized = json.dumps(response_data, default=str, sort_keys=True)
        calculated_checksum = hashlib.sha256((SALT + response_serialized).encode()).hexdigest()

        return received_checksum == calculated_checksum

    except Exception as e:
        print(f"❌ Error validating checksum: {e}")
        return False
    
def process_response(response, org):
    """Save ASM sync response to the MDL."""
    data = response.json()

    for ip_sub in data.get('ip_data', []):
        cidr = Cidr.objects.get(network=ip_sub.get('origin_cidr_network'), cidrorgs__organization=org)

        ip_obj, created = Ip.objects.get_or_create(
            ip=ip_sub.get('ip'),
            organization=org,
            defaults={
                "ip_hash": ip_sub.get('ip_hash'),
                "created_timestamp": ip_sub.get('created_timestamp'),
                "updated_timestamp": ip_sub.get('updated_timestamp'),
                "last_seen_timestamp": ip_sub.get('last_seen_timestamp'),
                "ip_version": ip_sub.get('ip_version'),
                "live": ip_sub.get('live'),
                "false_positive": ip_sub.get('false_positive'),
                "retired": ip_sub.get('retired'),
                "last_reverse_lookup": ip_sub.get('last_reverse_lookup'),
                "from_cidr": ip_sub.get('from_cidr'),
                "origin_cidr": cidr,
                "has_shodan_results": ip_sub.get('has_shodan_results'),
                "current": ip_sub.get('current'),
                "conflict_alerts": ip_sub.get('conflict_alerts'),
            }
        )
        if not created:
            ip_obj.updated_timestamp = ip_sub.get('updated_timestamp')
            ip_obj.last_seen_timestamp =ip_sub.get('last_seen_timestamp')
            ip_obj.retired =ip_sub.get('retired')
            ip_obj.false_positive =ip_sub.get('false_positive')
            ip_obj.from_cidr = ip_sub.get('from_cidr')
            ip_obj.origin_cidr = cidr
            ip_obj.last_reverse_lookup = ip_sub.get('last_reverse_lookup')
            ip_obj.has_shodan_results = ip_sub.get('has_shodan_results')
            ip_obj.current = ip_sub.get('current')
            ip_obj.conflict_alerts = ip_sub.get('conflict_alerts')
            ip_obj.save()

        for sub_dict in ip_obj.get('ip_sub_list', []):

            sub_obj = save_sub(sub_dict)

            IpsSubs.objects.update_or_create(
                ip=ip_obj,
                sub_domain=sub_obj,
                defaults={
                    "first_seen": sub_obj.get('link_first_seen'),
                    "last_seen": sub_obj.get('link_last_seen'),
                    "current": sub_obj.get('link_current'),
                },
            )
    
    for loose_sub in data.get('loose_subs', []):
        sub_obj = save_sub(loose_sub)
                
    return data.get('total_pages')


def save_sub(sub_dict, org):
    """Save and update sub_domain."""
    try:
        data_source = DataSource.objects.get(name=sub_dict.get('subdomain_source'))
    except DataSource.DoesNotExist:
        data_source = unknown_data_source

    root_obj, rd_created = SubDomains.objects.get_or_create(
        sub_domain=sub_dict.get('from_root_domain'),
        organization=org,
        defaults={
            'is_root_domain': True,
            'enumerate_subs': False,
            'current': True,
            'data_source': unknown_data_source
        }
    )

    sub_obj, sd_created = SubDomains.objects.get_or_create(
        sub_domain=sub_dict.get('sub_domain'),
        organization=org,
        defaults={
            'root_domain': root_obj,
            'is_root_domain': sub_dict.get('is_root_domain'),
            'data_source': data_source,
            # 'dns_record':
            'status': sub_dict.get('status'),
            'first_seen': sub_dict.get('first_seen'),
            'last_seen': sub_dict.get('last_seen'),
            'created_at': sub_dict.get('created_at'),
            'updated_at': sub_dict.get('updated_at'),
            'current': sub_dict.get('current'),
            'identified': sub_dict.get('identified'),
            'ip_address': sub_dict.get('ip_address'),
            'synced_at': sub_dict.get('synced_at'),
            'from_root_domain': sub_dict.get('from_root_domain'),
            'enumerate_subs': sub_dict.get('enumerate_subs'),
            'subdomain_source': sub_dict.get('subdomain_source'),
            'ip_only': sub_dict.get('ip_only'),
            'reverse_name': sub_dict.get('reverse_name'),
            'screenshot': sub_dict.get('screenshot'),
            'country': sub_dict.get('country'),
            'asn': sub_dict.get('asn'),
            'cloud_hosted': sub_dict.get('cloud_hosted'),
            'ssl': sub_dict.get('ssl'),
            'censys_certificates_results': sub_dict.get('censys_certificates_results'),
            'trustymail_results': sub_dict.get('trustymail_results'),
        }
    )
    if not sd_created:
        sub_obj.data_source = data_source
        sub_obj.status = sub_dict.get('status')
        sub_obj.first_seen = sub_dict.get('first_seen')
        sub_obj.last_seen = sub_dict.get('last_seen')
        sub_obj.updated_at = sub_dict.get('updated_at')
        sub_obj.current = sub_dict.get('current')
        sub_obj.identified = sub_dict.get('identified')
        sub_obj.ip_address = sub_dict.get('ip_address')
        sub_obj.enumerate_subs = sub_dict.get('enumerate_subs')
        sub_obj.subdomain_source = sub_dict.get('subdomain_source')
        sub_obj.ip_only = sub_dict.get('ip_only')
        sub_obj.reverse_name = sub_dict.get('reverse_name')
        sub_obj.screenshot = sub_dict.get('screenshot')
        sub_obj.country = sub_dict.get('country')
        sub_obj.asn = sub_dict.get('asn')
        sub_obj.cloud_hosted = sub_dict.get('cloud_hosted')
        sub_obj.ssl = sub_dict.get('ssl')
        sub_obj.censys_certificates_results = sub_dict.get('censys_certificates_results')
        sub_obj.trustymail_results = sub_dict.get('trustymail_results')
        sub_obj.save()

    return sub_obj