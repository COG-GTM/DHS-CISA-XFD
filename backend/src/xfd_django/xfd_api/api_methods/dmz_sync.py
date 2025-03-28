"""DmzSync API."""
from datetime import datetime
import os
import uuid
import json

# Third-Party Libraries
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Prefetch
from django.core.paginator import Paginator
from django.forms import model_to_dict
from fastapi import HTTPException
from ..schema_models.dmz_sync import AsmSyncRequest, AsmSyncResponse, IpInsert, LooseSub, IpsSub

from ..auth import (
    can_access_user,
    is_global_view_admin,
    is_global_write_admin,
    is_org_admin,
    is_regional_admin,
    matches_user_region,
)

from ..helpers.regionStateMap import REGION_STATE_MAP
from xfd_mini_dl.models import Organization, Role, User, IpsSubs, Ip, SubDomains, DataSource
from ..tools.serializers import serialize_user

def list_data_sources(current_user):
    """Return all Data Sources."""
    try:
        if not is_global_write_admin(current_user):
                raise HTTPException(status_code=403, detail="Unauthorized access.")
        data_sources = DataSource.objects.values('name', 'description', 'last_run')
        return list(data_sources)
    
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))
    
    
def dmz_asm_sync(asm_sync_data, current_user):
    """Return ASM asset data based on the passed org."""
    try:

        if not is_global_write_admin(current_user):
            raise HTTPException(status_code=403, detail="Unauthorized access.")
        data_dict = asm_sync_data.dict() if hasattr(asm_sync_data, "dict") else asm_sync_data
        
        acronym = data_dict.get('acronym')
        page_size = data_dict.get('page_size')
        page_num = data_dict.get('page')
        last_seen_after = data_dict.get('since_date')
        if last_seen_after is None:
            raise HTTPException(status_code=400, detail="since_date is required.")
        organization = Organization.objects.get(acronym=acronym)
        
        # Prefetch IpsSubs for IP-to-Subdomain relationship, apply filter to IpsSubs directly
        ips_subs_prefetch = Prefetch(
            'ipssubs',  # IpsSubs is the through table for IP -> Subdomain relationship
            queryset=IpsSubs.objects.filter(last_seen__gt=last_seen_after).select_related('sub_domain'),  # Filter on last_seen
            to_attr='prefetched_ips_subs'
        )

        ips = Ip.objects.filter(
            organization=organization,
            last_seen_timestamp__gte=last_seen_after
        ).order_by('ip').prefetch_related(
            ips_subs_prefetch,  # Prefetch IpsSubs for linking Ips to SubDomains
            'origin_cidr'  # Prefetch the origin CIDR for the IPs
        )

        # Paginate the result
        paginator = Paginator(ips, page_size)
        page = paginator.get_page(page_num)
        ip_page_count = paginator.num_pages
        ip_results = []
        if page_num <= ip_page_count:
            for ip in page:
                ip_dict = ip.__dict__
                ip_sub_list = []
                for ip_sub in ip_dict.get('prefetched_ips_subs'):
                    ip_sub_dict = ip_sub.__dict__
                    sub_dict = ip_sub.sub_domain.__dict__
                    ip_sub_list.append(
                        IpsSub(
                            ips_subs_uid = str(ip_sub_dict.get('ips_subs_uid')),
                            # ip_id: f68d5f74-0380-11f0-8054-0242ac120009
                            # sub_domain_id: f6a500d4-0380-11f0-8054-0242ac120009
                            link_first_seen = ip_sub_dict.get('first_seen'),
                            link_last_seen = ip_sub_dict.get('last_seen'),
                            link_current = ip_sub_dict.get('current'),
                            sub_domain_uid = str(sub_dict.get('sub_domain_uid')),
                            sub_domain = sub_dict.get('sub_domain'),
                            root_domain_id = str(sub_dict.get('root_domain_id')),
                            is_root_domain = sub_dict.get('is_root_domain'),
                            data_source_id = str(sub_dict.get('data_source_id')),
                            dns_record_id = sub_dict.get('dns_record_id'),
                            status = sub_dict.get('status'),
                            first_seen = sub_dict.get('first_seen'),
                            last_seen = sub_dict.get('last_seen'),
                            created_at = sub_dict.get('created_at'),
                            updated_at = sub_dict.get('updated_at'),
                            current = sub_dict.get('current'),
                            identified = sub_dict.get('identified'),
                            ip_address = sub_dict.get('ip_address'),
                            synced_at = sub_dict.get('synced_at'),
                            from_root_domain = sub_dict.get('from_root_domain'),
                            enumerate_subs = sub_dict.get('enumerate_subs'),
                            subdomain_source = sub_dict.get('subdomain_source'),
                            ip_only = sub_dict.get('ip_only'),
                            reverse_name = sub_dict.get('reverse_name'),
                            screenshot = sub_dict.get('screenshot'),
                            country = sub_dict.get('country'),
                            asn = sub_dict.get('asn'),
                            cloud_hosted = sub_dict.get('cloud_hosted'),
                            ssl = sub_dict.get('ssl'),
                            censys_certificates_results = sub_dict.get('censys_certificates_results'),
                            trustymail_results = sub_dict.get('trustymail_results'),
                        ).dict()
                    )

                ip_object = IpInsert(
                    id = str(ip_dict.get('id')),
                    ip_hash = ip_dict.get('ip_hash'),
                    organization_id = str(ip_dict.get('organization_id')), #Not useful, 
                    created_timestamp = ip_dict.get('created_timestamp'),
                    updated_timestamp = ip_dict.get('updated_timestamp'),
                    last_seen_timestamp = ip_dict.get('last_seen_timestamp'),
                    ip = ip_dict.get('ip'),
                    ip_version = ip_dict.get('ip_version'),
                    live = ip_dict.get('live'),
                    false_positive = ip_dict.get('false_positive'),
                    retired = ip_dict.get('retired'),
                    last_reverse_lookup = ip_dict.get('last_reverse_lookup'),
                    from_cidr = ip_dict.get('from_cidr'),
                    origin_cidr_network = str(ip.origin_cidr.network) if ip.origin_cidr else None,
                    has_shodan_results = ip_dict.get('has_shodan_results'),
                    current = ip_dict.get('current'),
                    conflict_alerts = json.dumps(ip_dict.get('conflict_alerts')),
                    ip_sub_list = ip_sub_list
                ).dict()
                ip_results.append(ip_object)

        subdomains_without_current_ip = SubDomains.objects.filter(
            organization=organization,
            current=True
        ).exclude(
            ipssubs__current=True  # Exclude subdomains that have a current IP-SubDomain relationship
        ).distinct().order_by('sub_domain')

        sub_paginator = Paginator(subdomains_without_current_ip, page_size)
        sub_page = sub_paginator.get_page(page_num) 
        sub_page_count = sub_paginator.num_pages
        loose_sub_list = []
        if page_num <= sub_page_count:
            for sub in sub_page:
                sub_dict = sub.__dict__
                loose_sub_list.append(
                    LooseSub(
                        sub_domain_uid = str(sub_dict.get('sub_domain_uid')),
                        sub_domain = sub_dict.get('sub_domain'),
                        root_domain_id = str(sub_dict.get('root_domain_id')),
                        is_root_domain = sub_dict.get('is_root_domain'),
                        data_source_id = str(sub_dict.get('data_source_id')),
                        dns_record_id = str(sub_dict.get('dns_record_id')),
                        status = sub_dict.get('status'),
                        # first_seen = sub_dict.get('first_seen').isoformat() if isinstance(sub_dict.get('first_seen'), datetime) else sub_dict.get('first_seen'),
                        first_seen = sub_dict.get('first_seen'),
                        last_seen = sub_dict.get('last_seen'),
                        created_at = sub_dict.get('created_at'),
                        updated_at = sub_dict.get('updated_at'),
                        current = sub_dict.get('current'),
                        identified = sub_dict.get('identified'),
                        ip_address = sub_dict.get('ip_address'),
                        synced_at = sub_dict.get('synced_at'),
                        from_root_domain = sub_dict.get('from_root_domain'),
                        enumerate_subs = sub_dict.get('enumerate_subs'),
                        subdomain_source = sub_dict.get('subdomain_source'),
                        ip_only = sub_dict.get('ip_only'),
                        reverse_name = sub_dict.get('reverse_name'),
                        screenshot = sub_dict.get('screenshot'),
                        country = sub_dict.get('country'),
                        asn = sub_dict.get('asn'),
                        cloud_hosted = sub_dict.get('cloud_hosted'),
                        ssl = sub_dict.get('ssl'),
                        censys_certificates_results = sub_dict.get('censys_certificates_results'),
                        trustymail_results = sub_dict.get('trustymail_results'),
                    ).dict()
                )
        return {
            "total_pages":max(ip_page_count,sub_page_count),
            "current_page": page_num,
            "ip_data": ip_results,
            "loose_subs": loose_sub_list
        }
    
    except HTTPException as http_exc:
        raise http_exc
    except Organization.DoesNotExist:
        raise HTTPException(status_code=404, detail="Parent organization not found")
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))