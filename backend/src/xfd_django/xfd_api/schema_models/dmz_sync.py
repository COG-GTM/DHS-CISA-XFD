"""ASM sync schemas."""
# Standard Python Libraries
from datetime import datetime
from typing import Dict, List, Optional

# Third-Party Libraries
from pydantic import BaseModel, Json


class DataSource(BaseModel):
    """DataSourceGet schema."""

    name: str
    description: str
    last_run: Optional[datetime]

    class Config:
        """Config."""

        from_attributes = True


class PagedOrgDateRequest(BaseModel):
    """PagedOrgDateRequest schema."""

    page: int = 1
    page_size: Optional[int] = 25
    acronym: str
    since_date: Optional[datetime] = None

    class Config:
        """Config."""

        from_attributes = True


class IpsSub(BaseModel):
    """IpsSub schema."""

    ips_subs_uid: str
    # ip_id: f68d5f74-0380-11f0-8054-0242ac120009
    # sub_domain_id: f6a500d4-0380-11f0-8054-0242ac120009
    link_first_seen: Optional[datetime] = None
    link_last_seen: Optional[datetime] = None
    link_current: Optional[bool] = None
    sub_domain_uid: str
    sub_domain: str
    root_domain_id: Optional[str] = None
    is_root_domain: Optional[bool] = None
    data_source_id: Optional[str] = None
    dns_record_id: Optional[str] = None
    status: Optional[bool] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    current: Optional[bool] = True
    identified: Optional[bool] = None
    ip_address: Optional[str] = None
    synced_at: Optional[datetime] = None
    from_root_domain: Optional[str] = None
    enumerate_subs: Optional[bool] = None
    subdomain_source: Optional[str] = None
    ip_only: Optional[bool] = None
    reverse_name: Optional[str] = None
    screenshot: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    cloud_hosted: Optional[bool] = None
    ssl: Optional[Dict] = {}
    censys_certificates_results: Optional[Dict] = {}
    trustymail_results: Optional[Dict] = {}

    class Config:
        """Config."""

        from_attributes = True
        json_encoders = {datetime: lambda v: v.isoformat()}


class IpInsert(BaseModel):
    """Ip schema."""

    id: str
    ip_hash: str
    organization_id: str
    created_timestamp: Optional[datetime] = None
    updated_timestamp: Optional[datetime] = None
    last_seen_timestamp: Optional[datetime] = None
    ip: str
    ip_version: Optional[str] = None
    live: Optional[bool] = None
    false_positive: Optional[bool] = None
    retired: Optional[bool] = None
    last_reverse_lookup: Optional[datetime] = None
    from_cidr: Optional[bool] = None
    origin_cidr_network: Optional[str] = None
    has_shodan_results: Optional[bool] = None
    current: Optional[bool] = None
    conflict_alerts: Optional[Json] = []
    ip_sub_list: Optional[List[IpsSub]] = []

    class Config:
        """Config."""

        from_attributes = True
        json_encoders = {datetime: lambda v: v.isoformat()}


class LooseSub(BaseModel):
    """LooseSub schema."""

    sub_domain_uid: str
    sub_domain: str
    root_domain_id: Optional[str] = None
    is_root_domain: Optional[bool] = None
    data_source_id: Optional[str] = None
    dns_record_id: Optional[str] = None
    status: Optional[bool] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    current: Optional[bool] = True
    identified: Optional[bool] = None
    ip_address: Optional[str] = None
    synced_at: Optional[datetime] = None
    from_root_domain: Optional[str] = None
    enumerate_subs: Optional[bool] = None
    subdomain_source: Optional[str] = None
    ip_only: Optional[bool] = None
    reverse_name: Optional[str] = None
    screenshot: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    cloud_hosted: Optional[bool] = None
    ssl: Optional[Dict] = {}
    censys_certificates_results: Optional[Dict] = {}
    trustymail_results: Optional[Dict] = {}

    class Config:
        """Config."""

        from_attributes = True
        json_encoders = {datetime: lambda v: v.isoformat()}


class AsmSyncResponse(BaseModel):
    """Cpe schema."""

    total_pages: int
    current_page: int
    ip_data: Optional[List[IpInsert]] = None
    loose_subs: Optional[List[LooseSub]] = None

    class Config:
        """Config."""

        from_attributes = True


class CredentialExposure(BaseModel):
    """CredentialExposure schema."""

    credential_exposures_uid: str
    email: str
    root_domain: str
    sub_domain_string: str
    breach_name: str
    modified_date: Optional[datetime] = None
    created_at: Optional[datetime] = None
    name: Optional[str] = None
    login_id: Optional[str] = None
    phone: Optional[str] = None
    password: Optional[str] = None
    hash_type: Optional[str] = None
    intelx_system_id: Optional[str] = None
    organization_acronym: Optional[str] = None
    data_source_name: Optional[str] = None

    class Config:
        """Config."""

        from_attributes = True


class CredentialBreach(BaseModel):
    """CredentialBreach schema."""

    credential_breaches_uid: str
    breach_name: str
    description: str
    exposed_cred_count: Optional[int] = None
    breach_date: Optional[datetime] = None
    added_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    data_classes: Optional[list[str]] = None
    password_included: Optional[bool] = None
    is_verified: Optional[bool] = None
    is_fabricated: Optional[bool] = None
    is_sensitive: Optional[bool] = None
    is_retired: Optional[bool] = None
    is_spam_list: Optional[bool] = None
    data_source_name: Optional[str] = None

    class Config:
        """Config."""

        from_attributes = True


class CredSyncResponse(BaseModel):
    """Cpe schema."""

    total_pages: int
    current_page: int
    credential_exposures: Optional[List[CredentialExposure]] = None
    credential_breaches: Optional[List[CredentialBreach]] = None

    class Config:
        """Config."""

        from_attributes = True
