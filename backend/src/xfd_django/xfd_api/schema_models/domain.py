"""Domain schema."""
# Third-Party Libraries
# from pydantic.types import UUID1, UUID
# Standard Python Libraries
from datetime import datetime
from typing import Any, List, Optional
from uuid import UUID

# Third-Party Libraries
from pydantic import BaseModel, field_validator


class Domain(BaseModel):
    """Domain schema."""

    id: UUID
    created_at: datetime
    updated_at: datetime
    synced_at: Optional[datetime] = None
    ip: str
    from_root_domain: Optional[str]
    subdomain_source: Optional[str]
    ip_only: bool
    reverse_name: Optional[str]
    name: Optional[str]
    screenshot: Optional[str]
    country: Optional[str]
    asn: Optional[str]
    cloud_hosted: bool
    ssl: Optional[Any]
    censys_certificates_results: Optional[dict]
    trustymail_results: Optional[dict]
    discovered_by_id: Optional[UUID]
    organization_id: Optional[UUID]
    from_cidr: Optional[bool]

    class Config:
        """Domain base schema config."""

        from_attributes = True
        validate_assignment = True


class DomainFilters(BaseModel):
    """DomainFilters schema."""

    port: Optional[int] = None
    service: Optional[str] = None
    reverse_name: Optional[str] = None
    ip: Optional[str] = None
    organization: Optional[str] = None
    organization_name: Optional[str] = None
    vulnerabilities: Optional[str] = None
    tag: Optional[str] = None
    name: Optional[str] = None

    class Config:
        """Config."""

        from_attributes = True


class DomainSearch(BaseModel):
    """DomainSearch schema."""

    page: int = 1
    sort: Optional[str] = "ASC"
    order: Optional[str] = "id"
    filters: Optional[DomainFilters] = None
    page_size: Optional[int] = 25

    class Config:
        """Config."""

        from_attributes = True


class DomainSearchResponse(BaseModel):
    """List of Domain objects."""

    result: List["GetDomainResponse"]
    count: int


class TotalDomainsResponse(BaseModel):
    """Total domain response."""

    value: int

    class Config:
        """Config."""

        from_attributes = True


class OrganizationResponse(BaseModel):
    """Organization response."""

    id: UUID
    name: str

    class Config:
        """Config."""

        orm_mode = True
        from_attributes = True


class ProductResponse(BaseModel):
    """Product response."""

    name: str
    version: Optional[str] = None


class ServiceResponse(BaseModel):
    """Service response."""

    id: UUID
    port: int
    last_seen: Optional[datetime] = None
    products: Any

    class Config:
        """Config."""

        orm_mode = True
        from_attributes = True


class VulnerabilityResponse(BaseModel):
    """Vulnerability response."""

    id: UUID
    title: str
    severity: Optional[str] = None
    state: str
    created_at: Optional[datetime] = None
    cve: Optional[str] = None

    class Config:
        """Config."""

        orm_mode = True
        from_attributes = True


class WebpageResponse(BaseModel):
    """Webpage response."""

    url: str
    status: str
    responseSize: Optional[int] = None

    class Config:
        """Config."""

        orm_mode = True
        from_attributes = True


class GetDomainResponse(BaseModel):
    """Get domain response."""

    id: UUID
    name: str
    ip: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    country: Optional[str] = None
    cloud_hosted: Optional[bool] = False
    organization: Optional[OrganizationResponse]
    vulnerabilities: Optional[List[VulnerabilityResponse]] = []
    services: Optional[List[ServiceResponse]] = []
    webpages: Optional[List[WebpageResponse]] = []

    class Config:
        """Config."""

        from_attributes = True

    @field_validator("services", mode="before")
    def ensure_services_list(cls, v):
        """Ensure services."""
        if hasattr(v, "all"):
            return list(v.all())
        return v

    @field_validator("vulnerabilities", mode="before")
    def ensure_vulns_list(cls, v):
        """Ensure vulns list."""
        if hasattr(v, "all"):
            return list(v.all())
        return v

    @field_validator("webpages", mode="before")
    def ensure_webpages_list(cls, v):
        """Ensure webpages."""
        if hasattr(v, "all"):
            return list(v.all())
        return v
