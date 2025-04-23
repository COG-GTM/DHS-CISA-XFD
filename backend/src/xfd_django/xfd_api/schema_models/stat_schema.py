"""Stats schema."""
# Standard Python Libraries
from datetime import datetime
from typing import Any, Dict, List, Optional

# Third-Party Libraries
from pydantic import BaseModel


# Reusing the previously defined models
class ServiceStat(BaseModel):
    """Service stat."""

    id: str
    value: int
    label: str


class PortStat(BaseModel):
    """Port stat."""

    id: int
    value: int
    label: str


class VulnerabilityStat(BaseModel):
    """Vulnerability stat."""

    id: str
    value: int
    label: str


class SeverityCountStat(BaseModel):
    """Severity count stat."""

    id: str
    value: int
    label: str


class Domain(BaseModel):
    """Domain schema."""

    id: str
    created_at: datetime
    updated_at: datetime
    synced_at: Optional[datetime]
    ip: Optional[str]
    from_root_domain: Optional[str]
    subdomain_source: Optional[str]
    ip_only: Optional[bool]
    reverse_name: Optional[str]
    name: Optional[str]
    screenshot: Optional[str]
    country: Optional[str]
    asn: Optional[str]
    cloud_hosted: Optional[bool]
    from_cidr: Optional[bool]
    is_fceb: Optional[bool]
    ssl: Optional[dict]
    censys_certificates_results: Optional[dict]
    trustymail_results: Optional[dict]


class LatestVulnerability(BaseModel):
    """Latest vulnerability."""

    created_at: datetime
    title: str
    description: Optional[str]
    severity: Optional[str]


class MostCommonVulnerability(BaseModel):
    """Most common vulnerability."""

    title: str
    description: str
    severity: Optional[str]
    count: int


class ByOrgStat(BaseModel):
    """By org stat."""

    id: str
    org_id: str
    value: int
    label: str


# Main StatsResponse model
class StatsResponse(BaseModel):
    """Stats response."""

    result: Dict[str, Any] = {
        "domains": {
            "services": List[ServiceStat],
            "ports": List[PortStat],
            "num_vulnerabilities": List[VulnerabilityStat],
            "total": int,
        },
        "vulnerabilities": {
            "severity": List[SeverityCountStat],
            "latest_vulnerabilities": List[LatestVulnerability],
            "most_common_vulnerabilities": List[MostCommonVulnerability],
            "by_org": List[ByOrgStat],
        },
    }
