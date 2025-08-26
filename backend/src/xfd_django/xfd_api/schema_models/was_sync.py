"""Schema models for WAS scan summaries."""
"""Cve schema."""
# Standard Python Libraries
from datetime import date
from typing import List, Optional, Dict
from uuid import UUID

# Third-Party Libraries
from pydantic import BaseModel, Field
class WasScanSummarySchema(BaseModel):
    summary_uid: UUID
    start_date: date
    end_date: date
    scan_identifier: List[str]
    was_org_id: str

    assets_scanned_count: int
    unique_vulnerabilities_critical: int
    unique_vulnerabilities_high: int
    unique_vulnerabilities_medium: int
    unique_vulnerabilities_low: int
    unique_vulnerabilities_info: int

    total_vulnerabilities_critical: int
    total_vulnerabilities_high: int
    total_vulnerabilities_medium: int
    total_vulnerabilities_low: int
    total_vulnerabilities_info: int

    max_age_days_critical: Optional[int]
    max_age_days_high: Optional[int]
    median_age_days_by_severity: Dict[str, float]

    kev_counts_by_severity: Dict[str, int]
    max_age_days_kevs: Optional[int]

    hosts_with_1_to_5_vulns_count: int
    hosts_with_6_to_9_vulns_count: int
    hosts_with_10_or_more_vulns_count: int
    hosts_with_vulnerability_above_info_count: int

    owasp_category_counts: Dict[str, int]
    vulnerability_type_counts: Dict[str, int]

    information_gathered_count: int
    sensitive_content_count: int

    class Config:
        orm_mode = True
        validate_assignment = True


class GetWasScanSummariesResponse(BaseModel):
    status: str = Field("ok")
    payload: List[WasScanSummarySchema]
