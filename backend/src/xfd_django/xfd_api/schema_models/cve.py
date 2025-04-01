"""Cve schema."""
# Third-Party Libraries
# from pydantic.types import UUID1, UUID
# Standard Python Libraries
from datetime import datetime
from typing import Optional
from uuid import UUID

# Third-Party Libraries
from pydantic import BaseModel


class Cve(BaseModel):
    """Cve schema."""

    id: UUID
    name: Optional[str]
    published_at: datetime
    modified_at: datetime
    status: str
    description: Optional[str]
    cvss_v2_source: Optional[str]
    cvss_v2_type: Optional[str]
    cvss_v2_vector_string: Optional[str]
    cvss_V2_base_severity: Optional[str]
    cvss_V2_exploitability_score: Optional[str]
    cvss_V2_impact_score: Optional[str]
    cvss_V3_source: Optional[str]
    cvss_V3_type: Optional[str]
    cvss_V3_vector_string: Optional[str]
    cvss_V3_base_severity: Optional[str]
    cvss_V3_exploitability_score: Optional[str]
    cvss_V3_impact_score: Optional[str]
    cvss_V4_source: Optional[str]
    cvss_V4_type: Optional[str]
    cvss_V4_vector_string: Optional[str]
    cvss_V4_base_severity: Optional[str]
    cvss_V4_exploitability_score: Optional[str]
    cvss_V4_impact_score: Optional[str]
    weaknesses: Optional[str]
    references: Optional[str]

    class Config:
        """Config."""

        from_attributes = True
