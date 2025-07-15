"""Schemas to support scan task endpoints."""

# Standard Python Libraries
from datetime import datetime
from typing import Any, Dict, List, Optional

# Third-Party Libraries
from pydantic import BaseModel


class StatusCount(BaseModel):
    """HTTP status and distinct org count."""

    http_status: int
    count: int


class ScanOrgCountByStatus(BaseModel):
    """Scan metadata and success counts per status."""

    id: str
    created_at: datetime
    updated_at: datetime
    name: str
    arguments: str
    frequency: int
    last_run: Optional[datetime]
    is_granular: bool
    is_user_modifiable: bool
    is_single_scan: bool
    manual_run_pending: bool
    concurrent_tasks: int
    tags: List[str]
    organizations: List[Dict[str, Any]]
    total_orgs: int
    success_rate: List[StatusCount]


class ListScansOrgCountByStatusResponse(BaseModel):
    """Top-level response model for API."""

    scans: List[ScanOrgCountByStatus]
    metrics_window_days: int
