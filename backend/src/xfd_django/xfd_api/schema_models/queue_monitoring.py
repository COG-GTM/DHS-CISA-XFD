"""Queue monitoring schemas."""
# Third-Party Libraries
# from pydantic.types import UUID1, UUID
# Standard Python Libraries
from datetime import datetime
from typing import Any, List, Optional
from uuid import UUID

# Third-Party Libraries
from pydantic import BaseModel


class QueueSearch(BaseModel):
    """Queue search schema."""

    page: int = 1
    sort: Optional[str] = "ASC"
    order: Optional[str] = "id"
    filters: Optional[dict] = None
    pageSize: Optional[int] = 25


class QueueMetadata(BaseModel):
    """Queue metadata."""
    name: str
    messagesAvailable: int
    messagesInFlight: int
    messagesDelayed: int


class QueueListResponse(BaseModel):
    """Queue list response."""
    result: List[QueueMetadata]
    count: int
