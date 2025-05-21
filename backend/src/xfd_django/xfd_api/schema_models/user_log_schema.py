"""User event log schema."""

# Standard Python Libraries
from typing import Any, Dict, List, Optional

# Third-Party Libraries
from pydantic import BaseModel, validator


class Filter(BaseModel):
    """Filter schema for string-based log fields."""

    value: str
    operator: Optional[str] = "contains"

    @validator("operator")
    def validate_operator(cls, v):
        """Validate that the operator is one of the allowed values."""
        allowed = [
            "is",
            "not",
            "after",
            "on_or_after",
            "before",
            "on_or_before",
            "empty",
            "not_empty",
        ]
        if v and v not in allowed:
            raise ValueError(f"Operator must be one of {allowed}")
        return v


class DateFilter(BaseModel):
    """Date filter schema for date-based log fields."""

    value: str
    operator: str

    @validator("operator")
    def validate_operator(cls, v):
        """Validate that the operator is one of the allowed date operators."""
        allowed = [
            "is",
            "not",
            "after",
            "on_or_after",
            "before",
            "on_or_before",
            "empty",
            "not_empty",
        ]
        if v not in allowed:
            raise ValueError(f"Operator must be one of {allowed}")
        return v


class LogSearch(BaseModel):
    """Log search schema for basic log search queries."""

    event_type: Optional[Filter] = None
    result: Optional[Filter] = None
    timestamp: Optional[DateFilter] = None
    payload: Optional[str] = None

    @validator("payload")
    def validate_payload(cls, v):
        """Validate that payload, if provided, is a string."""
        if v:
            if not isinstance(v, str):
                raise ValueError("Payload must be a string")
        return v


class LogSearchResponse(BaseModel):
    """Log search response model containing results and count."""

    result: List[Any]
    count: int


class LogFilters(BaseModel):
    """Schema for specifying optional filters on log fields such as event type, result, created_at, and payload emails."""

    event_type: Optional[Dict[str, Any]] = None
    result: Optional[Dict[str, Any]] = None
    created_at: Optional[Dict[str, Any]] = None
    payload_user_email: Optional[Dict[str, Any]] = None  # For payload.user.email
    payload_user_performed_assignment_email: Optional[
        Dict[str, Any]
    ] = None  # For payload.user_performed_assignment.email

    class Config:
        """Pydantic configuration for LogFilters."""

        from_attributes = True
        arbitrary_types_allowed = True


class FilterCondition(BaseModel):
    """Filter condition with optional value for advanced filtering."""

    operator: str
    value: Optional[Any] = None

    @validator("value", always=True)
    def validate_value(cls, v, values):
        """Validate value based on the operator."""
        operator = values.get("operator", "").lower()
        if operator in ["is empty", "is not empty"] and v is not None:
            raise ValueError(f"Value must be null for operator '{operator}'")
        if operator not in ["is empty", "is not empty"] and v is None:
            raise ValueError(f"Value is required for operator '{operator}'")
        return v


class LogSearchFilter(BaseModel):
    """Log search filter schema for advanced filtering and pagination."""

    page: int = 1
    page_size: int = 15
    filters: Dict[str, FilterCondition] = {}

    @validator("filters")
    def validate_filters(cls, v):
        """Validate that filters use allowed fields and operators."""
        allowed_fields = [
            "event_type",
            "result",
            "timestamp",
            "payload.user.email",
            "payload.user_performed_assignment.email",
        ]
        allowed_operators = [
            "contains",
            "equals",
            "starts with",
            "ends with",
            "is empty",
            "is not empty",
        ]
        allowed_date_operators = [
            "equals",
            "lessThan",
            "greaterThan",
            "is empty",
            "is not empty",
        ]
        for field, condition in v.items():
            if field not in allowed_fields:
                raise ValueError(f"Invalid filter field: {field}")
            operator = condition.operator.lower()
            if field == "timestamp" and operator not in allowed_date_operators:
                raise ValueError(f"Invalid operator for timestamp: {operator}")
            elif field != "timestamp" and operator not in allowed_operators:
                raise ValueError(f"Invalid operator for {field}: {operator}")
        return v


class GetLogResponse(BaseModel):
    """Schema for a single log entry in the API response."""

    id: str
    event_type: str
    result: str
    created_at: str
    payload: Dict[str, Any]

    class Config:
        """Pydantic configuration for GetLogResponse."""

        from_attributes = True


class LogSearchResponseFilters(BaseModel):
    """Response model for filtered log search, including results and count."""

    result: List[GetLogResponse]
    count: int
