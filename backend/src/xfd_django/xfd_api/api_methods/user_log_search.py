"""User log search."""

# Standard Python Libraries
from datetime import timedelta
import json
import re
import traceback
from typing import Any, Dict

# Third-Party Libraries
from dateutil.parser import parse  # type: ignore
from django.db.models import Q
from django.utils import timezone
from fastapi import HTTPException
from xfd_mini_dl.models import Log

from ..auth import is_global_view_admin
from ..schema_models.user_log_schema import LogSearch, LogSearchFilter


def parse_query_string(query):
    """Convert a query string into a dictionary for filtering."""
    pattern = re.compile(r'(\w+(\.\w+)*)\s*:\s*("[^"]+"|\'[^\']+\'|\S+)')
    matches = pattern.findall(query)
    result = {}
    for match in matches:
        key, _, value = match
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        orm_key = key.replace(".", "__")
        result[orm_key] = value
    return result


def safe_get(d, *keys):
    """Safely get a nested value from a dictionary, returning an empty dict if any key is missing."""
    for key in keys:
        if not isinstance(d, dict):
            return {}
        d = d.get(key, {})
    return d


def extract_log_value(field, log):
    """Extract the relevant value from a log entry based on the field."""
    if field == "event_type":
        return log.get("event_type", "")
    if field == "result":
        return log.get("result", "")
    if field in ("acted_on_user_name", "payload.user.full_name"):
        payload = log.get("payload", {})
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}
        sources = [
            payload.get("user", {}),
            safe_get(payload, "removal_result", "role_deleted", "user"),
            payload.get("user_to_approve", {}),
            safe_get(payload, "approval_results", "role_deleted", "user"),
        ]
        for source in sources:
            if source and source.get("full_name"):
                return source.get("full_name", "")
        return ""
    if field in ("acted_on_user_email", "payload.user.email"):
        payload = log.get("payload", {})
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}
        sources = [
            payload.get("user", {}),
            safe_get(payload, "removal_result", "role_deleted", "user"),
            payload.get("user_to_approve", {}),
            safe_get(payload, "approval_results", "role_deleted", "user"),
        ]
        for source in sources:
            if source and source.get("email"):
                return source.get("email", "")
        return ""
    payload = log.get("payload", {})
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            payload = {}
    if field == "payload.user_performed_assignment.full_name":
        sources = [
            payload.get("user_performed_assignment", {}),
            payload.get("user_performed_removal", {}),
            payload.get("user_performed_approval", {}),
            payload.get("user_performed_invite", {}),
        ]
        for source in sources:
            if source and source.get("full_name"):
                return source.get("full_name", "")
        return ""
    if field == "payload.user_performed_assignment.email":
        sources = [
            payload.get("user_performed_assignment", {}),
            payload.get("user_performed_removal", {}),
            payload.get("user_performed_approval", {}),
            payload.get("user_performed_invite", {}),
        ]
        for source in sources:
            if source and source.get("email"):
                return source.get("email", "")
        return ""
    if field == "payload.user_performed_assignment.region_id":
        sources = [
            payload.get("user_performed_assignment", {}),
            payload.get("user_performed_removal", {}),
            payload.get("user_performed_approval", {}),
            payload.get("user_performed_invite", {}),
        ]
        for source in sources:
            if source and source.get("region_id"):
                return str(source.get("region_id", ""))
        return ""
    if field == "payload.organization.name":
        sources = [
            payload.get("organization", {}),
            payload.get("from_organization", {}),
        ]
        for source in sources:
            if source and source.get("name"):
                return source.get("name", "")
        return ""
    if field == "payload.role":
        return payload.get("role", "")
    if field == "payload.state":
        sources = [
            payload,
            payload.get("user_performed_assignment", {}),
            payload.get("user_performed_removal", {}),
            payload.get("user_performed_approval", {}),
            payload.get("user_performed_invite", {}),
            payload.get("user", {}),
        ]
        for source in sources:
            if source and source.get("state"):
                return source.get("state", "")
        return ""
    if field == "payload.user.user_type":
        sources = [
            payload.get("user", {}),
            payload.get("user_to_approve", {}),
        ]
        for source in sources:
            if source and source.get("user_type"):
                return source.get("user_type", "")
        return ""
    if field == "payload.user_to_approve.user_type":
        sources = [
            payload.get("user_to_approve", {}),
            payload.get("user", {}),
        ]
        for source in sources:
            if source and source.get("user_type"):
                return source.get("user_type", "")
        return ""
    return ""


def matches_date_filter(log_date, operator, filter_criteria_date):
    """Return True if log_date matches the date filter operator and value."""
    if operator in ["is", "equals"]:
        return log_date is not None and log_date == filter_criteria_date
    if operator in ["is not", "not"]:
        return log_date is None or log_date != filter_criteria_date
    if operator in ["is after", "after"]:
        return log_date is not None and log_date > filter_criteria_date
    if operator in ["is on or after", "on or after"]:
        return log_date is not None and log_date >= filter_criteria_date
    if operator in ["is before", "before"]:
        return log_date is not None and log_date < filter_criteria_date
    if operator in ["is on or before", "on or before"]:
        return log_date is not None and log_date <= filter_criteria_date
    return False


def matches_string_filter(log_value: str, operator: str, value: str) -> bool:
    """Check if a log value matches a string filter condition."""
    op = operator.replace(" ", "").lower()
    if op == "contains":
        return value.lower() in (log_value or "").lower()
    elif op in ("equals", "is"):
        return (log_value or "").lower() == (value or "").lower()
    elif op in ("startswith", "starts with"):
        return (log_value or "").lower().startswith((value or "").lower())
    elif op in ("endswith", "ends with"):
        return (log_value or "").lower().endswith((value or "").lower())
    elif op in ("isempty", "is empty"):
        return log_value is None or log_value == ""
    elif op in ("isnotempty", "is not empty"):
        return log_value is not None and log_value != ""
    elif op in ("isanyof", "is any of"):
        if not value:
            return False
        if isinstance(value, str):
            value_list = [v.strip().lower() for v in value.split(",")]
        else:
            value_list = [str(v).strip().lower() for v in value]
        return (log_value or "").lower() in value_list
    elif op == "doesnotcontain":
        return value.lower() not in (log_value or "").lower()
    elif op == "doesnotequal":
        return (log_value or "").lower() != (value or "").lower()
    return False


def generate_date_condition(filter_obj: Dict[str, Any]) -> Q:
    """Return a Q object for date-based log filtering."""
    operator = (
        filter_obj.get("operator", "")
        .replace("_", " ")
        .replace("-", " ")
        .lower()
        .strip()
    )
    value = filter_obj.get("value", "")
    # Exclude string-only operators from date logic
    if operator in ["doesnotcontain", "doesnotequal"]:
        raise ValueError("Operator not supported for date fields.")
    if operator in ["empty", "is empty"]:
        return Q(created_at__isnull=True)
    elif operator in ["not empty", "is not empty"]:
        return Q(created_at__isnull=False)
    operators_require_value = [
        "is",
        "equals",
        "not",
        "is not",
        "after",
        "is after",
        "on or after",
        "is on or after",
        "before",
        "is before",
        "on or before",
        "is on or before",
    ]
    if operator in operators_require_value and (value is None or value == ""):
        return Q()
    try:
        date_obj = parse(value)
        date_obj = date_obj.replace(second=0, microsecond=0)
        if timezone.is_naive(date_obj):
            date_obj = timezone.make_aware(date_obj, timezone.get_current_timezone())
        date_obj = date_obj.replace(second=0, microsecond=0)
    except Exception:
        raise ValueError("Invalid date format. Use ISO format.")
    if operator in ["is", "equals"]:
        start_dt = date_obj
        end_dt = start_dt + timedelta(minutes=1)
        return Q(created_at__gte=start_dt, created_at__lt=end_dt)
    elif operator in ["not", "is not"]:
        start_dt = date_obj
        end_dt = start_dt + timedelta(minutes=1)
        return ~Q(created_at__gte=start_dt, created_at__lt=end_dt)
    elif operator in ["after", "is after"]:
        return Q(created_at__gt=date_obj)
    elif operator in ["on or after", "is on or after"]:
        return Q(created_at__gte=date_obj)
    elif operator in ["before", "is before"]:
        return Q(created_at__lt=date_obj)
    elif operator in ["on or before", "is on or before"]:
        return Q(created_at__lte=date_obj)
    else:
        raise ValueError("Invalid date operator.")


def search_logs(search_data, current_user):
    """Search logs using filters and return serialized results."""
    try:
        if not is_global_view_admin(current_user):
            raise HTTPException(status_code=403, detail="Unauthorized access.")
        search_dict = search_data.dict(exclude_unset=True)
        q_object = Q()
        if "event_type" in search_dict and search_dict["event_type"]:
            operator = (
                search_dict["event_type"]
                .get("operator", "contains")
                .replace(" ", "")
                .lower()
            )
            value = search_dict["event_type"]["value"]
            if operator == "contains":
                q_object &= Q(event_type__icontains=value)
            elif operator in ("equals", "is"):
                q_object &= Q(event_type__iexact=value)
            elif operator == "doesnotcontain":
                q_object &= ~Q(event_type__icontains=value)
            elif operator == "doesnotequal":
                q_object &= ~Q(event_type__iexact=value)
        if "result" in search_dict and search_dict["result"]:
            operator = (
                search_dict["result"]
                .get("operator", "contains")
                .replace(" ", "")
                .lower()
            )
            value = search_dict["result"]["value"]
            if operator == "contains":
                q_object &= Q(result__icontains=value)
            elif operator in ("equals", "is"):
                q_object &= Q(result__iexact=value)
            elif operator == "doesnotcontain":
                q_object &= ~Q(result__icontains=value)
            elif operator == "doesnotequal":
                q_object &= ~Q(result__iexact=value)
        if "timestamp" in search_dict and search_dict["timestamp"]:
            q_object &= generate_date_condition(search_dict["timestamp"])
        if "payload" in search_dict and search_dict["payload"]:
            payload_filters = parse_query_string(search_dict["payload"])
            for key, value in payload_filters.items():
                q_object &= Q(**{f"payload__{key}": value})
        logs_qs = Log.objects.filter(q_object)
        count = logs_qs.count()
        logs_serialized = []
        for log in logs_qs:
            try:
                payload_dict = json.loads(log.payload)
            except (ValueError, TypeError):
                payload_dict = log.payload
            logs_serialized.append(
                {
                    "id": str(log.id),
                    "event_type": log.event_type,
                    "result": log.result if log.result == "success" else "failed",
                    "payload": payload_dict,
                    "created_at": log.created_at.isoformat(),
                }
            )
        return logs_serialized, count
    except ValueError as ve:
        raise HTTPException(status_code=500, detail=str(ve))
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


def search_logs_filtered(search_data: LogSearchFilter, current_user):
    """Apply advanced filters to logs and return paginated results."""
    try:
        if not is_global_view_admin(current_user):
            raise HTTPException(status_code=403, detail="Unauthorized access.")

        base_search = LogSearch()
        all_logs, _ = search_logs(base_search, current_user)

        filtered_logs = []
        for log in all_logs:
            matches = True
            for field, condition in search_data.filters.items():
                value = getattr(condition, "value", "") or ""
                operator = getattr(condition, "operator", "")
                operator = re.sub(r"([a-z])([A-Z])", r"\1 \2", operator)
                operator = operator.replace("_", " ").replace("-", " ").lower().strip()

                if field == "timestamp":
                    log_value = log.get("created_at", "")
                    log_date = None
                    if log_value:
                        try:
                            log_date = parse(log_value)
                        except (ValueError, TypeError):
                            log_date = None
                    if operator == "is empty":
                        if log_date is not None:
                            matches = False
                        continue
                    if operator == "is not empty":
                        if log_date is None:
                            matches = False
                        continue
                    if operator in ["doesnotcontain", "doesnotequal"]:
                        matches = False
                        continue
                    filter_criteria_date = None
                    valid_filter_value_for_comparison = False
                    if isinstance(value, str) and value:
                        try:
                            filter_criteria_date = parse(value)
                            valid_filter_value_for_comparison = True
                        except (ValueError, TypeError):
                            matches = False
                    else:
                        matches = False
                    if (
                        log_date
                        and filter_criteria_date
                        and matches
                        and valid_filter_value_for_comparison
                    ):
                        log_date = log_date.replace(second=0, microsecond=0)
                        filter_criteria_date = filter_criteria_date.replace(
                            second=0, microsecond=0
                        )
                        if timezone.is_naive(log_date):
                            log_date = timezone.make_aware(
                                log_date, timezone.get_current_timezone()
                            )
                        if timezone.is_naive(filter_criteria_date):
                            filter_criteria_date = timezone.make_aware(
                                filter_criteria_date, timezone.get_current_timezone()
                            )
                        if not matches_date_filter(
                            log_date, operator, filter_criteria_date
                        ):
                            matches = False
                    elif not (log_date and filter_criteria_date):
                        matches = False
                    continue

                log_value = extract_log_value(field, log)
                if not matches_string_filter(log_value, operator, value):
                    matches = False
                    break

            if matches:
                filtered_logs.append(log)

        page = search_data.page
        page_size = search_data.page_size
        start = (page - 1) * page_size
        end = start + page_size
        return filtered_logs[start:end], len(filtered_logs)

    except ValueError as ve:
        raise HTTPException(status_code=500, detail=str(ve))
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))
