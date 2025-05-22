"""User log search."""

# Standard Python Libraries
from datetime import datetime
import json
import re
import traceback
from typing import Any, Dict

# Third-Party Libraries
from dateutil.parser import parse  # type: ignore
from django.db.models import Q
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


def generate_date_condition(filter_obj: Dict[str, Any]) -> Q:
    """Return a Q object for date-based log filtering."""
    operator = filter_obj.get("operator")
    value = filter_obj.get("value", "")
    try:
        date_obj = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError("Invalid date format. Use ISO format.")
    if operator == "is":
        return Q(created_at__exact=date_obj)
    elif operator == "not":
        return ~Q(created_at__exact=date_obj)
    elif operator == "after":
        return Q(created_at__gt=date_obj)
    elif operator == "on_or_after":
        return Q(created_at__gte=date_obj)
    elif operator == "before":
        return Q(created_at__lt=date_obj)
    elif operator == "on_or_before":
        return Q(created_at__lte=date_obj)
    elif operator == "empty":
        return Q(created_at__isnull=True)
    elif operator == "not_empty":
        return Q(created_at__isnull=False)
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
            q_object &= Q(event_type__icontains=search_dict["event_type"]["value"])
        if "result" in search_dict and search_dict["result"]:
            q_object &= Q(result__icontains=search_dict["result"]["value"])
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


def matches_string_filter(log_value: str, operator: str, value: str) -> bool:
    """Check if a log value matches a string filter condition."""
    if operator == "contains":
        return value.lower() in log_value.lower()
    elif operator == "equals":
        return log_value == value
    elif operator == "starts with":
        return log_value.lower().startswith(value.lower())
    elif operator == "ends with":
        return log_value.lower().endswith(value.lower())
    elif operator == "is empty":
        return log_value == ""
    elif operator == "is not empty":
        return log_value != ""
    return False


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
                value = condition.value or ""
                operator = condition.operator.lower()

                if field == "event_type":
                    log_value = log["event_type"] or ""
                elif field == "result":
                    log_value = log.get("result", "") or ""
                    if not matches_string_filter(log_value, operator, value):
                        matches = False
                        break
                    continue
                elif field == "timestamp":
                    log_date = parse(log["created_at"])
                    filter_date = parse(value)
                    if operator == "equals" and log_date != filter_date:
                        matches = False
                    elif operator == "lessthan" and log_date >= filter_date:
                        matches = False
                    elif operator == "greaterthan" and log_date <= filter_date:
                        matches = False
                    elif operator == "is empty" and log_date:
                        matches = False
                    elif operator == "is not empty" and not log_date:
                        matches = False
                    continue
                elif field == "payload.user.email":
                    log_value = log["payload"].get("user", {}).get("email", "")
                elif field == "payload.user_performed_assignment.email":
                    log_value = (
                        log["payload"]
                        .get("user_performed_assignment", {})
                        .get("email", "")
                    )
                elif field == "payload.user_performed_assignment.region_id":
                    log_value = str(
                        log["payload"]
                        .get("user_performed_assignment", {})
                        .get("region_id", "")
                    )
                elif field == "payload.organization.name":
                    log_value = log["payload"].get("organization", {}).get("name", "")
                else:
                    continue

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
