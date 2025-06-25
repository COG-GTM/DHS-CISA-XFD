"""Stats methods."""
# Standard Python Libraries
from datetime import date, datetime, timedelta
import json
from typing import Any, Dict, List, Optional, Tuple
import uuid

# Third-Party Libraries
from django.forms.models import model_to_dict
from fastapi import HTTPException, Request
from redis import asyncio as aioredis
from xfd_api.auth import get_stats_org_ids
from xfd_api.helpers.stats_helpers import (
    get_stats_count_from_cache,
    get_total_count,
    safe_redis_mget,
)
from xfd_api.helpers.uuid_helpers import is_valid_uuid
from xfd_api.schema_models import stat_schema
from xfd_mini_dl.models import (
    HostSummary,
    Organization,
    PortScanServiceSummary,
    PortScanSummary,
    VulnScanSummary,
)

from ..auth import get_org_memberships, is_global_view_admin


# GET: /stats
async def get_stats(filter_data, current_user, redis_client, request: Request):
    """Compile all stats."""

    async def safe_fetch(fetch_fn, *args, **kwargs):
        """Safely fetch stats, returning an empty list on failure."""
        try:
            return await fetch_fn(*args, **kwargs)
        except Exception as e:
            print("Error fetching stats with {}: {}".format(fetch_fn.__name__, e))
            return []

    filtered_org_ids = get_stats_org_ids(current_user, filter_data)

    # Ensure organization_ids is not empty
    if not filtered_org_ids:
        raise HTTPException(
            status_code=404,
            detail="No organizations found for the user with the specified filters.",
        )

    # Fetch
    try:
        return {
            "result": {
                "domains": {
                    "services": await safe_fetch(
                        get_user_services_count,
                        filter_data,
                        current_user,
                        redis_client,
                        filtered_org_ids=filtered_org_ids,
                    ),
                    "ports": await safe_fetch(
                        get_user_ports_count,
                        filter_data,
                        current_user,
                        redis_client,
                        filtered_org_ids=filtered_org_ids,
                    ),
                    "num_vulnerabilities": await safe_fetch(
                        get_num_vulns,
                        filter_data,
                        current_user,
                        redis_client,
                        filtered_org_ids=filtered_org_ids,
                    ),
                    "total": await safe_fetch(get_total_count, filtered_org_ids),
                },
                "vulnerabilities": {
                    "severity": await safe_fetch(
                        get_severity_stats,
                        filter_data,
                        current_user,
                        redis_client,
                        filtered_org_ids=filtered_org_ids,
                    ),
                    "latest_vulnerabilities": await safe_fetch(
                        stats_latest_vulns,
                        filter_data,
                        current_user,
                        redis_client,
                        request,
                        filtered_org_ids=filtered_org_ids,
                    ),
                    "most_common_vulnerabilities": await safe_fetch(
                        stats_most_common_vulns,
                        filter_data,
                        current_user,
                        redis_client,
                        request,
                        filtered_org_ids=filtered_org_ids,
                    ),
                    "by_org": await safe_fetch(
                        get_by_org_stats,
                        filter_data,
                        current_user,
                        redis_client,
                        filtered_org_ids=filtered_org_ids,
                    ),
                },
            }
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail="An unexpected error occurred: {}".format(e)
        )


async def get_user_services_count(
    filter_data, current_user, redis_client, filtered_org_ids=None
):
    """Retrieve services from Elasticache filtered by user."""
    try:
        if not filtered_org_ids:
            filtered_org_ids = get_stats_org_ids(current_user, filter_data)

            # Ensure organization_ids is not empty
            if not filtered_org_ids:
                raise HTTPException(
                    status_code=404,
                    detail="No organizations found for the user with the specified filters.",
                )

        services_data = await get_stats_count_from_cache(
            redis_client, "services_stats", filtered_org_ids
        )

        if not services_data:
            raise HTTPException(
                status_code=404,
                detail="No service data found for the user's organizations in cache.",
            )

        return services_data

    except aioredis.RedisError as redis_error:
        raise HTTPException(
            status_code=500, detail="Redis error: {}".format(redis_error)
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail="An unexpected error occurred: {}".format(e)
        )


async def get_user_ports_count(
    filter_data, current_user, redis_client, filtered_org_ids=None
):
    """Retrieve ports from Elasticache filtered by user."""
    try:
        if not filtered_org_ids:
            filtered_org_ids = get_stats_org_ids(current_user, filter_data)

            # Ensure organization_ids is not empty
            if not filtered_org_ids:
                raise HTTPException(
                    status_code=404,
                    detail="No organizations found for the user with the specified filters.",
                )

        ports_data = await get_stats_count_from_cache(
            redis_client, "ports_stats", filtered_org_ids
        )

        if not ports_data:
            raise HTTPException(
                status_code=404,
                detail="No port data found for the user's organizations in cache.",
            )

        return ports_data

    except aioredis.RedisError as redis_error:
        raise HTTPException(
            status_code=500, detail="Redis error: {}".format(redis_error)
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail="An unexpected error occurred: {}".format(e)
        )


async def get_num_vulns(filter_data, current_user, redis_client, filtered_org_ids=None):
    """Retrieve ports from Elasticache filtered by user."""
    try:
        if not filtered_org_ids:
            filtered_org_ids = get_stats_org_ids(current_user, filter_data)

            # Ensure organization_ids is not empty
            if not filtered_org_ids:
                raise HTTPException(
                    status_code=404,
                    detail="No organizations found for the user with the specified filters.",
                )

        num_vulns_data = await get_stats_count_from_cache(
            redis_client, "vulnerabilities_stats", filtered_org_ids
        )

        if not num_vulns_data:
            raise HTTPException(
                status_code=404,
                detail="No port data found for the user's organizations in cache.",
            )

        return num_vulns_data

    except aioredis.RedisError as redis_error:
        raise HTTPException(
            status_code=500, detail="Redis error: {}".format(redis_error)
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail="An unexpected error occurred: {}".format(e)
        )


async def get_severity_stats(
    filter_data, current_user, redis_client, filtered_org_ids=None
):
    """Retrieve ports from Elasticache filtered by user."""
    try:
        if not filtered_org_ids:
            filtered_org_ids = get_stats_org_ids(current_user, filter_data)

            # Ensure organization_ids is not empty
            if not filtered_org_ids:
                raise HTTPException(
                    status_code=404,
                    detail="No organizations found for the user with the specified filters.",
                )

        severity_data = await get_stats_count_from_cache(
            redis_client, "severity_stats", filtered_org_ids
        )

        if not severity_data:
            raise HTTPException(
                status_code=404,
                detail="No severity data found for the user's organizations in cache.",
            )

        return severity_data

    except aioredis.RedisError as redis_error:
        raise HTTPException(
            status_code=500, detail="Redis error: {}".format(redis_error)
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail="An unexpected error occurred: {}".format(e)
        )


async def stats_latest_vulns(
    filter_data,
    current_user,
    redis_client,
    request: Request,
    max_results=50,
    filtered_org_ids=None,
):
    """Retrieve the latest vulnerabilities from Elasticache filtered by user."""
    try:
        if not filtered_org_ids:
            filtered_org_ids = get_stats_org_ids(current_user, filter_data)

            # Ensure organization_ids is not empty
            if not filtered_org_ids:
                raise HTTPException(
                    status_code=404,
                    detail="No organizations found for the user with the specified filters.",
                )

        # Generate all Redis keys at once
        redis_keys = [
            "latest_vulnerabilities:{}".format(org_id) for org_id in filtered_org_ids
        ]

        # Use MGET to fetch all keys in a single operation
        results = await safe_redis_mget(
            redis_client, redis_keys, request.app.state.redis_semaphore
        )

        vulnerabilities = []

        # Process the results, skip None values
        for data in results:
            if data:
                vulnerabilities.extend(json.loads(data))

        # Limit the results to the maximum specified
        vulnerabilities = sorted(vulnerabilities, key=lambda x: x["created_at"])[
            :max_results
        ]

        if not vulnerabilities:
            raise HTTPException(
                status_code=404,
                detail="No vulnerabilities found for the user's organizations in cache.",
            )

        return vulnerabilities

    except aioredis.RedisError as redis_error:
        raise HTTPException(
            status_code=500, detail="Redis error: {}".format(redis_error)
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred: {}".format(e),
        )


async def stats_most_common_vulns(
    filter_data,
    current_user,
    redis_client,
    request: Request,
    max_results=10,
    filtered_org_ids=None,
):
    """Retrieve the most common vulnerabilities from Elasticache filtered by user."""
    try:
        if not filtered_org_ids:
            filtered_org_ids = get_stats_org_ids(current_user, filter_data)

            # Ensure organization_ids is not empty
            if not filtered_org_ids:
                raise HTTPException(
                    status_code=404,
                    detail="No organizations found for the user with the specified filters.",
                )

        # Generate all Redis keys at once
        redis_keys = [
            "most_common_vulnerabilities:{}".format(org_id)
            for org_id in filtered_org_ids
        ]

        # Use MGET to fetch all keys in a single operation
        results = await safe_redis_mget(
            redis_client, redis_keys, request.app.state.redis_semaphore
        )

        vulnerabilities = []

        # Process the results, skip None values
        for data in results:
            if data:
                vulnerabilities.extend(json.loads(data))

        # Limit the results to the maximum specified
        vulnerabilities = sorted(vulnerabilities, key=lambda x: x["count"])[
            :max_results
        ]

        return vulnerabilities

    except aioredis.RedisError as redis_error:
        raise HTTPException(
            status_code=500, detail="Redis error: {}".format(redis_error)
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred: {}".format(e),
        )


async def get_by_org_stats(
    filter_data, current_user, redis_client, filtered_org_ids=None
):
    """Fetch the count of open vulnerabilities grouped by organization from Redis."""
    try:
        if not filtered_org_ids:
            filtered_org_ids = get_stats_org_ids(current_user, filter_data)

            # Ensure organization_ids is not empty
            if not filtered_org_ids:
                raise HTTPException(
                    status_code=404,
                    detail="No organizations found for the user with the specified filters.",
                )

        # Initialize the results list
        by_org_data = []

        # Fetch data from Redis for each organization ID
        for org_id in filtered_org_ids:
            redis_key = "by_org_stats:{}".format(org_id)
            org_stats = await redis_client.get(redis_key)
            if org_stats:
                by_org_data.append(
                    json.loads(org_stats)
                )  # Directly append the Redis data

        if not by_org_data:
            raise HTTPException(
                status_code=404,
                detail="No organization data found in cache.",
            )

        return by_org_data

    except aioredis.RedisError as redis_error:
        raise HTTPException(
            status_code=500, detail="Redis error: {}".format(redis_error)
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred: {}".format(e),
        )


def get_vs_condensed_trending_data(filters, current_user):
    """Query VS summary and return in a condensed format."""
    organization_id = filters.organization_id

    if not is_valid_uuid(organization_id):
        raise HTTPException(status_code=404, detail="Invalid organization ID.")

    try:
        organization = Organization.objects.get(id=organization_id)
    except Organization.DoesNotExist:
        raise HTTPException(status_code=404, detail="Organization not found.")

    if (
        not is_global_view_admin(current_user)
        and not current_user.user_type == "regionalAdmin"
    ):
        org_ids = get_org_memberships(current_user)
        if uuid.UUID(organization_id) not in org_ids:
            raise HTTPException(
                status_code=404, detail="Access denied to requested organization."
            )

    if current_user.user_type == "regionalAdmin" and current_user.region_id:
        if organization.region_id != current_user.region_id:
            raise HTTPException(
                status_code=404, detail="Access denied to requested organization."
            )

    start_date = filters.start_date
    end_date = filters.end_date
    sources = filters.sources or []
    today = datetime.today().date()

    results = {}

    def replace_none_with_empty_list(results_dict):
        for key, value in results_dict.items():
            if value is None:
                results_dict[key] = []
        return results_dict

    def fetch_and_flatten(model, prefix, exclude_fields=None):
        exclude_fields = exclude_fields or []
        qs = model.objects.filter(organization=organization)

        if not start_date and not end_date:
            latest = qs.order_by("-summary_date").first()
            summaries = [latest] if latest else []
        elif start_date and not end_date:
            summaries = qs.filter(summary_date__range=(start_date, today)).order_by(
                "summary_date"
            )
        elif not start_date and end_date:
            summaries = qs.filter(summary_date=end_date).order_by("summary_date")
        else:
            summaries = qs.filter(summary_date__range=(start_date, end_date)).order_by(
                "summary_date"
            )

        if exclude_fields:
            summaries = summaries.defer(*exclude_fields)

        for obj in summaries:
            obj_dict = model_to_dict(obj, exclude=exclude_fields)
            for field, value in obj_dict.items():
                key = f"{prefix}_{field}"
                results.setdefault(key, []).append(value)

    if "host" in sources:
        fetch_and_flatten(HostSummary, "host_summary")

    if "port" in sources:
        fetch_and_flatten(PortScanSummary, "port_scan_summary")

    if "port_service" in sources:
        fetch_and_flatten(PortScanServiceSummary, "port_scan_service_summary")

    if "vs" in sources:
        exclude = ["included_tickets"] if not filters.enhanced_data else []
        fetch_and_flatten(VulnScanSummary, "vuln_scan_summary", exclude_fields=exclude)

    return replace_none_with_empty_list(results)


def get_vs_trending_data(filters, current_user):
    """Query VS scan data based on the user filters."""
    organization_id = filters.organization_id

    if not is_valid_uuid(organization_id):
        raise HTTPException(status_code=404, detail="Invalid organization ID.")

    try:
        organization = Organization.objects.get(id=organization_id)
    except Organization.DoesNotExist:
        raise HTTPException(status_code=404, detail="Organization not found.")

    if (
        not is_global_view_admin(current_user)
        and not current_user.user_type == "regionalAdmin"
    ):
        org_ids = get_org_memberships(current_user)
        if uuid.UUID(organization_id) not in org_ids:
            raise HTTPException(
                status_code=404, detail="Access denied to requested organization."
            )

    if current_user.user_type == "regionalAdmin" and current_user.region_id:
        if organization.region_id != current_user.region_id:
            raise HTTPException(
                status_code=404, detail="Access denied to requested organization."
            )

    start_date = filters.start_date
    end_date = filters.end_date
    sources = filters.sources or []
    today = datetime.today().date()

    def fetch_summaries(model, exclude_fields=None):
        exclude_fields = exclude_fields or []
        qs = model.objects.filter(organization=organization)

        if not start_date and not end_date:
            latest = qs.order_by("-summary_date").first()
            return [model_to_dict(latest, exclude=exclude_fields)] if latest else []

        if start_date and not end_date:
            qs = qs.filter(summary_date__range=(start_date, today))
        elif not start_date and end_date:
            qs = qs.filter(summary_date=end_date)
        else:
            qs = qs.filter(summary_date__range=(start_date, end_date))

        qs = qs.order_by("summary_date")  # Order ascending by date

        if exclude_fields:
            qs = qs.defer(*exclude_fields)

        return [model_to_dict(obj, exclude=exclude_fields) for obj in qs]

    host_dicts = fetch_summaries(HostSummary) if "host" in sources else None

    ports_dicts = fetch_summaries(PortScanSummary) if "port" in sources else None

    port_services_dicts = (
        fetch_summaries(PortScanServiceSummary) if "port_service" in sources else None
    )

    vuln_scan_summaries = (
        fetch_summaries(
            VulnScanSummary,
            exclude_fields=["included_tickets"] if not filters.enhanced_data else [],
        )
        if "vs" in sources
        else None
    )

    return {
        "host_summaries": host_dicts,
        "port_scan_summaries": ports_dicts,
        "port_scan_service_summaries": port_services_dicts,
        "vuln_scan_summaries": vuln_scan_summaries,
    }


# Allowed fields dictionary — module-level constant
ALLOWED_FIELDS_BY_SOURCE = {
    "vs": list(stat_schema.VulnScanSummaryV2Response.__fields__.keys()),
    "host": list(stat_schema.HostScanSummaryV2Response.__fields__.keys()),
    "port": list(stat_schema.PortScanSummaryV2Response.__fields__.keys()),
    "port_service": list(
        stat_schema.PortScanServiceSummaryV2Response.__fields__.keys()
    ),
}

FIELD_AGGREGATION_MAP = {
    "id": "max",
    "summary_date": "average_date",  # still handled specially
    "avg_summary_date": None,  # this is derived, not aggregated
    "start_date": "min",
    "end_date": "max",
    "cvss_base_score": "max",
    "rrs": "max",
    "count": "sum",
    "vulnerable_host_count": "max",
    "critical_severity_count": "max",
    # Add more field-specific logic here
}


def compute_segment_ranges(
    start: date, end: date, segment_size: int
) -> List[Tuple[date, date]]:
    """Compute date ranges for each segment (from newest to oldest)."""
    segments = []
    current_end = end

    while current_end > start:
        current_start = max(start, current_end - timedelta(days=segment_size - 1))
        segments.append((current_start, current_end))
        current_end = current_start - timedelta(days=1)

    return list(reversed(segments))


def aggregate_segment_data(
    segment_results: List[dict], selected_fields: List[str], segment_date: date
) -> Dict[str, Any]:
    """Aggregete the segment data into the segment."""
    if not segment_results:
        return {
            **{field: None for field in selected_fields},
            "summary_date": segment_date,
        }

    aggregated: Dict[str, Any] = {}

    for field in selected_fields:
        values: List[Any] = [
            item.get(field) for item in segment_results if item.get(field) is not None
        ]

        if not values:
            continue

        # Special case: calculate avg_summary_date from summary_date field
        if field == "summary_date":
            dates = [d for d in values if isinstance(d, date)]
            if dates:
                timestamps = [
                    datetime.combine(d, datetime.min.time()).timestamp() for d in dates
                ]
                avg_ts = sum(timestamps) / len(timestamps)
                aggregated["avg_summary_date"] = datetime.fromtimestamp(avg_ts).date()
            else:
                aggregated["avg_summary_date"] = None
            continue

        # Skip list/dict fields unless explicitly mapped
        if isinstance(values[0], (list, dict)) and field not in FIELD_AGGREGATION_MAP:
            continue

        agg_type = FIELD_AGGREGATION_MAP.get(field, "max")

        if agg_type == "max":
            aggregated[field] = max(values)
        elif agg_type == "sum":
            numeric_values = [v for v in values if isinstance(v, (int, float))]
            aggregated[field] = sum(numeric_values)
        elif agg_type == "avg":
            numeric_values = [v for v in values if isinstance(v, (int, float))]
            aggregated[field] = round(sum(numeric_values) / len(numeric_values), 2)
        elif agg_type == "min":
            aggregated[field] = min(values)
        else:
            aggregated[field] = values[0]  # fallback

    aggregated["summary_date"] = segment_date
    return aggregated


def get_fields_for_source(
    source: str, requested_fields: Optional[List[str]]
) -> List[str]:
    """Return validated list of fields for a given source. Defaults to all if empty."""
    allowed = ALLOWED_FIELDS_BY_SOURCE.get(source)
    if allowed is None:
        raise HTTPException(status_code=400, detail=f"Unsupported source: {source}")

    if not requested_fields:  # None or empty list
        return allowed

    invalid = set(requested_fields) - set(allowed)
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid fields for source '{source}': {list(invalid)}",
        )

    return requested_fields


def filter_fields(summary_list: List[dict], selected_fields: List[str]) -> List[dict]:
    """Filter out fields that are not requested by the user."""
    return [
        {k: v for k, v in item.items() if k in selected_fields} for item in summary_list
    ]


def get_v2_trending_data(payload, current_user):  # pylint: disable=R0915
    """Query VS scan data based on the user filters and apply optional segment summarization."""
    filters = payload.filters
    fields_by_source = payload.fields or {}
    segment_size = payload.segment_size
    enhanced_data = (
        filters.enhanced_data if filters and filters.enhanced_data else False
    )

    organization_id = filters.organization_id

    if not is_valid_uuid(organization_id):
        raise HTTPException(status_code=404, detail="Invalid organization ID.")

    try:
        organization = Organization.objects.get(id=organization_id)
    except Organization.DoesNotExist:
        raise HTTPException(status_code=404, detail="Organization not found.")

    if (
        not is_global_view_admin(current_user)
        and not current_user.user_type == "regionalAdmin"
    ):
        org_ids = get_org_memberships(current_user)
        if uuid.UUID(organization_id) not in org_ids:
            raise HTTPException(
                status_code=404, detail="Access denied to requested organization."
            )

    if current_user.user_type == "regionalAdmin" and current_user.region_id:
        if organization.region_id != current_user.region_id:
            raise HTTPException(
                status_code=404, detail="Access denied to requested organization."
            )

    start_date = filters.start_date
    end_date = filters.end_date
    sources = filters.sources or []
    today = datetime.today().date()

    # Ensure end date is set
    end_date = end_date or today
    if not start_date:
        # Fallback start date 30 days before end
        start_date = end_date - timedelta(days=30)

    duration_days = (end_date - start_date).days
    is_condensed = bool(segment_size and duration_days > 60)

    segment_ranges = (
        compute_segment_ranges(start_date, end_date, segment_size)
        if is_condensed
        else None
    )

    # Share with fetch_summaries
    def fetch_summaries(
        model,
        source: str,
        exclude_fields=None,
        segment_ranges: Optional[List[Tuple[date, date]]] = None,
        is_condensed=False,
    ) -> List[dict]:
        exclude_fields = exclude_fields or []
        selected_fields = get_fields_for_source(source, fields_by_source.get(source))

        if not is_condensed:
            qs = model.objects.filter(organization=organization)
            if start_date:
                qs = qs.filter(summary_date__gte=start_date)
            if end_date:
                qs = qs.filter(summary_date__lte=end_date)

            qs = qs.order_by("summary_date")

            if exclude_fields:
                qs = qs.defer(*exclude_fields)

            all_results = [model_to_dict(obj, exclude=exclude_fields) for obj in qs]
            return filter_fields(all_results, selected_fields)

        if not segment_ranges:
            return []

        condensed = []
        for seg_start, seg_end in segment_ranges:
            qs = model.objects.filter(
                organization=organization, summary_date__range=(seg_start, seg_end)
            ).order_by("summary_date")

            if exclude_fields:
                qs = qs.defer(*exclude_fields)

            segment_results = [model_to_dict(obj, exclude=exclude_fields) for obj in qs]
            summary = aggregate_segment_data(
                segment_results, selected_fields, segment_date=seg_end
            )
            condensed.append(summary)

        return condensed

    # Retrieve summaries by source
    host_dicts = (
        fetch_summaries(
            HostSummary,
            "host",
            segment_ranges=segment_ranges,
            is_condensed=is_condensed,
        )
        if "host" in sources
        else None
    )

    ports_dicts = (
        fetch_summaries(
            PortScanSummary,
            "port",
            segment_ranges=segment_ranges,
            is_condensed=is_condensed,
        )
        if "port" in sources
        else None
    )

    port_services_dicts = (
        fetch_summaries(
            PortScanServiceSummary,
            "port_service",
            segment_ranges=segment_ranges,
            is_condensed=is_condensed,
        )
        if "port_service" in sources
        else None
    )

    vuln_scan_summaries = (
        fetch_summaries(
            VulnScanSummary,
            source="vs",
            exclude_fields=["included_tickets"] if not enhanced_data else [],
            segment_ranges=segment_ranges,
            is_condensed=is_condensed,
        )
        if "vs" in sources
        else None
    )

    return {
        "host_summaries": host_dicts,
        "port_scan_summaries": ports_dicts,
        "port_scan_service_summaries": port_services_dicts,
        "vuln_scan_summaries": vuln_scan_summaries,
    }
