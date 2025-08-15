"""Sync CVE/SSVC from Redshift (AE feed) into MDL."""
# Standard Python Libraries
import logging
import os
import sys
from typing import Any, Dict, List, Tuple

# Third-Party Libraries
import django
from django.db import transaction
from xfd_api.tasks.vulnScanningSync import fetch_from_redshift_with_params
from xfd_mini_dl.models import Cve as CveModel
from xfd_mini_dl.models import CveSsvc

from ..helpers.redshift_helpers import (
    extract_cvss,
    extract_references,
    extract_ssvc,
    extract_weaknesses_from_problem_types,
    newdata_set,
    parse_iso8601,
    pick_english_description,
    safe_json_loads,
)

# Setup logging
LOGGER = logging.getLogger(__name__)

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()


def handler(event):
    """Sync CVE/SSVC from Redshift (AE feed) into MDL."""
    try:
        main()
        return {
            "statusCode": 200,
            "body": "Redshift scan update completed successfully.",
        }
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}


def parse_redshift_row(row_values: List[Any]) -> dict:
    """Extract and parse all expected Redshift row fields."""
    return {
        "cve_name": str(row_values[0]) if len(row_values) > 0 else None,
        "assigner_short_name": str(row_values[1])
        if len(row_values) > 1 and row_values[1]
        else None,
        "cna_title": str(row_values[2])
        if len(row_values) > 2 and row_values[2]
        else None,
        "descriptions_json": safe_json_loads(
            row_values[3] if len(row_values) > 3 else None
        ),
        "affected_json": safe_json_loads(
            row_values[4] if len(row_values) > 4 else None
        ),
        "metrics_json": safe_json_loads(row_values[5] if len(row_values) > 5 else None),
        "problem_types_json": safe_json_loads(
            row_values[6] if len(row_values) > 6 else None
        ),
        "references_json": safe_json_loads(
            row_values[7] if len(row_values) > 7 else None
        ),
        "source_json": safe_json_loads(row_values[8] if len(row_values) > 8 else None),
        "adp_json": safe_json_loads(row_values[9] if len(row_values) > 9 else None),
        "published_at": parse_iso8601(row_values[10])
        if len(row_values) > 10 and row_values[10]
        else None,
        "modified_at": parse_iso8601(row_values[11])
        if len(row_values) > 11 and row_values[11]
        else None,
    }


def create_or_update_cve(parsed: dict) -> CveModel:
    """Create or minimally patch a CveModel record."""
    weaknesses_list = extract_weaknesses_from_problem_types(
        parsed["problem_types_json"]
    )
    description_text = (
        pick_english_description(parsed["descriptions_json"])
        if isinstance(parsed["descriptions_json"], list)
        else None
    )
    reference_urls_list = (
        extract_references(parsed["references_json"])
        if isinstance(parsed["references_json"], list)
        else []
    )
    (
        cvss_version,
        cvss_vector,
        cvss_base_score,
        cvss_base_severity,
        cvss_source_type,
    ) = extract_cvss(
        parsed["metrics_json"] if isinstance(parsed["metrics_json"], list) else []
    )

    defaults = {
        "description": description_text,
        "title": parsed["cna_title"],
        "assigner": parsed["assigner_short_name"],
        "source_attribution": "AE/Redshift",
        "published_at": parsed["published_at"],
        "modified_at": parsed["modified_at"],
        "reference_urls": reference_urls_list or None,
        "cna_source_json": parsed["source_json"]
        if isinstance(parsed["source_json"], (dict, list))
        else None,
        "cna_affected_json": parsed["affected_json"]
        if isinstance(parsed["affected_json"], (dict, list))
        else None,
        "cna_problem_types_json": parsed["problem_types_json"] or None,
        "weaknesses": weaknesses_list or None,
    }

    # CVSS preference
    if cvss_source_type == "v4":
        defaults.update(
            {
                "cvss_v4_version": cvss_version,
                "cvss_v4_vector_string": cvss_vector,
                "cvss_v4_base_score": cvss_base_score,
                "cvss_v4_base_severity": cvss_base_severity,
            }
        )
    elif cvss_source_type == "v3":
        defaults.update(
            {
                "cvss_v3_version": cvss_version,
                "cvss_v3_vector_string": cvss_vector,
                "cvss_v3_base_score": cvss_base_score,
                "cvss_v3_base_severity": cvss_base_severity,
            }
        )

    cve_object, _ = CveModel.objects.get_or_create(
        name=parsed["cve_name"], defaults=defaults
    )
    patch_minimal_fields(
        cve_object, parsed, description_text, reference_urls_list, weaknesses_list
    )
    patch_cvss(
        cve_object,
        cvss_source_type,
        cvss_version,
        cvss_vector,
        cvss_base_score,
        cvss_base_severity,
    )
    return cve_object


def patch_minimal_fields(
    cve_object, parsed, description_text, reference_urls_list, weaknesses_list
):
    """Patch JSON and text fields if empty."""
    updated_fields = []
    field_map = {
        "title": parsed["cna_title"],
        "assigner": parsed["assigner_short_name"],
        "description": description_text,
        "reference_urls": reference_urls_list,
        "published_at": parsed["published_at"],
        "modified_at": parsed["modified_at"],
        "cna_source_json": parsed["source_json"],
        "cna_affected_json": parsed["affected_json"],
        "cna_problem_types_json": parsed["problem_types_json"],
        "weaknesses": weaknesses_list,
    }
    for field, value in field_map.items():
        if value and not getattr(cve_object, field):
            setattr(cve_object, field, value)
            updated_fields.append(field)
    if updated_fields:
        cve_object.save(update_fields=updated_fields)


def patch_cvss(
    cve_object,
    cvss_source_type,
    cvss_version,
    cvss_vector,
    cvss_base_score,
    cvss_base_severity,
):
    """Patch CVSS fields with newer data."""
    fields_to_update = []
    mapping = {
        "v4": [
            ("cvss_v4_version", cvss_version),
            ("cvss_v4_vector_string", cvss_vector),
            ("cvss_v4_base_score", cvss_base_score),
            ("cvss_v4_base_severity", cvss_base_severity),
        ],
        "v3": [
            ("cvss_v3_version", cvss_version),
            ("cvss_v3_vector_string", cvss_vector),
            ("cvss_v3_base_score", cvss_base_score),
            ("cvss_v3_base_severity", cvss_base_severity),
        ],
    }
    for field, value in mapping.get(cvss_source_type, []):
        if newdata_set(cve_object, field, value):
            fields_to_update.append(field)
    if fields_to_update:
        cve_object.save(update_fields=fields_to_update)


def upsert_ssvc(cve_object, adp_json):
    """Upsert SSVC data."""
    ssvc_payload = extract_ssvc(adp_json if isinstance(adp_json, list) else [])
    exploitation_value = ssvc_payload.get("exploitation")
    automatable_value = ssvc_payload.get("automatable")
    technical_impact_value = ssvc_payload.get("technical_impact")
    for key in ("exploitation_value", "automatable_value", "technical_impact_value"):
        val = locals()[key]
        if isinstance(val, str):
            locals()[key] = val.lower()
    CveSsvc.objects.update_or_create(
        cve=cve_object,
        defaults={
            "exploitation": exploitation_value,
            "automatable": automatable_value,
            "technical_impact": technical_impact_value,
            "adp_provider": ssvc_payload.get("adp_provider"),
            "adp_title": ssvc_payload.get("adp_title"),
            "ssvc_version": ssvc_payload.get("ssvc_version"),
            "ssvc_timestamp": parse_iso8601(ssvc_payload.get("ssvc_timestamp")),
            "adp_date_updated": parse_iso8601(ssvc_payload.get("adp_date_updated")),
        },
    )


def upsert_cve_from_redshift_row(row_values: List[Any]) -> None:
    """Orchestrates parsing, CVE upsert, and SSVC update."""
    parsed = parse_redshift_row(row_values)
    if not parsed["cve_name"]:
        return
    with transaction.atomic():
        cve_object = create_or_update_cve(parsed)
        upsert_ssvc(cve_object, parsed["adp_json"])


def build_redshift_sql() -> str:
    """Build the Redshift SQL query for CVE data with keyset pagination."""
    return """
           SELECT
               datatype,
               dataversion,
               cvemetadata_cve_id                              AS cve_id,
               cvemetadata_assigner_org_id                     AS assigner_org_id,
               cvemetadata_state                               AS state,
               cvemetadata_assigner_short_name                 AS assigner,
               cvemetadata_date_reserved                       AS date_reserved,
               cvemetadata_date_published                      AS published_at,
               cvemetadata_date_updated                        AS modified_at,
               containers_cna_title                            AS title,
               containers_cna_provider_metadata_org_id         AS cna_provider_org_id,
               containers_cna_provider_metadata_short_name     AS cna_provider_short_name,
               containers_cna_provider_metadata_date_updated   AS cna_provider_date_updated,
               containers_cna_descriptions                     AS descriptions,
               containers_cna_affected                         AS affected,
               containers_cna_metrics                          AS metrics,
               containers_cna_problem_types                    AS problem_types,
               containers_cna_references                       AS references,
               containers_cna_source                           AS source,
               containers_adp                                  AS adp,
               last_load_timestamp
           FROM cve.cve_org_data
           WHERE containers_adp IS NOT NULL
             AND cvemetadata_date_updated >= CURRENT_DATE - INTERVAL '1 year'
             AND (%s = '' OR cvemetadata_cve_id > %s)   -- keyset pagination only
           ORDER BY cvemetadata_cve_id;
           """


def sync_cve_from_redshift(max_batches: int = 100) -> int:
    """
    Fetch CVE rows from Redshift (parameterized, keyset-paginated), then upsert into local models.

    Returns total rows processed.
    """
    sql = build_redshift_sql()
    total_processed = 0
    last_key = ""
    batches = 0

    while True:
        # Params: last_key, last_key (twice) for the '%s = '' OR %s' predicate
        params: Tuple[Any, Any] = (last_key, last_key)
        rows: List[Dict[str, Any]] = fetch_from_redshift_with_params(sql, params)

        if not rows:
            break

        for row in rows:
            ordered_values = [
                row.get("cve_id"),
                row.get("assigner"),
                row.get("title"),
                row.get("descriptions"),
                row.get("affected"),
                row.get("metrics"),
                row.get("problem_types"),
                row.get("references"),
                row.get("source"),
                row.get("adp"),
                row.get("published_at"),
                row.get("modified_at"),
                row.get("state"),
                row.get("date_reserved"),
                row.get("assigner_org_id"),
                row.get("cna_provider_org_id"),
                row.get("cna_provider_short_name"),
                row.get("cna_provider_date_updated"),
            ]
            upsert_cve_from_redshift_row(ordered_values)
            last_key = str(row.get("cve_id") or last_key)
            total_processed += 1

        batches += 1
        if batches >= max_batches:
            LOGGER.warning(
                "Stopping after %s batches to avoid long Lambda runtime.", max_batches
            )
            break

    LOGGER.info("Redshift CVE sync complete: %s rows processed", total_processed)
    return total_processed


def main() -> int:
    """Task entrypoint used by handler() and CLI."""
    # You can run multiple prefixes if desired; keeping it simple:
    return sync_cve_from_redshift(max_batches=100)


if __name__ == "__main__":
    sys.exit(main())
