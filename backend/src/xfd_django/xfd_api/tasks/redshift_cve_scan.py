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


def upsert_cve_from_redshift_row(row_values: List[Any]) -> None:
    """Map one Redshift row to Cve and CveSsvc and upsert idempotently."""
    cve_name = str(row_values[0]) if len(row_values) > 0 else None
    assigner_short_name = (
        str(row_values[1]) if len(row_values) > 1 and row_values[1] else None
    )
    cna_title = str(row_values[2]) if len(row_values) > 2 and row_values[2] else None

    descriptions_json = safe_json_loads(row_values[3] if len(row_values) > 3 else None)
    # These two are currently unused by the model, but keep parsed for future use:
    affected_json = safe_json_loads(row_values[4] if len(row_values) > 4 else None)
    problem_types_json = safe_json_loads(row_values[6] if len(row_values) > 6 else None)

    metrics_json = safe_json_loads(row_values[5] if len(row_values) > 5 else None)
    references_json = safe_json_loads(row_values[7] if len(row_values) > 7 else None)
    source_json = safe_json_loads(row_values[8] if len(row_values) > 8 else None)
    adp_json = safe_json_loads(row_values[9] if len(row_values) > 9 else None)
    weaknesses_list = extract_weaknesses_from_problem_types(problem_types_json)

    if not cve_name:
        return

    # Description: pick English (or best-effort)
    description_text = None
    if isinstance(descriptions_json, list):
        description_text = pick_english_description(descriptions_json)

    # Reference URLs (list[str] or [])
    reference_urls_list = (
        extract_references(references_json) if isinstance(references_json, list) else []
    )

    # CVSS (prefers v4, else v3)
    (
        cvss_version,
        cvss_vector,
        cvss_base_score,
        cvss_base_severity,
        cvss_source_type,
    ) = extract_cvss(metrics_json if isinstance(metrics_json, list) else [])

    # SSVC (ADP)
    ssvc_payload = extract_ssvc(adp_json if isinstance(adp_json, list) else [])

    # Published/Modified
    published_at = (
        parse_iso8601(row_values[10])
        if len(row_values) > 10 and row_values[10]
        else None
    )
    modified_at = (
        parse_iso8601(row_values[11])
        if len(row_values) > 11 and row_values[11]
        else None
    )

    with transaction.atomic():
        cve_object, _ = CveModel.objects.get_or_create(
            name=cve_name,
            defaults={
                "description": description_text,
                "title": cna_title,
                "assigner": assigner_short_name,
                "source_attribution": "AE/Redshift",
                "published_at": published_at,
                "modified_at": modified_at,
                # CVSS v4 preferred, else v3 → CharFields
                "cvss_v4_version": cvss_version if cvss_source_type == "v4" else None,
                "cvss_v4_vector_string": cvss_vector
                if cvss_source_type == "v4"
                else None,
                "cvss_v4_base_score": cvss_base_score
                if cvss_source_type == "v4"
                else None,
                "cvss_v4_base_severity": cvss_base_severity
                if cvss_source_type == "v4"
                else None,
                "cvss_v3_version": cvss_version if cvss_source_type == "v3" else None,
                "cvss_v3_vector_string": cvss_vector
                if cvss_source_type == "v3"
                else None,
                "cvss_v3_base_score": cvss_base_score
                if cvss_source_type == "v3"
                else None,
                "cvss_v3_base_severity": cvss_base_severity
                if cvss_source_type == "v3"
                else None,
                "reference_urls": reference_urls_list or None,
                "cna_source_json": source_json
                if isinstance(source_json, (dict, list))
                else None,
                "cna_affected_json": affected_json
                if isinstance(affected_json, (dict, list))
                else None,
                "cna_problem_types_json": problem_types_json or None,
                "weaknesses": weaknesses_list or None,
            },
        )

        # Patch minimal fields on existing rows (only if empty)
        updated_fields: List[str] = []
        if not cve_object.source_attribution:
            cve_object.source_attribution = "AE/Redshift"
            updated_fields.append("source_attribution")
        if cna_title and not cve_object.title:
            cve_object.title = cna_title
            updated_fields.append("title")
        if assigner_short_name and not cve_object.assigner:
            cve_object.assigner = assigner_short_name
            updated_fields.append("assigner")
        if description_text and not cve_object.description:
            cve_object.description = description_text
            updated_fields.append("description")
        if reference_urls_list and not cve_object.reference_urls:
            cve_object.reference_urls = reference_urls_list
            updated_fields.append("reference_urls")
        if published_at and not cve_object.published_at:
            cve_object.published_at = published_at
            updated_fields.append("published_at")
        if modified_at and not cve_object.modified_at:
            cve_object.modified_at = modified_at
            updated_fields.append("modified_at")
        if (source_json and not cve_object.cna_source_json) and isinstance(
            source_json, (dict, list)
        ):
            cve_object.cna_source_json = source_json
            updated_fields.append("cna_source_json")
        if (affected_json and not cve_object.cna_affected_json) and isinstance(
            affected_json, (dict, list)
        ):
            cve_object.cna_affected_json = affected_json
            updated_fields.append("cna_affected_json")
        if problem_types_json and not cve_object.cna_problem_types_json:
            cve_object.cna_problem_types_json = problem_types_json
            updated_fields.append("cna_problem_types_json")
        if weaknesses_list and not cve_object.weaknesses:
            cve_object.weaknesses = weaknesses_list
            updated_fields.append("weaknesses")
        if updated_fields:
            cve_object.save(update_fields=updated_fields)

        # --- Patch CVSS if newer data arrives (prefer v4, else v3) ---
        cvss_fields_to_update: List[str] = []
        if cvss_source_type == "v4":
            if newdata_set(cve_object, "cvss_v4_version", cvss_version):
                cvss_fields_to_update.append("cvss_v4_version")
            if newdata_set(cve_object, "cvss_v4_vector_string", cvss_vector):
                cvss_fields_to_update.append("cvss_v4_vector_string")
            if newdata_set(cve_object, "cvss_v4_base_score", cvss_base_score):
                cvss_fields_to_update.append("cvss_v4_base_score")
            if newdata_set(cve_object, "cvss_v4_base_severity", cvss_base_severity):
                cvss_fields_to_update.append("cvss_v4_base_severity")
        elif cvss_source_type == "v3":
            if newdata_set(cve_object, "cvss_v3_version", cvss_version):
                cvss_fields_to_update.append("cvss_v3_version")
            if newdata_set(cve_object, "cvss_v3_vector_string", cvss_vector):
                cvss_fields_to_update.append("cvss_v3_vector_string")
            if newdata_set(cve_object, "cvss_v3_base_score", cvss_base_score):
                cvss_fields_to_update.append("cvss_v3_base_score")
            if newdata_set(cve_object, "cvss_v3_base_severity", cvss_base_severity):
                cvss_fields_to_update.append("cvss_v3_base_severity")
        if cvss_fields_to_update:
            cve_object.save(update_fields=sorted(set(cvss_fields_to_update)))
        # --- End CVSS patch ---

        # Normalize SSVC for consistent filtering, and USE the normalized values
        exploitation_value = ssvc_payload.get("exploitation")
        automatable_value = ssvc_payload.get("automatable")
        technical_impact_value = ssvc_payload.get("technical_impact")

        if isinstance(exploitation_value, str):
            exploitation_value = exploitation_value.lower()
        if isinstance(automatable_value, str):
            automatable_value = automatable_value.lower()
        if isinstance(technical_impact_value, str):
            technical_impact_value = technical_impact_value.lower()

        # Upsert SSVC (now using normalized values)
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
