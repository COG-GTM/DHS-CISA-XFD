"""Create views helper."""
# Standard Python Libraries
import logging

# Third-Party Libraries
from django.db import connections

# If changes are made to materialized view make sure to update version number
VW_SERVICE_VERSION = "20250823"
MAT_VW_COMBINED_VULNS_VERSION = "20250903"  # bumped due to schema change
DOMAIN_MAT_VIEW_VERSION = "20250823"
DOMAIN_SEARCH_MAT_VIEW_VERSION = "20250903"  # bumped due to combined depenedency

LOGGER = logging.getLogger(__name__)


def create_vuln_normal_views(database):
    """Create vuln normal views (ticket/shodan/credential)."""
    with connections[database].cursor() as cursor:
        LOGGER.info("Creating normal views...")

        # (Re)create base views
        cursor.execute("DROP VIEW IF EXISTS vw_ticket_vulns CASCADE;")
        cursor.execute("DROP VIEW IF EXISTS vw_shodan_vulns CASCADE;")
        cursor.execute("DROP VIEW IF EXISTS vw_credential_breaches CASCADE;")

        # ------------------------ vw_ticket_vulns ------------------------
        cursor.execute(
            """
            CREATE OR REPLACE VIEW vw_ticket_vulns AS
            WITH latest_ticket_event AS (
                SELECT DISTINCT ON (ticket_id) *
                FROM ticket_event
                ORDER BY ticket_id, event_timestamp DESC, id DESC
            ),
            latest_ip_sub AS (
                SELECT DISTINCT ON (ip_id) ip_id, sub_domain_id
                FROM ips_subs
                ORDER BY ip_id, sub_domain_id
            ),
            adp_latest AS (
                SELECT *
                FROM (
                    SELECT a.*,
                           ROW_NUMBER() OVER (
                             PARTITION BY a.cve_id
                             ORDER BY COALESCE(a.adp_date_updated, a.updated_at, a.ssvc_timestamp) DESC, a.id DESC
                           ) rn
                    FROM adp_ssvc a
                ) z
                WHERE rn = 1
            )
            SELECT DISTINCT ON (t.id)
                -- Core columns (order must be identical across unioned views)
                'vuln_scanning_tickets'                    AS scan_source,
                t.id::text                                 AS vuln_id,
                t.opened_timestamp::timestamp              AS created_at,
                t.updated_timestamp::timestamp             AS updated_at,
                COALESCE(t.closed_timestamp::timestamp, t.updated_timestamp::timestamp) AS last_seen,
                t.cve_string                               AS cve,
                t.vuln_name                                AS title,
                vs.cpe                                     AS product,
                t.ip_string                                AS domain_string,
                COALESCE(sub_link.sub_domain_id, t.ip_id)  AS domain_id,            -- uuid
                t.port_protocol                            AS protocol,
                t.vuln_port::text                          AS port,
                t.cvss_base_score::numeric                 AS cvss_base_score,
                CASE
                    WHEN t.cvss_severity = 0 THEN 'N/A'
                    WHEN t.cvss_severity = 1 THEN 'Low'
                    WHEN t.cvss_severity = 2 THEN 'Medium'
                    WHEN t.cvss_severity = 3 THEN 'High'
                    WHEN t.cvss_severity = 4 THEN 'Critical'
                    ELSE 'N/A'
                END                                         AS severity,
                t.organization_id                           AS organization_id,     -- uuid
                CASE WHEN t.is_open THEN 'open' ELSE 'closed' END AS state,
                t.vuln_source                               AS data_source,
                COALESCE(vs.description, te.reason, 'N/A')  AS description,
                t.false_positive::bool                      AS false_positive,
                t.is_kev::bool                              AS is_kev,
                t.is_kev_ransomware::bool                   AS is_kev_ransomware,
                t.service_name                              AS service_string,
                t.is_risky::bool                            AS is_risky_service,
                t.operating_system                          AS os,
                NULL::text                                  AS cwe,
                vs.cpe                                      AS cpe,
                NULL::jsonb                                 AS references,
                'unconfirmed'                               AS substate,
                NULL::bool                                  AS needs_population,
                NULL::jsonb                                 AS actions,
                NULL::jsonb                                 AS structured_data,
                NULL::jsonb                                 AS kev_results,
                -- Additional fields (existing)
                t.ip_string                                 AS ip_string,
                vs.cvss_vector                              AS cvss_vector,
                t.cvss_severity::int                        AS severity_int,
                vs.plugin_id                                AS plugin_id,
                vs.solution                                 AS solution,
                vs.synopsis                                 AS synopsis,
                vs.plugin_output                            AS results,

                -- ===== CVE columns (individual, not JSONB) =====
                cv.id::text                                 AS cve_row_id,
                cv.name                                     AS cve_name,
                cv.published_at::timestamp                  AS cve_published_at,
                cv.modified_at::timestamp                   AS cve_modified_at,
                cv.status                                   AS cve_status,
                cv.description                              AS cve_description,

                cv.cvss_v2_source                           AS cve_cvss_v2_source,
                cv.cvss_v2_type                             AS cve_cvss_v2_type,
                cv.cvss_v2_version                          AS cve_cvss_v2_version,
                cv.cvss_v2_vector_string                    AS cve_cvss_v2_vector_string,
                cv.cvss_v2_base_score::numeric              AS cve_cvss_v2_base_score,
                cv.cvss_v2_base_severity                    AS cve_cvss_v2_base_severity,
                cv.cvss_v2_exploitability_score::numeric    AS cve_cvss_v2_exploitability_score,
                cv.cvss_v2_impact_score::numeric            AS cve_cvss_v2_impact_score,

                cv.cvss_v3_source                           AS cve_cvss_v3_source,
                cv.cvss_v3_type                             AS cve_cvss_v3_type,
                cv.cvss_v3_version                          AS cve_cvss_v3_version,
                cv.cvss_v3_vector_string                    AS cve_cvss_v3_vector_string,
                cv.cvss_v3_base_score::numeric              AS cve_cvss_v3_base_score,
                cv.cvss_v3_base_severity                    AS cve_cvss_v3_base_severity,
                cv.cvss_v3_exploitability_score::numeric    AS cve_cvss_v3_exploitability_score,
                cv.cvss_v3_impact_score::numeric            AS cve_cvss_v3_impact_score,

                cv.cvss_v4_source                           AS cve_cvss_v4_source,
                cv.cvss_v4_type                             AS cve_cvss_v4_type,
                cv.cvss_v4_version                          AS cve_cvss_v4_version,
                cv.cvss_v4_vector_string                    AS cve_cvss_v4_vector_string,
                cv.cvss_v4_base_score::numeric              AS cve_cvss_v4_base_score,
                cv.cvss_v4_base_severity                    AS cve_cvss_v4_base_severity,
                cv.cvss_v4_exploitability_score::numeric    AS cve_cvss_v4_exploitability_score,
                cv.cvss_v4_impact_score::numeric            AS cve_cvss_v4_impact_score,

                -- arrays → jsonb safely
                CASE WHEN cv.weaknesses     IS NOT NULL THEN to_jsonb(cv.weaknesses)     ELSE NULL::jsonb END AS cve_weaknesses,
                CASE WHEN cv.reference_urls IS NOT NULL THEN to_jsonb(cv.reference_urls) ELSE NULL::jsonb END AS cve_reference_urls,
                CASE WHEN cv.cpe_list       IS NOT NULL THEN to_jsonb(cv.cpe_list)       ELSE NULL::jsonb END AS cve_cpe_list,

                cv.dve_score::numeric                        AS cve_dve_score,
                cv.source_attribution                        AS cve_source_attribution,
                cv.assigner                                  AS cve_assigner,
                cv.title                                     AS cve_title,

                -- text/jsonb → jsonb safely (no trimming/parsing)
                CASE WHEN cv.cna_source_json        IS NOT NULL THEN to_jsonb(cv.cna_source_json)        ELSE NULL::jsonb END AS cve_cna_source_json,
                CASE WHEN cv.cna_affected_json      IS NOT NULL THEN to_jsonb(cv.cna_affected_json)      ELSE NULL::jsonb END AS cve_cna_affected_json,
                CASE WHEN cv.cna_problem_types_json IS NOT NULL THEN to_jsonb(cv.cna_problem_types_json) ELSE NULL::jsonb END AS cve_cna_problem_types_json,

                -- ===== ADP/SSVC latest row =====
                adp.id::text                                 AS adp_id,
                adp.cve_id::text                              AS adp_cve_id,
                adp.exploitation                              AS adp_exploitation,
                adp.automatable                               AS adp_automatable,
                adp.technical_impact                          AS adp_technical_impact,
                adp.adp_provider                              AS adp_provider,
                adp.adp_title                                 AS adp_title,
                adp.ssvc_version                              AS adp_ssvc_version,
                adp.ssvc_timestamp::timestamp                 AS adp_ssvc_timestamp,
                adp.adp_date_updated::timestamp               AS adp_date_updated,
                adp.created_at::timestamp                     AS adp_created_at,
                adp.updated_at::timestamp                     AS adp_updated_at

            FROM ticket t
            LEFT JOIN latest_ticket_event te ON te.ticket_id = t.id
            LEFT JOIN vuln_scan vs           ON vs.id = te.vuln_scan_id
            LEFT JOIN latest_ip_sub sub_link ON sub_link.ip_id = t.ip_id
            LEFT JOIN cve cv                 ON cv.name = t.cve_string
            LEFT JOIN adp_latest adp         ON adp.cve_id::text = cv.id::text
            ;
            """
        )

        # ------------------------ vw_shodan_vulns ------------------------
        cursor.execute(
            """
            CREATE OR REPLACE VIEW vw_shodan_vulns AS
            WITH latest_ip_sub AS (
                SELECT DISTINCT ON (ip_id) ip_id, sub_domain_id
                FROM ips_subs
                ORDER BY ip_id, sub_domain_id
            ),
            adp_latest AS (
                SELECT *
                FROM (
                    SELECT a.*,
                           ROW_NUMBER() OVER (
                             PARTITION BY a.cve_id
                             ORDER BY COALESCE(a.adp_date_updated, a.updated_at, a.ssvc_timestamp) DESC, a.id DESC
                           ) rn
                    FROM adp_ssvc a
                ) z
                WHERE rn = 1
            )
            SELECT DISTINCT ON (sv.shodan_vuln_uid)
                'shodan_vulnerability'                      AS scan_source,
                sv.shodan_vuln_uid::text                    AS vuln_id,
                sv.created_at::timestamp                    AS created_at,
                sv."timestamp"::timestamp                   AS updated_at,
                sv."timestamp"::timestamp                   AS last_seen,
                sv.cve                                      AS cve,
                sv.name                                     AS title,
                array_to_string(sv.cpe, ', ')               AS product,
                sv.ip_string                                AS domain_string,
                COALESCE(sub_link.sub_domain_id, sv.ip_uid) AS domain_id,       -- uuid
                sv.protocol                                 AS protocol,
                sv.port::text                               AS port,
                sv.cvss::numeric                            AS cvss_base_score,
                COALESCE(sv.severity, 'N/A')                AS severity,
                sv.organization_uid                         AS organization_id,  -- uuid
                'open'                                      AS state,
                'Shodan'                                    AS data_source,
                COALESCE(sv.summary, sv.mitigation, 'N/A')  AS description,
                NULL::bool                                  AS false_positive,
                NULL::bool                                  AS is_kev,
                NULL::bool                                  AS is_kev_ransomware,
                NULL::text                                  AS service_string,
                NULL::bool                                  AS is_risky_service,
                NULL::text                                  AS os,
                NULL::text                                  AS cwe,
                array_to_string(sv.cpe, ', ')               AS cpe,
                NULL::jsonb                                 AS references,
                'unconfirmed'                               AS substate,
                NULL::bool                                  AS needs_population,
                NULL::jsonb                                 AS actions,
                NULL::jsonb                                 AS structured_data,
                NULL::jsonb                                 AS kev_results,

                sv.ip_string                                AS ip_string,
                NULL::text                                  AS cvss_vector,
                NULL::int                                   AS severity_int,
                NULL::text                                  AS plugin_id,
                NULL::text                                  AS solution,
                NULL::text                                  AS synopsis,
                NULL::text                                  AS results,

                -- CVE (by name)
                cv.id::text                                 AS cve_row_id,
                cv.name                                     AS cve_name,
                cv.published_at::timestamp                  AS cve_published_at,
                cv.modified_at::timestamp                   AS cve_modified_at,
                cv.status                                   AS cve_status,
                cv.description                              AS cve_description,

                cv.cvss_v2_source                           AS cve_cvss_v2_source,
                cv.cvss_v2_type                             AS cve_cvss_v2_type,
                cv.cvss_v2_version                          AS cve_cvss_v2_version,
                cv.cvss_v2_vector_string                    AS cve_cvss_v2_vector_string,
                cv.cvss_v2_base_score::numeric              AS cve_cvss_v2_base_score,
                cv.cvss_v2_base_severity                    AS cve_cvss_v2_base_severity,
                cv.cvss_v2_exploitability_score::numeric    AS cve_cvss_v2_exploitability_score,
                cv.cvss_v2_impact_score::numeric            AS cve_cvss_v2_impact_score,

                cv.cvss_v3_source                           AS cve_cvss_v3_source,
                cv.cvss_v3_type                             AS cve_cvss_v3_type,
                cv.cvss_v3_version                          AS cve_cvss_v3_version,
                cv.cvss_v3_vector_string                    AS cve_cvss_v3_vector_string,
                cv.cvss_v3_base_score::numeric              AS cve_cvss_v3_base_score,
                cv.cvss_v3_base_severity                    AS cve_cvss_v3_base_severity,
                cv.cvss_v3_exploitability_score::numeric    AS cve_cvss_v3_exploitability_score,
                cv.cvss_v3_impact_score::numeric            AS cve_cvss_v3_impact_score,

                cv.cvss_v4_source                           AS cve_cvss_v4_source,
                cv.cvss_v4_type                             AS cve_cvss_v4_type,
                cv.cvss_v4_version                          AS cve_cvss_v4_version,
                cv.cvss_v4_vector_string                    AS cve_cvss_v4_vector_string,
                cv.cvss_v4_base_score::numeric              AS cve_cvss_v4_base_score,
                cv.cvss_v4_base_severity                    AS cve_cvss_v4_base_severity,
                cv.cvss_v4_exploitability_score::numeric    AS cve_cvss_v4_exploitability_score,
                cv.cvss_v4_impact_score::numeric            AS cve_cvss_v4_impact_score,

                -- arrays → jsonb safely
                CASE WHEN cv.weaknesses     IS NOT NULL THEN to_jsonb(cv.weaknesses)     ELSE NULL::jsonb END AS cve_weaknesses,
                CASE WHEN cv.reference_urls IS NOT NULL THEN to_jsonb(cv.reference_urls) ELSE NULL::jsonb END AS cve_reference_urls,
                CASE WHEN cv.cpe_list       IS NOT NULL THEN to_jsonb(cv.cpe_list)       ELSE NULL::jsonb END AS cve_cpe_list,

                cv.dve_score::numeric                        AS cve_dve_score,
                cv.source_attribution                        AS cve_source_attribution,
                cv.assigner                                  AS cve_assigner,
                cv.title                                     AS cve_title,

                -- text/jsonb → jsonb safely (no trimming/parsing)
                CASE WHEN cv.cna_source_json        IS NOT NULL THEN to_jsonb(cv.cna_source_json)        ELSE NULL::jsonb END AS cve_cna_source_json,
                CASE WHEN cv.cna_affected_json      IS NOT NULL THEN to_jsonb(cv.cna_affected_json)      ELSE NULL::jsonb END AS cve_cna_affected_json,
                CASE WHEN cv.cna_problem_types_json IS NOT NULL THEN to_jsonb(cv.cna_problem_types_json) ELSE NULL::jsonb END AS cve_cna_problem_types_json,

                -- ADP (latest)
                adp.id::text                                 AS adp_id,
                adp.cve_id::text                              AS adp_cve_id,
                adp.exploitation                              AS adp_exploitation,
                adp.automatable                               AS adp_automatable,
                adp.technical_impact                          AS adp_technical_impact,
                adp.adp_provider                              AS adp_provider,
                adp.adp_title                                 AS adp_title,
                adp.ssvc_version                              AS adp_ssvc_version,
                adp.ssvc_timestamp::timestamp                 AS adp_ssvc_timestamp,
                adp.adp_date_updated::timestamp               AS adp_date_updated,
                adp.created_at::timestamp                     AS adp_created_at,
                adp.updated_at::timestamp                     AS adp_updated_at

            FROM shodan_vulns sv
            LEFT JOIN LATERAL (
                SELECT sub_domain_id
                FROM ips_subs ipsubs
                WHERE ipsubs.ip_id = sv.ip_uid
                ORDER BY sub_domain_id
                LIMIT 1
            ) AS sub_link ON TRUE
            LEFT JOIN cve cv         ON cv.name = sv.cve
            LEFT JOIN adp_latest adp ON adp.cve_id::text = cv.id::text
            ;
            """
        )

        # --------------------- vw_credential_breaches ---------------------
        cursor.execute(
            """
            CREATE OR REPLACE VIEW vw_credential_breaches AS
            SELECT DISTINCT ON (vuln_id)
                'credential_breach'                          AS scan_source,
                vuln_id::text                                AS vuln_id,
                created_at::timestamp                        AS created_at,
                updated_at::timestamp                        AS updated_at,
                last_seen::timestamp                         AS last_seen,
                NULL::text                                   AS cve,
                title                                        AS title,
                NULL::text                                   AS product,
                domain                                       AS domain_string,
                domain_id                                    AS domain_id,          -- uuid
                'SMTP,IMAP,POP3'                             AS protocol,
                NULL::text                                   AS port,
                NULL::numeric                                AS cvss_base_score,
                'N/A'                                        AS severity,
                organization_id                              AS organization_id,    -- uuid
                'open'                                       AS state,
                data_source                                  AS data_source,
                description                                  AS description,
                NULL::bool                                   AS false_positive,
                NULL::bool                                   AS is_kev,
                NULL::bool                                   AS is_kev_ransomware,
                NULL::text                                   AS service_string,
                NULL::bool                                   AS is_risky_service,
                NULL::text                                   AS os,
                NULL::text                                   AS cwe,
                NULL::text                                   AS cpe,
                NULL::jsonb                                  AS references,
                'unconfirmed'                                AS substate,
                NULL::bool                                   AS needs_population,
                NULL::jsonb                                  AS actions,
                NULL::jsonb                                  AS structured_data,
                NULL::jsonb                                  AS kev_results,

                NULL::text                                   AS ip_string,
                NULL::text                                   AS cvss_vector,
                NULL::int                                    AS severity_int,
                NULL::text                                   AS plugin_id,
                NULL::text                                   AS solution,
                NULL::text                                   AS synopsis,
                NULL::text                                   AS results,

                -- CVE columns (N/A placeholders to align union)
                NULL::text                                   AS cve_row_id,
                NULL::text                                   AS cve_name,
                NULL::timestamp                              AS cve_published_at,
                NULL::timestamp                              AS cve_modified_at,
                NULL::text                                   AS cve_status,
                NULL::text                                   AS cve_description,

                NULL::text                                   AS cve_cvss_v2_source,
                NULL::text                                   AS cve_cvss_v2_type,
                NULL::text                                   AS cve_cvss_v2_version,
                NULL::text                                   AS cve_cvss_v2_vector_string,
                NULL::numeric                                AS cve_cvss_v2_base_score,
                NULL::text                                   AS cve_cvss_v2_base_severity,
                NULL::numeric                                AS cve_cvss_v2_exploitability_score,
                NULL::numeric                                AS cve_cvss_v2_impact_score,

                NULL::text                                   AS cve_cvss_v3_source,
                NULL::text                                   AS cve_cvss_v3_type,
                NULL::text                                   AS cve_cvss_v3_version,
                NULL::text                                   AS cve_cvss_v3_vector_string,
                NULL::numeric                                AS cve_cvss_v3_base_score,
                NULL::text                                   AS cve_cvss_v3_base_severity,
                NULL::numeric                                AS cve_cvss_v3_exploitability_score,
                NULL::numeric                                AS cve_cvss_v3_impact_score,

                NULL::text                                   AS cve_cvss_v4_source,
                NULL::text                                   AS cve_cvss_v4_type,
                NULL::text                                   AS cve_cvss_v4_version,
                NULL::text                                   AS cve_cvss_v4_vector_string,
                NULL::numeric                                AS cve_cvss_v4_base_score,
                NULL::text                                   AS cve_cvss_v4_base_severity,
                NULL::numeric                                AS cve_cvss_v4_exploitability_score,
                NULL::numeric                                AS cve_cvss_v4_impact_score,

                NULL::jsonb                                  AS cve_weaknesses,
                NULL::jsonb                                  AS cve_reference_urls,
                NULL::jsonb                                  AS cve_cpe_list,

                NULL::numeric                                AS cve_dve_score,
                NULL::text                                   AS cve_source_attribution,
                NULL::text                                   AS cve_assigner,
                NULL::text                                   AS cve_title,
                NULL::jsonb                                  AS cve_cna_source_json,
                NULL::jsonb                                  AS cve_cna_affected_json,
                NULL::jsonb                                  AS cve_cna_problem_types_json,

                -- ADP columns (N/A placeholders)
                NULL::text                                   AS adp_id,
                NULL::text                                   AS adp_cve_id,
                NULL::text                                   AS adp_exploitation,
                NULL::text                                   AS adp_automatable,
                NULL::text                                   AS adp_technical_impact,
                NULL::text                                   AS adp_provider,
                NULL::text                                   AS adp_title,
                NULL::text                                   AS adp_ssvc_version,
                NULL::timestamp                              AS adp_ssvc_timestamp,
                NULL::timestamp                              AS adp_date_updated,
                NULL::timestamp                              AS adp_created_at,
                NULL::timestamp                              AS adp_updated_at

            FROM (
                SELECT
                    ce.credential_exposures_uid::text AS vuln_id,
                    cb.breach_date                    AS created_at,
                    cb.modified_date                  AS updated_at,
                    cb.modified_date                  AS last_seen,
                    cb.breach_name                    AS title,
                    COALESCE(sd.from_root_domain, sd.sub_domain) AS domain,
                    COALESCE(sd.root_domain_id, sd.sub_domain_uid) AS domain_id,
                    ce.organization_id                AS organization_id,
                    ds.name                           AS data_source,
                    cb.description,
                    ROW_NUMBER() OVER (
                        PARTITION BY cb.credential_breaches_uid, ce.sub_domain_id
                        ORDER BY ce.credential_exposures_uid
                    ) AS row_num
                FROM credential_breaches cb
                JOIN credential_exposures ce ON cb.credential_breaches_uid = ce.credential_breach_id
                JOIN sub_domains sd          ON ce.sub_domain_id = sd.sub_domain_uid
                JOIN data_source ds          ON ds.data_source_uid = cb.data_source_uid
            ) t
            WHERE row_num = 1;
            """
        )

        LOGGER.info("Normal views created.")


def create_vuln_materialized_views(database):
    """Create/refresh combined vulnerability materialized view."""
    # Build normal views from source DB first (kept from your original pattern)
    create_vuln_normal_views("mini_data_lake")

    with connections[database].cursor() as cursor:
        LOGGER.info("Creating materialized views...")

        cursor.execute("DROP MATERIALIZED VIEW IF EXISTS mat_vw_combined_vulns;")

        cursor.execute(
            """
            CREATE MATERIALIZED VIEW mat_vw_combined_vulns AS
            SELECT * FROM vw_ticket_vulns
            UNION ALL
            SELECT * FROM vw_shodan_vulns
            UNION ALL
            SELECT * FROM vw_credential_breaches;
            """
        )

        # Unique index required for REFRESH CONCURRENTLY
        cursor.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_uid
            ON mat_vw_combined_vulns (vuln_id);
            """
        )

        cursor.execute(
            "COMMENT ON MATERIALIZED VIEW mat_vw_combined_vulns IS 'version:{}';".format(
                MAT_VW_COMBINED_VULNS_VERSION
            )
        )

        LOGGER.info("Creating indexes on mat_vw_combined_vulns...")

        # Ensure pg_trgm is available
        cursor.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm;")

        # B-Tree indexes
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_domain_id ON mat_vw_combined_vulns (domain_id);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_organization_id ON mat_vw_combined_vulns (organization_id);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_severity ON mat_vw_combined_vulns (severity);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_state ON mat_vw_combined_vulns (state);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_substate ON mat_vw_combined_vulns (substate);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_is_kev ON mat_vw_combined_vulns (is_kev);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_created_at ON mat_vw_combined_vulns (created_at);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_scan_source ON mat_vw_combined_vulns (scan_source);"
        )

        # GIN + pg_trgm indexes
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_title_trgm ON mat_vw_combined_vulns USING gin (title gin_trgm_ops);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_domain_string_trgm ON mat_vw_combined_vulns USING gin (domain_string gin_trgm_ops);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_ip_string_trgm ON mat_vw_combined_vulns USING gin (ip_string gin_trgm_ops);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_cpe_trgm ON mat_vw_combined_vulns USING gin (cpe gin_trgm_ops);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_os_trgm ON mat_vw_combined_vulns USING gin (os gin_trgm_ops);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_cve_trgm ON mat_vw_combined_vulns USING gin (cve gin_trgm_ops);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_cwe_trgm ON mat_vw_combined_vulns USING gin (cwe gin_trgm_ops);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_port_trgm ON mat_vw_combined_vulns USING gin (port gin_trgm_ops);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_service_string_trgm ON mat_vw_combined_vulns USING gin (service_string gin_trgm_ops);"
        )

        LOGGER.info("Indexes created on mat_vw_combined_vulns.")
        LOGGER.info("Materialized views created.")


def create_domain_materialized_view(database):
    """Create mat_vw_domain view."""
    with connections[database].cursor() as cursor:
        LOGGER.info("Creating domain view...")
        cursor.execute("DROP MATERIALIZED VIEW IF EXISTS mat_vw_domain;")

        cursor.execute(
            """
            CREATE MATERIALIZED VIEW mat_vw_domain AS

            -- Subdomains (with or without linked IP)
            SELECT
                sub.sub_domain_uid AS id,
                sub.created_at,
                sub.updated_at,
                sub.synced_at,
                COALESCE(string_agg(DISTINCT host(ip.ip), ', '), NULL) AS ip,
                sub.from_root_domain,
                sub.subdomain_source,
                sub.ip_only,
                sub.reverse_name,
                sub.sub_domain AS name,
                sub.screenshot,
                sub.country,
                sub.asn,
                sub.cloud_hosted,
                ip.from_cidr,
                sub.ssl,
                sub.censys_certificates_results,
                sub.trustymail_results,
                NULL AS discovered_by_id,
                sub.organization_uid AS organization_id,
                'subdomain' as source

            FROM
                sub_domains sub
            LEFT JOIN
                ips_subs link ON sub.sub_domain_uid = link.sub_domain_id
            LEFT JOIN
                ip ON ip.id = link.ip_id
            GROUP BY
                sub.sub_domain_uid, sub.created_at, sub.updated_at, sub.synced_at,
                sub.from_root_domain, sub.subdomain_source, sub.ip_only,
                sub.reverse_name, sub.sub_domain, sub.screenshot, sub.country,
                sub.asn, sub.cloud_hosted, sub.ssl,
                sub.censys_certificates_results, sub.trustymail_results,
                sub.organization_uid, ip.from_cidr

            UNION ALL

            -- IPs with no linked subdomain
            SELECT
                ip.id,
                ip.created_timestamp AS created_at,
                ip.updated_timestamp AS updated_at,
                ip.synced_at AS synced_at,
                host(ip.ip) AS ip,
                NULL AS from_root_domain,
                NULL AS subdomain_source,
                TRUE AS ip_only,
                NULL AS reverse_name,
                host(ip.ip) AS name,
                NULL AS screenshot,
                NULL AS country,
                NULL AS asn,
                NULL AS cloud_hosted,
                ip.from_cidr,
                NULL AS ssl,
                NULL AS censys_certificates_results,
                NULL AS trustymail_results,
                NULL AS discovered_by_id,
                ip.organization_id,
                'ip' as source

            FROM
                ip
            WHERE
                ip.id NOT IN (SELECT ip_id FROM ips_subs);
        """
        )
        # Add unique index to allow REFRESH CONCURRENTLY
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_mat_vw_domain_id ON mat_vw_domain (id);"
        )

        # Add version comment
        cursor.execute(
            "COMMENT ON MATERIALIZED VIEW mat_vw_domain IS 'version:{}';".format(
                DOMAIN_MAT_VIEW_VERSION
            )
        )

        LOGGER.info("Domain materialized view created.")

        LOGGER.info("Creating indexes on mat_vw_domain...")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vw_domain_organization_id ON mat_vw_domain (organization_id);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vw_domain_name ON mat_vw_domain (name);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vw_domain_reverse_name ON mat_vw_domain (reverse_name);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vw_domain_ip ON mat_vw_domain (ip);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vw_domain_source ON mat_vw_domain (source);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vw_domain_created_at ON mat_vw_domain (created_at);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vw_domain_updated_at ON mat_vw_domain (updated_at);"
        )
        cursor.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vw_domain_org_id_id ON mat_vw_domain (organization_id, id);"
        )

        LOGGER.info("Domain Indexes created.")


def create_service_mat_view(database):
    """Create or replace the unified 'service' view."""
    with connections[database].cursor() as cursor:
        LOGGER.info("Creating 'service' view from ShodanAssets...")
        cursor.execute("DROP MATERIALIZED VIEW IF EXISTS mat_vw_service CASCADE;")
        cursor.execute("DROP VIEW IF EXISTS vw_shodan_service CASCADE;")
        cursor.execute("DROP VIEW IF EXISTS vw_portscan_service CASCADE;")

        cursor.execute(
            """
            CREATE OR REPLACE VIEW vw_shodan_service AS
            WITH latest_ip_sub AS (
                SELECT DISTINCT ON (ip_id) ip_id, sub_domain_id
                FROM ips_subs
                ORDER BY ip_id, sub_domain_id
            )
            SELECT
                s.shodan_asset_uid::text AS id,
                s.created_at AS "created_at",
                s.timestamp AS "updated_at",
                'shodan' AS "service_source",
                s.port,
                COALESCE(s.product, s.server) AS service,
                s.server AS banner,
                jsonb_build_array(
                    jsonb_build_object(
                        'name', COALESCE(s.product, s.server),
                        'cpe', NULL,
                        'tags', COALESCE(s.tags, '[]'::jsonb),
                        'vendor',
                            CASE
                                WHEN s.product ILIKE 'apache%' THEN 'apache'
                                WHEN s.product ILIKE 'microsoft%' THEN 'microsoft'
                                WHEN s.product ILIKE 'nginx%' THEN 'nginx'
                                WHEN s.product ILIKE 'jquery%' THEN 'jquery'
                                ELSE split_part(lower(s.product), ' ', 1)
                            END
                    )
                ) AS products,
                NULL::jsonb AS "censys_metadata",
                NULL::jsonb AS "censys_ipv4_results",
                NULL::jsonb AS "intrigue_ident_results",
                NULL::jsonb AS "shodan_results",
                NULL::jsonb AS "wappalyzer_results",
                s.timestamp AS "last_seen",
                s.ip_string AS "ip_string",
                COALESCE(sub_link.sub_domain_id,s.ip_uid) AS domain_id,
                NULL::uuid AS discovered_by_id
            FROM shodan_assets s
            LEFT JOIN latest_ip_sub sub_link ON sub_link.ip_id = s.ip_uid
            WHERE s.port IS NOT NULL AND
            (s.product IS NOT NULL OR s.server IS NOT NULL);
        """
        )

        LOGGER.info("Creating 'service' view from PortScans...")

        cursor.execute(
            """
            CREATE OR REPLACE VIEW vw_portscan_service AS
            WITH latest_ip_sub AS (
                SELECT DISTINCT ON (ip_id) ip_id, sub_domain_id
                FROM ips_subs
                ORDER BY ip_id, sub_domain_id
            )
            SELECT
                ps.id AS id,
                ps.time_scanned AS created_at,
                ps.time_scanned AS updated_at,
                'portscan' AS service_source,
                ps.port,
                ps.service_name AS service,
                ps.service_product AS banner,
                jsonb_build_array(
                    jsonb_build_object(
                        'name', ps.service_name,
                        'cpe', ps.service_cpe,
                        'tags', '[]'::jsonb,
                        'vendor',
                            CASE
                                WHEN ps.service_name ILIKE 'apache%' THEN 'apache'
                                WHEN ps.service_name ILIKE 'microsoft%' THEN 'microsoft'
                                WHEN ps.service_name ILIKE 'nginx%' THEN 'nginx'
                                WHEN ps.service_name ILIKE 'jquery%' THEN 'jquery'
                                ELSE split_part(lower(ps.service_name), ' ', 1)
                            END
                    )
                ) AS products,
                NULL::jsonb AS censys_metadata,
                NULL::jsonb AS censys_ipv4_results,
                NULL::jsonb AS intrigue_ident_results,
                NULL::jsonb AS shodan_results,
                NULL::jsonb AS wappalyzer_results,
                ps.time_scanned AS last_seen,
                ps.ip_string AS ip_string,
                COALESCE(sub_link.sub_domain_id, ps.ip_id) AS domain_id,
                NULL::uuid AS discovered_by_id
            FROM port_scan ps
            LEFT JOIN latest_ip_sub sub_link ON sub_link.ip_id = ps.ip_id
            WHERE ps.latest = TRUE
              AND ps.port IS NOT NULL
              AND ps.service_name IS NOT NULL;
        """
        )

        LOGGER.info("Creating materialized 'mat_vw_service' from union...")
        cursor.execute(
            """
            CREATE MATERIALIZED VIEW mat_vw_service AS
            SELECT * FROM vw_shodan_service
            UNION ALL
            SELECT * FROM vw_portscan_service;
            """
        )
        cursor.execute(
            "COMMENT ON MATERIALIZED VIEW mat_vw_service IS 'version:{}';".format(
                VW_SERVICE_VERSION
            )
        )
        LOGGER.info("Service materialized view created.")

        LOGGER.info("Creating unique indexes for service view...")

        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_vw_service_id ON mat_vw_service (id);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vw_service_domain_id ON mat_vw_service (domain_id);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vw_service_port ON mat_vw_service (port);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vw_service_service_source ON mat_vw_service (service_source);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vw_service_updated_at ON mat_vw_service (updated_at);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vw_service_last_seen ON mat_vw_service (last_seen);"
        )

        LOGGER.info("Materialized view 'mat_vw_service' created.")


def create_domain_search_mat_view(database):
    """
    Create mat_vw_domain_search view.

    Ensures mat_vw_combined_vulns exists FIRST to avoid
    'relation ... does not exist' errors when joining it.
    """
    # Guarantee dependency is present
    create_vuln_materialized_views(database)

    with connections[database].cursor() as cursor:
        LOGGER.info("Creating domain details materialized view...")
        cursor.execute("DROP MATERIALIZED VIEW IF EXISTS mat_vw_domain_search;")

        # Create materialized view
        cursor.execute(
            """
            CREATE MATERIALIZED VIEW mat_vw_domain_search AS

            SELECT
                d.id AS domain_id,
                d.name,
                d.ip,
                d.organization_id,
                o.name AS organization_name,
                d.source,
                d.country,
                d.cloud_hosted,
                d.reverse_name,
                d.created_at,
                d.updated_at,

            -- First 3 ports preview as comma-separated string
            (
                SELECT string_agg(port::text, ', ')
                FROM (
                    SELECT sub_inner.port
                    FROM (
                        SELECT s2.port, s2.last_seen
                        FROM mat_vw_service s2
                        WHERE s2.domain_id = d.id
                        ORDER BY s2.last_seen DESC
                    ) sub_inner
                    GROUP BY sub_inner.port
                    ORDER BY max(sub_inner.last_seen) DESC
                    LIMIT 3
                ) sub
            ) AS ports_preview,

            -- First 3 service names preview as comma-separated string
            (
                SELECT string_agg(service_name, ', ')
                FROM (
                    SELECT sub_inner.service_name
                    FROM (
                        SELECT (s2.products->0->>'name') AS service_name, s2.last_seen
                        FROM mat_vw_service s2
                        WHERE s2.domain_id = d.id
                        ORDER BY s2.last_seen DESC
                    ) sub_inner
                    GROUP BY sub_inner.service_name
                    ORDER BY max(sub_inner.last_seen) DESC
                    LIMIT 3
                ) sub
            ) AS services_preview,

            -- Services count
            COUNT(DISTINCT s.id) AS services_count,

            -- Vulnerabilities count
            CASE WHEN COUNT(DISTINCT v.vuln_id) = 0 THEN NULL ELSE COUNT(DISTINCT v.vuln_id) END AS vulnerabilities_count

            FROM
                mat_vw_domain d

            LEFT JOIN organization o
                ON o.id = d.organization_id

            LEFT JOIN mat_vw_service s
                ON s.domain_id = d.id

            LEFT JOIN mat_vw_combined_vulns v
                ON v.domain_id = d.id

            GROUP BY
                d.id,
                d.name,
                d.ip,
                d.organization_id,
                o.name,
                d.source,
                d.country,
                d.cloud_hosted,
                d.reverse_name,
                d.created_at,
                d.updated_at;
            """
        )

        # Add unique index for CONCURRENTLY refresh
        cursor.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_mat_vw_domain_search_id
            ON mat_vw_domain_search(domain_id);
            """
        )

        # Useful indexes for filtering/ordering
        LOGGER.info("Creating indexes on mat_vw_domain_search...")
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_mat_vw_domain_search_org_id_id
            ON mat_vw_domain_search (organization_id, domain_id);
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_mat_vw_domain_search_name
            ON mat_vw_domain_search (name);
            """
        )

        # Version tag
        cursor.execute(
            "COMMENT ON MATERIALIZED VIEW mat_vw_domain_search IS 'version:{}';".format(
                DOMAIN_SEARCH_MAT_VIEW_VERSION
            )
        )

        LOGGER.info("Domain details materialized view created.")


# Orchestration utility
def create_all_materialized(database):
    """Build everything in a dependency-safe order."""
    create_service_mat_view(database)  # independent
    create_domain_materialized_view(database)  # independent of combined
    create_vuln_materialized_views(database)  # builds combined MV
    create_domain_search_mat_view(database)  # depends on combined MV
