"""Create views helper."""

# Third-Party Libraries
from django.db import connections

# If changes are made to materialized view make sure to update version number
VW_SERVICE_VERSION = "20250606"
MAT_VW_COMBINED_VULNS_VERSION = "20250606"
DOMAIN_MAT_VIEW_VERSION = "20250606"


def create_vuln_normal_views(database):
    """Create vuln normal views."""
    with connections[database].cursor() as cursor:
        print("Creating normal views...")
        cursor.execute(
            """
            DROP VIEW IF EXISTS vw_ticket_vulns CASCADE;
        """
        )

        cursor.execute(
            """
            DROP VIEW IF EXISTS vw_shodan_vulns CASCADE;
        """
        )

        cursor.execute(
            """
            DROP VIEW IF EXISTS vw_credential_breaches CASCADE;
        """
        )
        cursor.execute(
            """
            CREATE OR REPLACE VIEW vw_ticket_vulns AS
            -- Query for VS Ticket Vulns
            SELECT
                'vuln_scanning_tickets' as scan_source,
                t.id as vuln_id,
                t.opened_timestamp::timestamp as created_at,
                t.updated_timestamp::timestamp as updated_at,
                coalesce(t.closed_timestamp::timestamp, t.updated_timestamp::timestamp) as last_seen,
                t.cve_string as cve,
                t.vuln_name as title,
                vs.cpe as product,
                t.ip_string as domain_string,
                COALESCE(sub_link.sub_domain_id, t.ip_id) AS domain_id,
                t.port_protocol as protocol,
                t.vuln_port::text as port,
                t.cvss_base_score,
                --COALESCE(t.cvss_severity::text, 'N/A') as severity,
                CASE
                    WHEN t.cvss_severity = 0 THEN 'N/A'
                    WHEN t.cvss_severity = 1 THEN 'Low'
                    WHEN t.cvss_severity = 2 THEN 'Medium'
                    WHEN t.cvss_severity = 3 THEN 'High'
                    WHEN t.cvss_severity = 4 THEN 'Critical'
                    ELSE 'N/A'
                END AS severity,
                t.organization_id,
                CASE
                    WHEN t.is_open THEN 'open'
                    ELSE 'closed'
                END AS state,
                t.vuln_source as data_source,
                COALESCE(vs.description, te.reason, 'N/A') as description,
                t.is_kev::bool as is_kev,
                t.service_name as service_string,
                t.is_risky::bool as is_risky_service,
                --null as os, --t.os as os --Not seeing this in the ticket
                t.operating_system as os,
                null as cwe,
                vs.cpe as cpe,
                null as references,
                'unconfirmed' as substate,
                null as needs_population,
                null as actions,
                null as structured_data,
                null as kev_results,
                --Additional fields requested:
                t.ip_string,
                vs.cvss_vector,
                t.cvss_severity as severity_int,
                vs.plugin_id,
                vs.solution,
                vs.synopsis,
                vs.plugin_output as results
            FROM ticket t
            LEFT JOIN LATERAL (
                SELECT te.*
                FROM ticket_event te
                WHERE te.ticket_id = t.id
                ORDER BY te.event_timestamp DESC, te.id DESC
                LIMIT 1
            ) te ON TRUE
            LEFT JOIN vuln_scan vs ON vs.id = te.vuln_scan_id
            LEFT JOIN LATERAL (
                SELECT sub_domain_id
                FROM ips_subs ipsubs
                WHERE ipsubs.ip_id = t.ip_id
                ORDER BY sub_domain_id
                LIMIT 1
            ) sub_link ON TRUE
            """
        )

        cursor.execute(
            """
            CREATE OR REPLACE VIEW vw_shodan_vulns AS
            -- Query for ShodanVulns
            SELECT
                'shodan_vulnerability' as scan_source,
                sv.shodan_vuln_uid::text as vuln_id,
                sv."created_at"::timestamp as created_at,
                sv."timestamp"::timestamp as updated_at,
                sv."timestamp"::timestamp as last_seen,
                sv.cve as cve,
                sv.name as title,
                array_to_string(sv.cpe, ', ') as product,
                sv.ip_string as domain,
                COALESCE(sub_link.sub_domain_id, sv.ip_uid) AS domain_id,
                sv.protocol as protocol,
                sv.port as port,
                sv.cvss as cvss_base_score,
                COALESCE(sv.severity, 'N/A') as severity,
                sv.organization_uid as organization_id,
                'open' as state,
                'Shodan' as data_source,
                COALESCE(sv.summary, sv.mitigation, 'N/A') as description,
                null::bool as is_kev,
                null as service_string,
                null::bool as is_risky_service,
                null as os, --t.os as os --Not seeing this in the ticket
                null as cwe,
                array_to_string(sv.cpe, ', ') as cpe,
                null as references,
                'unconfirmed' as substate,
                null as needs_population,
                null as actions,
                null as structured_data,
                null as kev_results,
                --Additional Data requested
                sv.ip_string,
                null AS cvss_vector,
                null::int AS severity_int,
                null as plugin_id,
                null AS solution,
                null AS synopsis,
                null AS results
            FROM shodan_vulns as sv
            LEFT JOIN LATERAL (
                SELECT sub_domain_id
                FROM ips_subs ipsubs
                WHERE ipsubs.ip_id = sv.ip_uid
                ORDER BY sub_domain_id -- or ORDER BY created_at if that column exists
                LIMIT 1
            ) AS sub_link ON TRUE
        """
        )

        cursor.execute(
            """
            CREATE OR REPLACE VIEW vw_credential_breaches AS
            SELECT
                scan_source,
                vuln_id,
                created_at,
                updated_at,
                last_seen,
                cve,
                title,
                product,
                domain,
                domain_id,
                protocol,
                port,
                cvss_base_score,
                severity,
                organization_id,
                state,
                data_source,
                description,
                null::bool as is_kev,
                null as service_string,
                null::bool as is_risky_service,
                null as os, --t.os as os --Not seeing this in the ticket
                null as cwe,
                null as cpe,
                null as references,
                'unconfirmed' as substate,
                null as needs_population,
                null as actions,
                null as structured_data,
                null as kev_results,
                --Additional Data requested
                null AS ip_string,
                null AS cvss_vector,
                null::int AS severity_int,
                null as plugin_id,
                null AS solution,
                null AS synopsis,
                null AS results
                FROM (
                SELECT
                    ce.credential_exposures_uid::text AS vuln_id,
                    'credential_breach' AS scan_source,
                    cb.breach_date AS created_at,
                    cb.modified_date AS updated_at,
                    cb.modified_date AS last_seen,
                    NULL AS cve,
                    cb.breach_name AS title,
                    NULL AS product,
                    COALESCE(sd.from_root_domain, sd.sub_domain) AS domain,
                    COALESCE(sd.root_domain_id, sd.sub_domain_uid) AS domain_id,
                    'SMTP,IMAP,POP3' AS protocol,
                    NULL AS port,
                    NULL::float AS cvss_base_score,
                    'N/A' AS severity,
                    ce.organization_id,
                    'open' AS state,
                    ds.name AS data_source,
                    cb.description,
                    ROW_NUMBER() OVER (
                        PARTITION BY cb.credential_breaches_uid, ce.sub_domain_id
                        ORDER BY ce.credential_exposures_uid
                    ) AS row_num
                FROM credential_breaches cb
                JOIN credential_exposures ce ON cb.credential_breaches_uid = ce.credential_breach_id
                JOIN sub_domains sd ON ce.sub_domain_id = sd.sub_domain_uid
                JOIN data_source ds ON ds.data_source_uid = cb.data_source_uid
            ) t
            WHERE row_num = 1;
        """
        )
        print("Normal views created.")


def create_vuln_materialized_views(database):
    """Create vuln materialized views."""
    create_vuln_normal_views("mini_data_lake")
    with connections[database].cursor() as cursor:
        print("Creating materialized views...")

        cursor.execute("DROP MATERIALIZED VIEW IF EXISTS mat_vw_combined_vulns;")

        # Example materialized view
        cursor.execute(
            """
            CREATE MATERIALIZED VIEW IF NOT EXISTS mat_vw_combined_vulns AS
            SELECT * from vw_ticket_vulns
            union
            SELECT * from vw_shodan_vulns
            union
            SELECT * from vw_credential_breaches
        """
        )

        # Create unique index required for CONCURRENTLY
        cursor.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_mat_vw_combined_vulns_uid
            ON mat_vw_combined_vulns (vuln_id)
        """
        )

        cursor.execute(
            "COMMENT ON MATERIALIZED VIEW mat_vw_combined_vulns IS 'version:{}';".format(
                MAT_VW_COMBINED_VULNS_VERSION
            )
        )

        print("Materialized views created.")


def create_domain_materialized_view(database):
    """Create mat_vw_domain view."""
    with connections[database].cursor() as cursor:
        print("Creating domain view...")
        cursor.execute("DROP MATERIALIZED VIEW IF EXISTS mat_vw_domain;")

        # Example materialized view
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
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_mat_vw_domain_id ON mat_vw_domain (id);
            """
        )

        # Add version comment
        cursor.execute(
            "COMMENT ON MATERIALIZED VIEW mat_vw_domain IS 'version:{}';".format(
                DOMAIN_MAT_VIEW_VERSION
            )
        )

        print("Domain materialized view created.")


def create_service_mat_view(database):
    """Create or replace the unified 'service' view (starting with Shodan data)."""
    with connections[database].cursor() as cursor:
        print("Creating 'service' view from ShodanAssets...")
        cursor.execute("DROP MATERIALIZED VIEW IF EXISTS mat_vw_service CASCADE;")
        cursor.execute("DROP VIEW IF EXISTS vw_service CASCADE;")
        cursor.execute("DROP VIEW IF EXISTS vw_shodan_service CASCADE;")
        cursor.execute("DROP VIEW IF EXISTS vw_portscan_service CASCADE;")

        cursor.execute(
            """
            CREATE OR REPLACE VIEW vw_shodan_service AS
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
            LEFT JOIN LATERAL (
                SELECT sub_domain_id
                FROM ips_subs ipsubs
                WHERE ipsubs.ip_id = s.ip_uid
                ORDER BY sub_domain_id -- or ORDER BY created_at if that column exists
                LIMIT 1
            ) AS sub_link ON TRUE
            WHERE s.port IS NOT NULL AND
            (s.product IS NOT NULL OR s.server IS NOT NULL);
        """
        )

        print("Creating 'service' view from PortScans...")

        cursor.execute(
            """
            CREATE OR REPLACE VIEW vw_portscan_service AS
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
            LEFT JOIN LATERAL (
                SELECT sub_domain_id
                FROM ips_subs ipsubs
                WHERE ipsubs.ip_id = ps.ip_id
                ORDER BY sub_domain_id
                LIMIT 1
            ) sub_link ON TRUE
            WHERE ps.latest = TRUE
            AND ps.port IS NOT NULL
            AND ps.service_name IS NOT NULL;
        """
        )

        print("Creating materialized 'mat_vw_service' from union...")
        cursor.execute(
            """
            CREATE MATERIALIZED VIEW mat_vw_service AS
            SELECT * FROM vw_shodan_service
            UNION ALL
            SELECT * FROM vw_portscan_service;
            """
        )

        print("Creating unique index for concurrent refresh...")
        cursor.execute(
            """
            CREATE UNIQUE INDEX idx_mat_vw_service_id ON mat_vw_service (id);
            """
        )

        cursor.execute(
            "COMMENT ON MATERIALIZED VIEW mat_vw_service IS 'version:{}';".format(
                VW_SERVICE_VERSION
            )
        )

        print("Materialized view 'mat_vw_service' created.")
