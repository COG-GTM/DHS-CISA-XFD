"""Syncdb helpers."""
# File: xfd_api/utils/db_utils.py
# Standard Python Libraries
from collections import defaultdict, deque
from datetime import datetime
import hashlib
from itertools import islice
import json
import os
import random
import secrets

# Third-Party Libraries
from django.apps import apps
from django.conf import settings
from django.db import connections, transaction
from django.db.backends.base.schema import BaseDatabaseSchemaEditor
from django.db.utils import OperationalError, ProgrammingError
from psycopg2.errors import WrongObjectType
from xfd_api.models import Domain, Service, Vulnerability
from xfd_api.tasks.es_client import ESClient
from xfd_mini_dl.models import ApiKey, Organization, OrganizationTag, User, UserType

# Constants for sample data generation
SAMPLE_TAG_NAME = "Sample Data"
NUM_SAMPLE_ORGS = 10
NUM_SAMPLE_DOMAINS = 10
PROB_SAMPLE_SERVICES = 0.5
PROB_SAMPLE_VULNERABILITIES = 0.5
SAMPLE_STATES = ["Virginia", "California", "Colorado"]
SAMPLE_REGION_IDS = ["1", "2", "3"]
ORGANIZATION_CHUNK_SIZE = 50

# Load sample data files
SAMPLE_DATA_DIR = os.path.join(settings.BASE_DIR, "xfd_api", "tasks", "sample_data")
services = json.load(open(os.path.join(SAMPLE_DATA_DIR, "services.json")))
cpes = json.load(open(os.path.join(SAMPLE_DATA_DIR, "cpes.json")))
vulnerabilities = json.load(open(os.path.join(SAMPLE_DATA_DIR, "vulnerabilities.json")))
nouns = json.load(open(os.path.join(SAMPLE_DATA_DIR, "nouns.json")))
adjectives = json.load(open(os.path.join(SAMPLE_DATA_DIR, "adjectives.json")))

# Elasticsearch client
es_client = ESClient()


def manage_elasticsearch_indices(dangerouslyforce):
    """Handle Elasticsearch index setup and teardown."""
    try:
        if dangerouslyforce:
            es_client.delete_all()
        es_client.sync_organizations_index()
        es_client.sync_domains_index()
        print("Elasticsearch indices synchronized.")
    except Exception as e:
        print("Error managing Elasticsearch indices: {}".format(e))


def populate_sample_data():
    """Populate sample data into the database."""
    with transaction.atomic():
        tag, _ = OrganizationTag.objects.get_or_create(name=SAMPLE_TAG_NAME)
        for _ in range(NUM_SAMPLE_ORGS):
            # Create organization
            org = Organization.objects.create(
                acronym="".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=5)),
                name=generate_random_name(),
                root_domains=["crossfeed.local"],
                ip_blocks=[],
                is_passive=False,
                state=random.choice(SAMPLE_STATES),
                region_id=random.choice(SAMPLE_REGION_IDS),
            )
            org.organization_tags.add(tag)

            # Create sample domains, services, and vulnerabilities
            # for _ in range(NUM_SAMPLE_DOMAINS):
            #     domain = create_sample_domain(org)
            #     create_sample_services_and_vulnerabilities(domain)

        # Create a user for the organization
        user = create_sample_user(org)

        # Create an API key for the user
        create_api_key_for_user(user)

        # test_user = create_test_user(org)

        # create_api_key_for_user(test_user)


def create_sample_user(organization):
    """Create a sample user linked to an organization."""
    user = User.objects.create(
        first_name="Sample",
        last_name="User",
        email="user{}@example.com".format(random.randint(1, 1000)),
        user_type=UserType.GLOBAL_ADMIN,
        state=random.choice(SAMPLE_STATES),
        region_id=random.choice(SAMPLE_REGION_IDS),
    )
    # Set user as the creator of the organization (optional)
    organization.created_by = user
    organization.save()
    return user


def create_test_user(organization):
    """Create a test user linked to an organization."""
    email = os.environ.get("PW_XFD_USERNAME")

    existing_user = User.objects.filter(email=email).first()

    if existing_user:
        return existing_user

    if not email:
        user = User.objects.create(
            first_name="Test",
            last_name="User",
            email=os.environ.get("PW_XFD_USERNAME"),
            user_type=UserType.GLOBAL_ADMIN,
            state=random.choice(SAMPLE_STATES),
            region_id=random.choice(SAMPLE_REGION_IDS),
            organization=organization,
        )

    return user


def create_api_key_for_user(user):
    """Create a sample API key linked to a user."""
    # Generate a random 16-byte API key
    key = secrets.token_hex(16)

    # Hash the API key
    hashed_key = hashlib.sha256(key.encode()).hexdigest()

    # Create the API key record
    ApiKey.objects.create(
        hashed_key=hashed_key,
        last_four=key[-4:],
        user=user,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )

    # Print the raw key for debugging or manual testing
    print("Created API key for user {}: {}".format(user.email, key))


def generate_random_name():
    """Generate a random organization name using an adjective and entity noun."""
    adjective = random.choice(adjectives)
    noun = random.choice(nouns)
    entity = random.choice(["City", "County", "Agency", "Department"])
    return "{} {} {}".format(adjective.capitalize(), entity, noun.capitalize())


def create_sample_domain(organization):
    """Create a sample domain linked to an organization."""
    domain_name = "{}-{}.crossfeed.local".format(
        random.choice(adjectives), random.choice(nouns)
    ).lower()
    ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
    return Domain.objects.create(
        name=domain_name,
        ip=ip,
        fromRootDomain="crossfeed.local",
        subdomainSource="findomain",
        organization=organization,
    )


def create_sample_services_and_vulnerabilities(domain):
    """Create sample services and vulnerabilities for a domain."""
    # Add random services
    if random.random() < PROB_SAMPLE_SERVICES:
        Service.objects.create(
            domain=domain,
            port=random.choice([80, 443]),
            service="http",
            serviceSource="shodan",
            wappalyzerResults=[
                {"technology": {"cpe": random.choice(cpes)}, "version": ""}
            ],
        )

    # Add random vulnerabilities
    if random.random() < PROB_SAMPLE_VULNERABILITIES:
        state = random.choice(["open", "closed"])
        Vulnerability.objects.create(
            title="Sample Vulnerability "
            + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=3)),
            domain=domain,
            service=None,
            description="Sample description",
            severity=random.choice(
                [
                    None,
                    "N/A",
                    "n/a",
                    "Null",
                    "null",
                    "Undefined",
                    "undefined",
                    "",
                    "Low",
                    "Medium",
                    "High",
                    "Critical",
                    "Other",
                    "!@#$%^&*()",
                    1234,
                    "low",
                    "medium",
                    "high",
                    "critical",
                    "other",
                ]
            ),
            cve="CVE-"
            + random.choice(
                [
                    "2024-47421",
                    "2021-22501",
                    "2024-53959",
                    "2024-47422",
                    "2024-47423",
                    "2020-28163",
                    "2020-29312",
                ]
            ),
            needsPopulation=True,
            state=state,
            substate=random.choice(["unconfirmed", "exploitable"])
            if state == "open"
            else random.choice(["false-positive", "accepted-risk", "remediated"]),
            source="sample_source",
            actions=[],
            structuredData={},
        )


def table_exists_in_db(table_name, database):
    """Check table exists."""
    with connections[database].cursor() as cursor:
        cursor.execute("SELECT to_regclass(%s);", [table_name])
        return cursor.fetchone()[0] is not None


def synchronize(target_app_label=None):
    """
    Synchronize the database schema with Django models.

    Handles creation, update, and removal of tables and fields dynamically,
    including Many-to-Many linking tables.
    """
    allowed_labels = ["xfd_mini_dl", "xfd_api"]
    db_mapping = {
        "xfd_mini_dl": "mini_data_lake",
        "xfd_api": "default",
    }

    if target_app_label is None:
        raise ValueError(
            "The 'target_app_label' parameter is required to synchronize specific models. "
            "Please provide an app label."
        )

    if target_app_label not in allowed_labels:
        raise ValueError(
            "Invalid 'target_app_label' provided. Must be one of: {}.".format(
                ", ".join(allowed_labels)
            )
        )

    # Get database name for 'connections':
    # The 'connections' object gets all databases defined in settings.py
    database = db_mapping.get(target_app_label, "default")
    print(
        "Synchronizing database schema for app '{}' in database '{}'...".format(
            target_app_label, database
        )
    )

    # Warning: Cursor automatically closes after use of 'with'
    with connections[database].schema_editor() as schema_editor:
        ordered_models = get_ordered_models(target_app_label)
        # Compute allowed table names from the models we are syncing.
        allowed_tables = {m._meta.db_table for m in ordered_models}
        for model in ordered_models:
            print("Processing model: {}".format(model.__name__))
            process_model(schema_editor, model, database, allowed_tables)

        print("Processing Many-to-Many tables...")
        process_m2m_tables(schema_editor, ordered_models, database)

        if target_app_label == "xfd_mini_dl":
            create_vuln_normal_views(database)
            create_vuln_materialized_views(database)
            create_domain_view(database)
            create_service_view(database)

        cleanup_stale_tables(ordered_models, database)

    print("Database synchronization complete.")


def get_ordered_models(target_app_label):
    """
    Get models in dependency order to ensure foreign key constraints are respected.

    Only consider dependencies among models within the same app, and break cycles
    deterministically (alphabetically by model name).
    """
    # Get all models for the app and create a set for quick membership checks.
    models = [
        m for m in apps.get_app_config(target_app_label).get_models() if m._meta.managed
    ]
    model_set = set(models)

    # Build dependency graph, but only include dependencies to models within the app.
    dependencies = defaultdict(set)
    dependents = defaultdict(set)
    for model in models:
        for field in model._meta.get_fields():
            # Only add a dependency if the related model is in our app's set.
            if field.is_relation and field.related_model in model_set:
                dependencies[model].add(field.related_model)
                dependents[field.related_model].add(model)

    # Start with models that have no dependencies.
    ordered = []
    independent_models = deque([model for model in models if not dependencies[model]])

    while independent_models:
        model = independent_models.popleft()
        ordered.append(model)
        # Remove this model as a dependency from its dependents.
        for dependent in list(dependents[model]):
            dependencies[dependent].discard(model)
            dependents[model].discard(dependent)
            if not dependencies[dependent]:
                independent_models.append(dependent)

    # Any models not yet added are in a dependency cycle.
    remaining = [model for model in models if model not in ordered]
    if remaining:
        print(
            "Circular dependencies detected among: {}".format(
                ", ".join(m.__name__ for m in remaining)
            )
        )
        # Sort them deterministically (alphabetically) so that, for example, 'User' comes before 'Organization'
        remaining_sorted = sorted(remaining, key=lambda m: m.__name__)
        ordered.extend(remaining_sorted)

    return ordered


def process_model(
    schema_editor: BaseDatabaseSchemaEditor, model, database, allowed_tables
):
    """Process a single model: create or update its table."""
    table_name = model._meta.db_table

    with connections[database].cursor() as cursor:
        try:
            # Check if the table exists
            cursor.execute("SELECT to_regclass(%s);", [table_name])
            table_exists = cursor.fetchone()[0] is not None

            if table_exists:
                print("Updating table for model: {}".format(model.__name__))
                update_table(schema_editor, model, database, allowed_tables)
            else:
                print("Creating table for model: {}".format(model.__name__))
                schema_editor.create_model(model)
        except Exception as e:
            print("Error processing model {}: {}".format(model.__name__, e))


def process_m2m_tables(schema_editor: BaseDatabaseSchemaEditor, models, database):
    """Handle creation of Many-to-Many linking tables."""
    with connections[database].cursor() as cursor:
        for model in models:
            for field in model._meta.local_many_to_many:
                m2m_table_name = field.m2m_db_table()

                # Check if the M2M table exists
                cursor.execute("SELECT to_regclass('{}');".format(m2m_table_name))
                table_exists = cursor.fetchone()[0] is not None

                if not table_exists:
                    print("Creating Many-to-Many table: {}".format(m2m_table_name))
                    schema_editor.create_model(field.remote_field.through)
                else:
                    print(
                        "Many-to-Many table {} already exists. Skipping.".format(
                            m2m_table_name
                        )
                    )


def update_table(
    schema_editor: BaseDatabaseSchemaEditor, model, database, allowed_tables
):
    """Update an existing table for the given model. Ensure columns match fields."""
    table_name = model._meta.db_table
    db_fields = {field.column for field in model._meta.fields}

    with connections[database].cursor() as cursor:
        # Get existing columns
        cursor.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = %s;",
            [table_name],
        )
        existing_columns = {row[0] for row in cursor.fetchall()}

        # Add missing columns
        missing_columns = db_fields - existing_columns
        for field in model._meta.fields:
            if field.column in missing_columns:
                if hasattr(field, "remote_field") and field.remote_field:
                    related_table = field.remote_field.model._meta.db_table
                    # If the related table isn't in allowed_tables or doesn't exist yet, skip adding this field.
                    if related_table not in allowed_tables or not table_exists_in_db(
                        related_table, database
                    ):
                        print(
                            "Skipping addition of foreign key field '{}' on model '{}' because referenced table '{}' does not exist yet.".format(
                                field.column, model.__name__, related_table
                            )
                        )
                        continue
                print(
                    "Adding column '{}' to table '{}'".format(field.column, table_name)
                )
                schema_editor.add_field(model, field)

        # Remove extra columns
        extra_columns = existing_columns - db_fields
        for column in extra_columns:
            print(
                "Removing extra column '{}' from table '{}'".format(column, table_name)
            )
            try:
                safe_table_name = connections[database].ops.quote_name(table_name)
                safe_column_name = connections[database].ops.quote_name(column)
                query = "ALTER TABLE {} DROP COLUMN IF EXISTS {};".format(
                    safe_table_name, safe_column_name
                )
                cursor.execute(query)
            except Exception as e:
                print(
                    "Error dropping column '{}' from table '{}': {}".format(
                        column, table_name, e
                    )
                )


def cleanup_stale_tables(models, database):
    """Remove tables that no longer correspond to any Django model or Many-to-Many relationship."""
    print("Checking for stale tables...")

    with connections[database].cursor() as cursor:
        model_tables = {model._meta.db_table for model in models if model._meta.managed}
        # [m for m in apps.get_app_config(target_app_label).get_models() if m._meta.managed]
        m2m_tables = {
            field.m2m_db_table()
            for model in models
            # if model._meta.managed
            for field in model._meta.local_many_to_many
        }
        expected_tables = model_tables.union(m2m_tables)

        cursor.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public';")
        existing_tables = {row[0] for row in cursor.fetchall()}

        # Get regular views
        cursor.execute(
            """
            SELECT table_name
            FROM information_schema.views
            WHERE table_schema = 'public';
        """
        )
        regular_views = {row[0] for row in cursor.fetchall()}

        # Get materialized views
        cursor.execute(
            """
            SELECT matviewname
            FROM pg_matviews
            WHERE schemaname = 'public';
        """
        )
        materialized_views = {row[0] for row in cursor.fetchall()}

        # Combine both
        all_views = regular_views.union(materialized_views)
        existing_tables = existing_tables - all_views
        stale_tables = existing_tables - expected_tables
        for table in stale_tables:
            print("Removing stale table: {}".format(table))
            try:
                # Use `quote_ident` to safely handle table names with special characters or reserved words
                cursor.execute(
                    "DROP TABLE {} CASCADE;".format(
                        connections[database].ops.quote_name(table)
                    )
                )
            except OperationalError as e:
                print("Error dropping stale table {}: {}".format(table, e))
            except WrongObjectType as e:
                print("Tried to drop a non table entity {}: {}".format(table, e))
            except ProgrammingError as e:
                print("Issue dropping entity {}: {}".format(table, e))


def drop_all_tables(app_label=None):
    """Drop all tables in the database. Used with `dangerouslyforce`."""
    allowed_labels = ["xfd_mini_dl", "xfd_api"]
    db_mapping = {
        "xfd_mini_dl": "mini_data_lake",
        "xfd_api": "default",
    }

    if app_label is None:
        raise ValueError(
            "The 'app_label' parameter is required to synchronize specific models."
        )

    if app_label not in allowed_labels:
        raise ValueError(
            "Invalid 'app_label' provided. Must be one of: {}.".format(
                ", ".join(allowed_labels)
            )
        )

    database = db_mapping.get(app_label, "default")
    print(
        "Resetting database schema for app '{}' in database '{}'...".format(
            app_label, database
        )
    )

    with connections[database].cursor() as cursor:
        try:
            # Drop all constraints first to avoid foreign key dependency issues
            cursor.execute("DROP SCHEMA public CASCADE;")
            cursor.execute("CREATE SCHEMA public;")
            cursor.execute(
                "GRANT ALL ON SCHEMA public TO {};".format(os.getenv("DB_USERNAME"))
            )
            cursor.execute("GRANT ALL ON SCHEMA public TO public;")
        except Exception as e:
            print("Error resetting schema: {}".format(e))

    print("Database schema reset successfully.")


def chunked_iterable(iterable, size):
    """Yield successive chunks of size `size` from `iterable`."""
    iterator = iter(iterable)
    while True:
        chunk = list(islice(iterator, size))
        if not chunk:
            break
        yield chunk


def update_organization_chunk(es_client, organizations):
    """Update a chunk of organizations."""
    es_client.update_organizations(organizations)


def sync_es_organizations():
    """Sync elastic search organizations."""
    try:
        # Fetch all organization IDs
        organization_ids = list(Organization.objects.values_list("id", flat=True))
        print("Found {} organizations to sync.".format(len(organization_ids)))

        if organization_ids:
            # Split IDs into chunks
            for organization_chunk in chunked_iterable(
                organization_ids, ORGANIZATION_CHUNK_SIZE
            ):
                # Fetch full organization data for the current chunk
                organizations = list(
                    Organization.objects.filter(id__in=organization_chunk).values(
                        "id",
                        "name",
                        "country",
                        "state",
                        "region_id",
                        "organization_tags",
                    )
                )
                print("Syncing {} organizations...".format(len(organizations)))

                # Attempt to update Elasticsearch
                update_organization_chunk(es_client, organizations)

            print("Organization sync complete.")
        else:
            print("No organizations to sync.")

    except Exception as e:
        print("Error syncing organizations: {}".format(e))
        raise e


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
                    WHEN te."action" IN ('OPENED', 'REOPENED', 'CHANGED', 'VERIFIED') THEN 'open'
                    WHEN te."action" = 'CLOSED' THEN 'closed'
                    ELSE 'unknown'  -- optional, in case other values sneak in
                END AS state,
                t.vuln_source as data_source,
                COALESCE(vs.description, te.reason, 'N/A') as description,
                t.is_kev::bool as is_kev,
                t.service_name as service_string,
                t.is_risky::bool as is_risky_service,
                null as os, --t.os as os --Not seeing this in the ticket
                null as cwe,
                vs.cpe as cpe,
                null as references,
                'unconfirmed' as substate,
                null as needs_population,
                null as actions,
                null as structured_data,
                null as kev_results
            FROM ticket t
            LEFT JOIN ticket_event te
            ON te.ticket_id = t.id
            LEFT JOIN vuln_scan vs
            ON vs.id = te.vuln_scan_id
            LEFT JOIN LATERAL (
                SELECT sub_domain_id
                FROM ips_subs ipsubs
                WHERE ipsubs.ip_id = t.ip_id
                ORDER BY sub_domain_id -- or ORDER BY created_at if that column exists
                LIMIT 1
            ) AS sub_link ON TRUE
            WHERE te.event_timestamp = (
                SELECT MAX(event_timestamp)
                FROM ticket_event
                WHERE ticket_id = t.id
            )
        """
        )

        # TODO: Fix created_at with real value
        cursor.execute(
            """
            CREATE OR REPLACE VIEW vw_shodan_vulns AS
            -- Query for ShodanVulns
            SELECT
                'shodan_vulnerability' as scan_source,
                sv.shodan_vuln_uid::text as vuln_id,
                sv."timestamp"::timestamp as created_at,
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
                null as kev_results
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
                null as kev_results
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

        # Optional refresh
        cursor.execute("REFRESH MATERIALIZED VIEW mat_vw_combined_vulns;")

        print("Materialized views created.")


def create_domain_view(database):
    """Create vw_domain view."""
    with connections[database].cursor() as cursor:
        print("Creating domain view...")
        cursor.execute("DROP VIEW IF EXISTS vw_service;")
        cursor.execute("DROP VIEW IF EXISTS vw_domain;")

        # Example materialized view
        cursor.execute(
            """
            CREATE OR REPLACE VIEW vw_domain AS

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
        print("Domain view created.")


def create_service_view(database):
    """Create or replace the unified 'service' view (starting with Shodan data)."""
    with connections[database].cursor() as cursor:
        print("Creating 'service' view from ShodanAssets...")

        cursor.execute(
            """
            CREATE OR REPLACE VIEW vw_service AS
            SELECT
                s.shodan_asset_uid AS id,
                s.timestamp AS "created_at",
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
        print("View 'vw_service' created.")
