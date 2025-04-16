"""Task for synchronizing vulnerability scanning data.

This module handles fetching, processing, and saving vulnerability scans,
port scans, hosts, and tickets from Redshift into the Django models.
"""

# Standard Python Libraries
# Uncomment the above to run the script standalone
import datetime
from ipaddress import IPv4Network, IPv6Network
import json
import logging
import os
import random

# Third-Party Libraries
from dateutil import parser  # type: ignore
import psycopg2
import requests
from xfd_api.helpers.regionStateMap import REGION_STATE_MAP
from xfd_api.utils.chunk import chunk_list_by_bytes
from xfd_api.utils.csv_utils import create_checksum
from xfd_api.utils.hash import hash_ip
from xfd_api.utils.scan_utils.vuln_scanning_sync_utils import (
    fetch_orgs_and_relations,
    load_test_data,
    save_cve_to_datalake,
    save_host,
    save_ip_to_datalake,
    save_organization_to_mdl,
    save_port_scan_to_datalake,
    save_ticket_to_datalake,
    save_vuln_scan,
    save_vuln_scan_to_xfd_db,
)
from xfd_mini_dl.models import Organization, Sector

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
    filename="vuln_scanning_sync.log",
)
LOGGER = logging.getLogger(__name__)


async def handler(event):
    """Handle execution of the vulnerability scanning sync task.

    This function serves as the entry point for triggering the synchronization
    process. It calls the `main` function and returns the appropriate response
    based on the execution outcome.

    Args:
        event (dict): The event data that triggers the function.

    Returns:
        dict: Response containing the status code and message.
    """
    try:
        main()
        return {"statusCode": 200, "body": "VS Sync completed successfully"}
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}


def query_redshift(query, params=None):
    """Execute a query on Redshift and return results as a list of dictionaries."""
    conn = psycopg2.connect(
        dbname=os.environ.get("REDSHIFT_DATABASE"),
        user=os.environ.get("REDSHIFT_USER"),
        password=os.environ.get("REDSHIFT_PASSWORD"),
        host=os.environ.get("REDSHIFT_HOST"),
        poert=5439,
    )

    try:
        cursor = conn.cursor(
            cursor_factory=psycopg2.extras.DictCursor
        )  # Use DictCursor for row dicts
        cursor.execute(query, params or ())
        results = cursor.fetchall()
        return [dict(row) for row in results]  # Convert to list of dicts
    finally:
        cursor.close()
        conn.close()


def main():
    """Execute the vulnerability scanning synchronization task."""
    LOGGER.info("Started VulnScanningSync scan...")
    # Load request data

    request_list = fetch_from_redshift("SELECT * FROM vmtableau.requests;")
    LOGGER.info("Fetched %d requests from Redshift", len(request_list))
    org_id_dict = process_orgs(request_list)
    # Process Organizations & Relations
    process_organizations_and_relations()

    # Process Vulnerability Scans
    LOGGER.info("Started processing vulnerability scans...")
    vuln_scans = fetch_from_redshift(
        "SELECT * FROM vmtableau.vuln_scans WHERE time >= GETDATE() - INTERVAL '2 days';"
    )
    LOGGER.info("Fetched %d vulnerability scans from Redshift", len(vuln_scans))
    if vuln_scans:
        process_vulnerability_scans(vuln_scans, org_id_dict)
        LOGGER.info("Finished processing vulnerability scans")

    # Process Host Scans
    LOGGER.info("Started processing host scans...")
    host_scans = fetch_from_redshift(
        "SELECT * FROM vmtableau.hosts WHERE last_change >= GETDATE() - INTERVAL '2 days';"
    )
    LOGGER.info("Fetched %d host scans from Redshift", len(host_scans))
    if host_scans:
        process_host_scans(host_scans, org_id_dict)
        LOGGER.info("Finished processing host scans")

    # Process Port Scans
    LOGGER.info("Started processing port scans...")
    port_scans = fetch_from_redshift(
        "SELECT * FROM vmtableau.port_scans WHERE time >= GETDATE() - INTERVAL '2 days';"
    )
    LOGGER.info("Fetched %d port scans from Redshift", len(port_scans))
    if port_scans:
        process_port_scans(port_scans, org_id_dict)
        LOGGER.info("Finished processing port scans")

    # Process Tickets
    LOGGER.info("Started processing tickets...")
    tickets = fetch_from_redshift(
        "SELECT * FROM vmtableau.tickets WHERE last_change >= GETDATE() - INTERVAL '2 days';"
    )
    LOGGER.info("Fetched %d tickets from Redshift", len(tickets))
    if tickets:
        process_tickets(tickets, org_id_dict)
        LOGGER.info("Finished processing tickets")


def detect_data_set(query):
    """Detect the data set from the query."""
    if "requests" in query:
        return "requests"
    if "vuln_scans" in query:
        return "vuln_scan"
    if "hosts" in query:
        return "hosts"
    if "tickets" in query:
        return "tickets"
    if "port_scans" in query:
        return "port_scans"
    return None


def fetch_from_redshift(query):
    """Fetch data from Redshift and log execution time."""
    IS_LOCAL = True
    if IS_LOCAL:
        data_set = detect_data_set(query)
        return load_test_data(data_set)
    try:
        start_time = datetime.datetime.now()
        result = query_redshift(query)
        end_time = datetime.datetime.now()
        duration_seconds = (end_time - start_time).total_seconds()
        LOGGER.info(f"[Redshift] [{duration_seconds}s] [{len(result)} records] {query}")
        return result.rows
    except Exception as e:
        LOGGER.info("Error fetching data from Redshift: %s", e)
        LOGGER.info("Erroneous query: %s", query)
        return []


def save_json_to_file(data, filename="test.json"):
    """Save JSON data to a file."""
    try:
        with open(filename, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)
        print(f"Data successfully saved to {filename}")
    except Exception as e:
        print(f"Error saving JSON to file: {e}")


def process_organizations_and_relations():
    """Fetch organizations and sync with the external API."""
    try:
        shaped_orgs = fetch_orgs_and_relations()
        if not shaped_orgs:
            return

        chunks = chunk_list_by_bytes(shaped_orgs, 2097152)
        for idx, chunk_info in enumerate(chunks):
            chunk = chunk_info["chunk"]
            bounds = chunk_info["bounds"]
            # save_json_to_file(json.dumps(chunk), f"org_chunk_{idx}.json")
            LOGGER.info(
                "Sending chunk %d - %d to sync API", bounds[0].start, bounds[0].end
            )
            send_csv_to_sync(json.dumps(chunk), bounds)

    except Exception as e:
        LOGGER.error("Error sending organizations to DMZ sync endpoint, %s", e)


def send_csv_to_sync(csv_data, bounds):
    """Send CSV data to /sync API."""
    body = {"data": csv_data}
    try:
        checksum = create_checksum(csv_data)
    except Exception as e:
        LOGGER.error("Error creating checksum: %s", e)
        return

    headers = {
        "x-checksum": checksum,
        "x-cursor": f"{bounds['start']}-{bounds['end']}",
        "Content-Type": "application/json",
        "Authorization": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImU0N2Q0MDk3LWM5ZTEtNGMxZS1iMmY0LWY2Mjg4OTU3NTlkMCIsImVtYWlsIjoiSkFOU09OLkJVTkNFQGFzc29jaWF0ZXMuY2lzYS5kaHMuZ292IiwiZXhwIjoxNzQxMzc1NTQwfQ.Yo4A0fBP8cF00ODKgxD5U2NaffXv1k3nmaN4jv5kyVs",
    }

    response = requests.post(
        "http://localhost:3000/sync", json=body, headers=headers, timeout=60
    )
    if response.status_code == 200:
        LOGGER.info("Successfully sent chunk to sync API")


def process_vulnerability_scans(vuln_scans, org_id_dict):
    """Process and save vulnerability scans."""
    for vuln in vuln_scans:
        try:
            owner_id = org_id_dict.get(vuln.get("owner"))
            ip_id = (
                save_ip_to_datalake(
                    {
                        "ip": vuln["ip"],
                        "ip_hash": hash_ip(vuln["ip"]),
                        "organization": {"id": owner_id},
                    }
                )
                if vuln.get("ip")
                else None
            )
            cve = (
                save_cve_to_datalake({"name": vuln["cve"]}) if vuln.get("cve") else None
            )
            vuln_scan_dict = build_vuln_scan_dict(vuln, owner_id, ip_id, cve)
            try:
                save_vuln_scan(vuln_scan_dict)
            except Exception as e:
                LOGGER.error("Error saving vulnerability scan: %s", e)
        except Exception as e:
            LOGGER.error("Error processing Vulnerability Scan: %s", e)
    for vuln in vuln_scans:
        try:
            save_vuln_scan_to_xfd_db(vuln)
        except Exception as e:
            print("Error saving to XFD DB", e)


def safe_fromisoformat(date_str: str | None) -> datetime.datetime | None:
    """Convert a date string to a datetime object."""
    if date_str is None:
        return None
    return parser.isoparse(date_str)


def build_vuln_scan_dict(vuln, owner_id, ip_id, cve):
    """Construct a vulnerability scan dictionary."""
    return {
        "id": vuln.get("_id"),
        "cert_id": vuln.get("cert", None),
        "cpe": vuln.get("cpe", None),
        "cve_string": vuln.get("cve", None),
        "cve": cve,
        "cvss_base_score": vuln.get("cvss_base_score", None),
        "cvss_temporal_score": vuln.get("cvss_temporal_score", None),
        "cvss_temporal_vector": vuln.get("cvss_temporal_vector", None),
        "cvss_vector": vuln.get("cvss_vector", None),
        "description": vuln.get("description", None)[:255],
        "exploit_available": vuln.get("exploit_available", None),
        "exploitability_ease": vuln.get("exploit_ease", None),
        "ip_string": vuln.get("ip", None),
        "ip": ip_id if ip_id else None,
        "latest": vuln.get("latest", None),
        "owner": vuln.get("owner", None),
        "osvdb_id": vuln.get("osvdb", None),
        "organization": Organization.objects.get(id=owner_id),
        "patch_publication_timestamp": safe_fromisoformat(
            vuln.get("patch_publication_date", None)
        ),
        "cisa_known_exploited": safe_fromisoformat(
            vuln.get("cisa-known-exploited", None)
        ),
        "port": vuln.get("port", None),
        "port_protocol": vuln.get("protocol", None),
        "risk_factor": vuln.get("risk_factor", None),
        "script_version": vuln.get("script_version", None),
        "see_also": vuln.get("see_also", None),
        "service": vuln.get("service", None),
        "severity": vuln.get("severity"),
        "solution": vuln.get("solution", None),
        "source": vuln.get("source", None),
        "synopsis": vuln.get("synopsis", None),
        "vuln_detection_timestamp": safe_fromisoformat(vuln.get("time")),
        "vuln_publication_timestamp": safe_fromisoformat(
            vuln.get("vuln_publication_timestamp")
        ),
        "xref": vuln.get("xref", None),
        "cwe": vuln.get("cwe", None),
        "bid": vuln.get("bid", None),
        "exploited_by_malware": bool(vuln.get("exploited_by_malware", None)),
        "thorough_tests": bool(vuln.get("thorough_tests", None)),
        "cvss_score_rationale": vuln.get("cvss_score_rationale", None),
        "cvss_score_source": vuln.get("cvss_score_source", None),
        "cvss3_base_score": vuln.get("cvss3_base_score", None),
        "cvss3_vector": vuln.get("cvss3_vector", None),
        "cvss3_temporal_vector": vuln.get("cvss3_temporal_vector", None),
        "cvss3_temporal_score": vuln.get("cvss3_temporal_score", None),
        "asset_inventory": bool(vuln.get("asset_inventory", None)),
        "plugin_id": vuln.get("plugin_id", None),
        "plugin_modification_date": safe_fromisoformat(
            vuln.get("plugin_modification_date", None)
        ),
        "plugin_publication_date": safe_fromisoformat(
            vuln.get("plugin_publication_date", None)
        ),
        "plugin_name": vuln.get("plugin_name", None),
        "plugin_type": vuln.get("plugin_type", None),
        "plugin_family": vuln.get("plugin_family", None),
        "f_name": vuln.get("fname", None),
        "cisco_bug_id": vuln.get("cisco-bug-id", None),
        "cisco_sa": vuln.get("cisco-sa", None),
        "plugin_output": vuln.get("plugin_output", None),
        "other_findings": {},
    }


def process_host_scans(host_scans, org_id_dict):
    """Process and save host scans."""
    for host in host_scans:
        try:
            lon, lat = json.loads(host.get("loc", "[]"))
            owner_id = org_id_dict.get(host.get("owner"))
            ip = (
                save_ip_to_datalake(
                    {
                        "ip": host["ip"],
                        "ip_hash": hash_ip(host["ip"]),
                        "organization": {"id": owner_id},
                    }
                )
                if host.get("ip")
                else None
            )

            host_dict = {
                "id": host.get("_id"),
                "ip_string": host.get("ip"),
                "ip": ip,
                "updated_timestamp": host.get("last_change"),
                "location_longitude": lon,
                "location_latitude": lat,
                "priority": host.get("priority"),
                "next_scan_timestamp": parser.parse(host.get("next_scan")),
                "rand": host.get("r", random.random()),
                "curr_stage": host.get("stage"),
                "status": host.get("status"),
                "organization": Organization.objects.get(id=owner_id),
            }
            save_host(host_dict)
        except Exception as e:
            print(f"Error processing host scan: {e}")


def process_tickets(tickets, org_id_dict):
    """Process and save ticket data."""
    # To-Do
    # Add fields to the Django model: is_kev, first_discovered, risky_service_group
    # Fields that don't exist in the data? OS
    for ticket in tickets:
        try:
            details = json.loads(ticket.get("details", "{}"))
            owner_id = org_id_dict.get(ticket["owner"])
            ip = (
                save_ip_to_datalake(
                    {
                        "ip": ticket["ip"],
                        "ip_hash": hash_ip(ticket["ip"]),
                        "organization": {"id": owner_id},
                    }
                )
                if ticket.get("ip")
                else None
            )
            cve = (
                save_cve_to_datalake({"name": details.get("cve")})
                if details.get("cve")
                else None
            )
            lon, lat = json.loads(ticket.get("loc", "[]"))
            time_closed_str = ticket.get("time_closed")
            time_opened_str = ticket.get("time_opened")
            is_risky = "Potentially Risky Service Detected:" in details.get("name", "")
            ticket_dict = {
                "id": ticket["_id"].replace("ObjectId('", "").replace("')", ""),
                "cve_string": details.get("cve"),
                "cve": cve,
                "cvss_base_score": details.get("cvss_base_score"),
                "cvss_version": details.get("cvss_version"),
                "vuln_name": details.get("name"),
                "cvss_score_source": details.get("score_source"),
                "cvss_severity": details.get("severity"),
                "vpr_score": details.get("vpr_score"),
                "false_positive": ticket.get("false_positive"),
                "ip_string": ticket.get("ip"),
                "ip": ip,
                "updated_timestamp": parser.parse(ticket.get("last_change")),
                "location_longitude": lon,
                "location_latitude": lat,
                "organization": Organization.objects.get(id=owner_id),
                "vuln_port": ticket.get("port"),
                "port_protocol": ticket.get("protocol"),
                "snapshots_bool": bool(ticket.get("snapshots", None)),
                "vuln_source": ticket.get("source"),
                "vuln_source_id": ticket.get("source_id"),
                "closed_timestamp": parser.parse(time_closed_str)
                if time_closed_str
                else None,
                "opened_timestamp": parser.parse(time_opened_str)
                if time_opened_str
                else None,
                "is_kev": details.get("kev"),
                "is_risky": is_risky,
                "service_name": details.get("service"),
            }
            events = json.loads(ticket.get("events", "[]"))
            save_ticket_to_datalake(ticket_dict, events, details)
            print("Saved ticket to MDL")
        except Exception as e:
            print(
                f"Error processing ticket data: {e} - {owner_id} - {ticket.get('owner')}"
            )


def process_port_scans(port_scans, org_id_dict):
    """Process and save port scan data."""
    for port_scan in port_scans:
        try:
            owner_id = org_id_dict.get(port_scan.get("owner"))
            if not owner_id:
                print(
                    f"{port_scan.get('Owner')} is not a recognized organization, skipping host"
                )
                continue

            ip = (
                save_ip_to_datalake(
                    {
                        "ip": port_scan.get("ip"),
                        "ip_hash": hash_ip(port_scan.get("ip")),
                        "organization": {"id": owner_id},
                    }
                )
                if port_scan.get("ip")
                else None
            )
            service_obj = json.loads(port_scan.get("service", "{}"))
            port_scan_dict = {
                "id": port_scan["_id"].replace("ObjectId('", "").replace("')", ""),
                "ip_string": port_scan.get("ip"),
                "ip": ip,
                "latest": port_scan.get("latest"),
                "port": port_scan.get("port"),
                "protocol": port_scan.get("protocol"),
                "reason": port_scan.get("reason"),
                "service": port_scan.get("service"),
                "service_name": service_obj.get("name", None),
                "service_confidence": service_obj.get("conf", None),
                "service_method": service_obj.get("method", None),
                "source": port_scan.get("source"),
                "state": port_scan.get("state"),
                "time_scanned": parser.parse(port_scan.get("time")),
                "organization": Organization.objects.get(id=owner_id),
            }
            save_port_scan_to_datalake(port_scan_dict)
            print("Saved port scan record")
        except Exception as e:
            print(f"Error processing port scan data: {e}")


def process_orgs(request_list):
    """Process organization data, save to MDL and return org ID dict for linking."""
    LOGGER.info("Processing organizations...")
    org_id_dict = {}
    sector_child_dict = {}
    parent_child_dict = {}

    # Process the request data
    if request_list and isinstance(request_list, list):
        process_request(request_list, sector_child_dict, parent_child_dict, org_id_dict)

        # Link parent-child organizations
        link_parent_child_organizations(parent_child_dict, org_id_dict)

        # Assign organizations to sectors
        assign_organizations_to_sectors(sector_child_dict, org_id_dict)

    return org_id_dict


def link_parent_child_organizations(
    parent_child_dict, org_id_dict, db_name="mini_data_lake_secondary"
):
    """Link child organizations to their respective parent organizations."""
    for parent_acronym, child_acronyms in parent_child_dict.items():
        parent_id = org_id_dict.get(parent_acronym)
        if not parent_id:
            continue

        try:
            parent_org = Organization.objects.using(db_name).get(id=parent_id)
        except Organization.DoesNotExist:
            continue

        # Collect child organization IDs
        children_ids = [
            org_id_dict.get(acronym)
            for acronym in child_acronyms
            if acronym in org_id_dict
        ]

        # Update parent field for child organizations
        if children_ids:
            Organization.objects.using(db_name).filter(id__in=children_ids).update(
                parent=parent_org.id
            )


def assign_organizations_to_sectors(
    sector_child_dict, org_id_dict, db_name="mini_data_lake_secondary"
):
    """Assign organizations to sectors based on sector-child relationships."""
    for sector_id, child_acronyms in sector_child_dict.items():
        try:
            sector = Sector.objects.using(db_name).get(id=sector_id)
        except Sector.DoesNotExist:
            continue

        organization_ids = [
            org_id_dict.get(acronym)
            for acronym in child_acronyms
            if acronym in org_id_dict
        ]

        if organization_ids:
            sector.organizations.add(
                *Organization.objects.using(db_name).filter(id__in=organization_ids)
            )


def process_request(request_list, sector_child_dict, parent_child_dict, org_id_dict):
    """Process requests and build dictionaries for linking later."""
    non_sector_list = {
        "CRITICAL_INFRASTRUCTURE",
        "FEDERAL",
        "ROOT",
        "SLTT",
        "CATEGORIES",
        "INTERNATIONAL",
        "THIRD_PARTY",
    }

    for request in request_list:
        request = parse_request_data(request)

        # Skip non-sector records
        if "type" not in request["agency"]:
            if request["_id"] in non_sector_list:
                continue

            process_sector(request, sector_child_dict)
            continue

        # Process parent-child relationships
        if request.get("children"):
            parent_child_dict[request["_id"]] = request["children"]

        # Process networks
        network_list = process_networks(request.get("networks", []))

        # Process location
        location_dict = process_location(request.get("agency", {}).get("location"))

        # Process organization
        process_organization(request, network_list, location_dict, org_id_dict)


def parse_request_data(request):
    """Parse JSON fields in the request."""
    json_fields = ["agency", "networks", "report_types", "scan_types", "children"]
    for field in json_fields:
        if field in request:
            request[field] = json.loads(request[field]) if request[field] else []
    return request


def process_sector(request, sector_child_dict):
    """Process sector data and update sector_child_dict."""
    if request.get("children"):
        sector_data = {
            "name": request["agency"]["name"],
            "acronym": request["_id"],
            "retired": bool(request["retired"]),
        }
        try:
            sector_obj, created = Sector.objects.update_or_create(
                acronym=sector_data["acronym"],
                defaults={
                    "name": sector_data["name"],
                    "retired": sector_data["retired"],
                },
            )
            sector_child_dict[sector_obj.id] = request["children"]
        except Exception as e:
            print("Error occurred creating sector", e)


def process_networks(networks):
    """Process network CIDR entries and return a list of network objects."""
    network_list = []
    for cidr in networks:
        try:
            address = IPv6Network(cidr) if ":" in cidr else IPv4Network(cidr)
            network_list.append(
                {"network": cidr, "start_ip": address[0], "end_ip": address[-1]}
            )
        except Exception as e:
            print("Invalid CIDR Format", e)
    return network_list


def process_location(org_location):
    """Create a dictionary representation of an organization's location."""
    if not org_location:
        return None

    return {
        "name": org_location.get("name"),
        "country_abrv": org_location.get("country", ""),
        "country": org_location.get("country_name"),
        "county": org_location.get("county"),
        "county_fips": org_location.get("county_fips"),
        "gnis_id": org_location.get("gnis_id"),
        "state_abrv": org_location.get("state"),
        "stateFips": org_location.get("state_fips"),
        "state": org_location.get("state_name"),
    }


def process_organization(request, network_list, location_dict, org_id_dict):
    """Save organization data and update org_id_dict."""
    org_data = {
        "name": request.get("agency", {}).get("name"),
        "acronym": request.get("_id"),
        "retired": bool(request.get("retired", False)),
        "type": request.get("agency", {}).get("type"),
        "state": request.get("agency", {}).get("location", {}).get("state"),
        "state_name": request.get("agency", {}).get("location", {}).get("state_name"),
        "county": request.get("agency", {}).get("location", {}).get("county"),
        "county_fips": request.get("agency", {}).get("location", {}).get("county_fips"),
        "state_fips": request.get("agency", {}).get("location", {}).get("state_fips"),
        "country": request.get("agency", {}).get("location", {}).get("country"),
        "country_name": request.get("agency", {})
        .get("location", {})
        .get("country_name"),
        "region_id": REGION_STATE_MAP.get(
            request.get("agency", {}).get("location", {}).get("state_name"), None
        ),
        "stakeholder": bool(request.get("stakeholder", False)),
        "enrolled_in_vs_timestamp": request.get("enrolled") or datetime.datetime.now(),
        "period_start_vs_timestamp": request.get("period_start"),
        "report_types": json.dumps(request.get("report_types", [])),
        "scan_types": json.dumps(request.get("scan_types", [])),
        "is_passive": False,
    }
    try:
        org_record = save_organization_to_mdl(org_data, network_list, location_dict)
        org_id_dict[request["_id"]] = org_record.id
    except Exception as e:
        LOGGER.info("Error saving organization: %s - %s", e, request["_id"])


if __name__ == "__main__":
    main()
