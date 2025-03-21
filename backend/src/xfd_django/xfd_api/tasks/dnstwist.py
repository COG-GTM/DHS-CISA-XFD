"""Use DNS twist to fuzz domain names and cross check with a blacklist."""
# Standard Python Libraries
import contextlib
import datetime
import json
import logging
import pathlib
import traceback


# Third-Party Libraries
import dnstwist
import dshield
import psycopg2.extras as extras
import requests
from uuid import uuid4

from typing import Optional

import os
import sys
import django
from django.conf import settings

# Set the Django settings module
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path.append(PROJECT_ROOT)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")


settings.DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": "crossfeed",
        "USER": "crossfeed",
        "PASSWORD": "password",
        "HOST": "127.0.0.1",
        "PORT": "5432",
        "TEST": {
            "NAME": "crossfeed_test",  # Name of the test database
        },
    },
    "mini_data_lake": {
        "ENGINE": "django.db.backends.postgresql_psycopg2",  # Replace with your database engine
        "NAME": "crossfeed_mini_datalake",
        "USER": "crossfeed",
        "PASSWORD": "password",
        "HOST": "127.0.0.1",
        "PORT": "5432",
        "TEST": {
            "NAME": "mini_data_lake_test",  # Name of the test database
        },
    },
}


# Initialize Django
django.setup()


from xfd_mini_dl.models import Organization as Organization, DataSource, SubDomains

# from .data.pe_db.db_query_source import (
#     addSubdomain, => Hits PE API to add a subdomain
#     connect,
#     execute_dnstwist_data, => Hits PE API to add domain permutation
#     get_data_source_uid, => Gets Data Source ID for DNSTwist
#     get_orgs, => Returns all orgs
#     getSubdomain, => Returns sub_domain ID given the sub_domain
#     org_root_domains,
# )


date = datetime.datetime.now().strftime("%Y-%m-%d")
LOGGER = logging.getLogger(__name__)


# Update this function to use the new homebrew blocklist checking system
def checkBlocklist(dom, sub_domain_uid, source_uid, pe_org_uid, perm_list):
    """Cross reference the dnstwist results with DShield Blocklist."""
    malicious = False
    attacks = 0
    reports = 0
    if "original" in dom["fuzzer"]:
        return None, perm_list
    elif "dns_a" not in dom:
        return None, perm_list
    else:
        if str(dom["dns_a"][0]) == "!ServFail":
            return None, perm_list

        # Check IP in Blocklist API
        response = requests.get(
            "http://api.blocklist.de/api.php?ip=" + str(dom["dns_a"][0])
        ).content

        if str(response) != "b'attacks: 0<br />reports: 0<br />'":
            try:
                malicious = True
                attacks = int(str(response).split("attacks: ")[1].split("<")[0])
                reports = int(str(response).split("reports: ")[1].split("<")[0])
            except Exception:
                malicious = False
                dshield_attacks = 0
                dshield_count = 0

        # Check IP in DSheild API
        try:
            results = dshield.ip(str(dom["dns_a"][0]), return_format=dshield.JSON)
            results = json.loads(results)
            threats = results["ip"]["threatfeeds"]
            attacks = results["ip"]["attacks"]
            attacks = int(0 if attacks is None else attacks)
            malicious = True
            dshield_attacks = attacks
            dshield_count = len(threats)
        except Exception:
            dshield_attacks = 0
            dshield_count = 0

    # Check IPv6
    if "dns_aaaa" not in dom:
        dom["dns_aaaa"] = [""]
    elif str(dom["dns_aaaa"][0]) == "!ServFail":
        dom["dns_aaaa"] = [""]
    else:
        # Check IP in Blocklist API
        response = requests.get(
            "http://api.blocklist.de/api.php?ip=" + str(dom["dns_aaaa"][0])
        ).content
        if str(response) != "b'attacks: 0<br />reports: 0<br />'":
            try:
                malicious = True
                attacks = int(str(response).split("attacks: ")[1].split("<")[0])
                reports = int(str(response).split("reports: ")[1].split("<")[0])
            except Exception:
                malicious = False
                dshield_attacks = 0
                dshield_count = 0
        try:
            results = dshield.ip(str(dom["dns_aaaa"][0]), return_format=dshield.JSON)
            results = json.loads(results)
            threats = results["ip"]["threatfeeds"]
            attacks = results["ip"]["attacks"]
            attacks = int(0 if attacks is None else attacks)
            malicious = True
            dshield_attacks = attacks
            dshield_count = len(threats)
        except Exception:
            dshield_attacks = 0
            dshield_count = 0

    # Clean-up other fields
    if "ssdeep_score" not in dom:
        dom["ssdeep_score"] = ""
    if "dns_mx" not in dom:
        dom["dns_mx"] = [""]
    if "dns_ns" not in dom:
        dom["dns_ns"] = [""]

    # Ignore duplicates
    permutation = dom["domain"]
    if permutation in perm_list:
        return None, perm_list
    else:
        perm_list.append(permutation)

    domain_dict = {
        "organizations_uid": pe_org_uid,
        "data_source_uid": source_uid,
        "sub_domain_uid": sub_domain_uid,
        "domain_permutation": dom["domain"],
        "ipv4": dom["dns_a"][0],
        "ipv6": dom["dns_aaaa"][0],
        "mail_server": dom["dns_mx"][0],
        "name_server": dom["dns_ns"][0],
        "fuzzer": dom["fuzzer"],
        "date_active": date,
        "ssdeep_score": dom["ssdeep_score"],
        "malicious": malicious,
        "blocklist_attack_count": attacks,
        "blocklist_report_count": reports,
        "dshield_record_count": dshield_count,
        "dshield_attack_count": dshield_attacks,
    }
    return domain_dict, perm_list


def execute_dnstwist(root_domain, test=0):
    """Run dnstwist on each root domain."""
    pathtoDict = str(pathlib.Path(__file__).parent.resolve()) + "/data/common_tlds.dict"
    dnstwist_result = dnstwist.run(
        registered=True,
        tld=pathtoDict,
        format="json",
        threads=8,
        domain=root_domain,
    )
    if test == 1:
        return dnstwist_result
    finalorglist = dnstwist_result + []
    if root_domain.split(".")[-1] == "gov":
        for dom in dnstwist_result:
            if (
                ("tld-swap" not in dom["fuzzer"])
                and ("original" not in dom["fuzzer"])
                and ("replacement" not in dom["fuzzer"])
                and ("repetition" not in dom["fuzzer"])
                and ("omission" not in dom["fuzzer"])
                and ("insertion" not in dom["fuzzer"])
                and ("transposition" not in dom["fuzzer"])
            ):
                LOGGER.info("Running again on %s", dom["domain"])
                secondlist = dnstwist.run(
                    registered=True,
                    tld=pathtoDict,
                    format="json",
                    threads=8,
                    domain=dom["domain"],
                )
                finalorglist += secondlist
    return finalorglist


def get_data_source_uid(data_source_name: str) -> Optional[str]:
    try:
        data_source_record = DataSource.objects.get(name=data_source_name)
        return data_source_record.data_source_uid
    except DataSource.DoesNotExist:
        return None


def get_org_root_domains(org_id):
    sub_domains = SubDomains.objects.filter(organization_id=org_id, is_root_domain=True)
    return sub_domains


def get_sub_domain_uid(sub_domain: str) -> Optional[str]:
    try:
        sub_domain_record = SubDomains.objects.get(sub_domain=sub_domain)
        return sub_domain_record.sub_domain_uid
    except SubDomains.DoesNotExist:
        return None


def reverse_domain(domain: str) -> str:
    return ".".join(domain.split(".")[::-1])


def get_orgs() -> list:
    try:
        orgs = Organization.objects.all()
        return orgs
    except Exception as e:
        print(f"Error fetching organizations from data lake {str(e)}")


def add_sub_domain(sub_domain: str, org_uid: str, is_root_domain: bool) -> None:
    try:
        sub_domain_record = SubDomains(
            sub_domain_uid=str(uuid4()),
            is_root_domain=is_root_domain,
            first_seen=datetime.datetime.now(datetime.timezone.utc),
            last_seen=datetime.datetime.now(datetime.timezone.utc),
            created_at=datetime.datetime.now(datetime.timezone.utc),
            updated_at=datetime.datetime.now(datetime.timezone.utc),
            reverse_name=reverse_domain(sub_domain),
            cloud_hosted=False,
            censys_certificates_results=[],
            trustymail_resuts=[],
            sub_domain=sub_domain,
            organization_uid=org_uid,
        )
        sub_domain_record.save()
    except Exception as e:
        print(f"Error adding subdomain to data lake {str(e)}")


def run_dnstwist(orgs_list):
    """Run DNStwist on certain domains and upload findings to database."""
    source_uid = get_data_source_uid("DNSTwist")

    """ Get P&E Orgs """
    orgs = get_orgs()

    orgs_final = []
    if orgs_list == "all":
        for org in orgs:
            if org.pe_report_on:
                orgs_final.append(org)
            else:
                continue
    elif orgs_list == "DEMO":
        for org in orgs:
            if org.pe_demo:
                orgs_final.append(org)
            else:
                continue
    else:
        for org in orgs:
            if org.name in orgs_list:
                orgs_final.append(org)
            else:
                continue
    # return
    failures = []
    for org in orgs_final:
        org_id = org.id
        org_name = org.name
        pe_org_id = org.name

        # Only run on orgs in the org list
        if pe_org_id in orgs_list or orgs_list == "all" or orgs_list == "DEMO":
            LOGGER.info("Running DNSTwist on %s", org_name)
            print("Running DNSTwist on", org_name)
            """Collect DNSTwist data from Crossfeed"""
            try:
                # Get root domains
                root_dict = get_org_root_domains(org_id)
                domain_list = []
                perm_list = []
                for root in root_dict:
                    root_domain = root.root_domain
                    if root_domain == "Null_Root":
                        continue
                    LOGGER.info("\tRunning on root domain: %s", root.root_domain)
                    print("\tRunning on root domain:", root.root_domain)

                    with open(
                        "dnstwist_output.txt", "w"
                    ) as f, contextlib.redirect_stdout(f):
                        finalorglist = execute_dnstwist(root_domain)

                    # Get subdomain uid
                    sub_domain = root_domain
                    try:
                        print("Grabbing Sub Domain UID for", sub_domain)
                        sub_domain_uid = get_sub_domain_uid(sub_domain)
                    except Exception:
                        # TODO: Create custom exceptions.
                        # Issue 265: https://github.com/cisagov/pe-reports/issues/265
                        # Add and then get it
                        add_sub_domain(sub_domain, org_id, True)  # api ver.
                        # addSubdomain(PE_conn, sub_domain, pe_org_uid, True) # tsql ver.
                        sub_domain_uid = get_sub_domain_uid(sub_domain)

                    # Check Blocklist
                    for dom in finalorglist:
                        domain_dict, perm_list = checkBlocklist(
                            dom, sub_domain_uid, source_uid, org_id, perm_list
                        )
                        if domain_dict is not None:
                            domain_list.append(domain_dict)
            except Exception as error:
                # TODO: Create custom exceptions.
                # Issue 265: https://github.com/cisagov/pe-reports/issues/265
                LOGGER.info("Failed selecting DNSTwist data.")
                print(error)
                failures.append(org_name)
                LOGGER.info(traceback.format_exc())

            """Insert cleaned data into PE database."""
            try:
                for domain in domain_list:
                    execute_dnstwist_data(domain)
            except Exception:
                # TODO: Create custom exceptions.
                # Issue 265: https://github.com/cisagov/pe-reports/issues/265
                LOGGER.info("Failure inserting data into database.")
                failures.append(org_name)
                LOGGER.info(traceback.format_exc())
    if failures != []:
        LOGGER.error("These orgs failed:")
        LOGGER.error(failures)


if __name__ == "__main__":
    run_dnstwist("all")
