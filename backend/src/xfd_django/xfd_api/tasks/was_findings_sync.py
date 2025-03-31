import sys
import requests
import json
import os
from retry import retry
import base64
import logging
# from lxml import objectify
# import pandas as pd
# import time
# import base64
# import xml.etree.ElementTree as ET
# from collections import defaultdict
from datetime import datetime, timedelta, timezone
# from dateutil.relativedelta import relativedelta
# import re
# from io import BytesIO
# import qualys_redact
# from pdfrw import PdfReader, PdfWriter, PageMerge
# import pe_reports
from pe_reports.data.config import staging_config

# from data.pe_db.db_query_source  import api_was_report_insert, api_was_finding_insert
from ..helpers import api_was_finding_insert
API_DIC = staging_config(section="was")
username = API_DIC.get("username")
password = API_DIC.get("password")
credentials = f"{username}:{password}"
auth_string ="Basic " + base64.b64encode(credentials.encode('utf-8')).decode('utf-8')

LOGGER = logging.getLogger(__name__)

def handler(event):
    """Identify credential breaches associated with stakeholder's root domains."""
    try:
        is_dmz = os.getenv("IS_DMZ", "0") == "1"
        is_local = os.getenv("IS_LOCAL", "1") == "1"
        if not is_dmz and not is_local:
            LOGGER.warning("Scan can only be run in the DMZ or locally. Exiting now.")
            return {
                "statusCode": 200,
                "body": "WAS insert finding cannot run outside the DMZ.",
            }
        main()
        return {
            "statusCode": 200,
            "body": "WAS insert finding completed successfully.",
        }
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}

class InvalidQualysCall(Exception):
    """Raise When qualys returns an error."""
    pass
class InvalidApiCall(Exception):
    """Raise when the API call is invalid or no data is returned."""
    pass

def qualys_post_call(link,header,data,validate=True):
    """Make a call to Qualys API."""
    response = requests.request("POST",link, headers=header,data=json.dumps(data))
    if validate != True:
        return json.loads(response.json())
    if response.status_code != 200:
        LOGGER.error("Error Code: %s", response.status_code)
        LOGGER.error(f"Request Headers: {response.request.headers}")
        LOGGER.error(response.text)
        raise InvalidQualysCall
    responseJson = json.loads(response.text)
    if responseJson['ServiceResponse']['responseCode'] != 'SUCCESS':
        LOGGER.info(responseJson['ServiceResponse']['responseCode'])
        raise InvalidApiCall
    return responseJson

@retry((InvalidApiCall,InvalidQualysCall), tries=3, delay=2, backoff=2)
def qualys_call(link,header,data):
    """Make a call to Qualys API."""
    response = requests.post(link, headers=header,data=json.dumps(data))
    if response.status_code != 200:
        LOGGER.error("Error Code: %s", response.status_code)
        raise InvalidQualysCall
    responseJson = json.loads(response.text)
    if responseJson['ServiceResponse']['responseCode'] != 'SUCCESS':
        LOGGER.error(responseJson['ServiceResponse']['responseCode'])
        raise InvalidApiCall
    return responseJson

def get_recently_completed_scans(days_back=2):

    header = {
        'Content-Type' : "application/json",
        'accept' : "application/json",
        'Authorization': auth_string
        # 'user' : username,
        # 'password' : password
    }
    LOGGER.info(header)
    status_url = "https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/search/was/wasscanschedule"

    now = datetime.now(timezone.utc)

    # Calculate the date for two days ago
    two_days_ago = now - timedelta(days=days_back)

    # Set the time to the start of the day (00:00:00) and make sure it's in UTC
    start_of_day_two_days_ago = two_days_ago.replace(hour=0, minute=0, second=0, microsecond=0)

    # Format the date as a string in ISO 8601 format with Z for UTC
    date_string = start_of_day_two_days_ago.strftime('%Y-%m-%dT%H:%M:%SZ')

    payload = {
        "ServiceRequest": {
            "preferences": {
                "limitResults": 1000
            },
            "filters": {
                "Criteria": [
                    {
                        "field": "lastScan.status",
                        "operator": "EQUALS",
                        "value": "FINISHED"
                    },
                    {
                        "field": "lastScan.launchedDate",
                        "operator": "GREATER",
                        "value": date_string
                    }
                ]
            }
        }
    }
    id_scan_date_dict = {}
    LOGGER.info(payload)
    status_response = qualys_post_call(status_url, header, payload)
    has_more_records = True
    while has_more_records is True:
        for scan in status_response.get('ServiceResponse',{}).get('data',[]):
            id_scan_date_dict[scan.get('WasScanSchedule',{}).get('target',{}).get('tags',{}).get('included',{}).get('tagList',{}).get('list',[{}])[0].get('Tag',{}).get('name',None)] = scan.get('WasScanSchedule',{}).get('lastScan',{}).get('launchedDate',None)

        has_more_records = True if status_response.get('ServiceResponse',{}).get("hasMoreRecords",False) == "true" else False

        if has_more_records == True:
            payload['ServiceRequest']['filters']["Criteria"].append({
                "field": "id",
                "operator": "GREATER",
                "value": status_response.get('ServiceResponse',{}).get("lastId")
            })

            status_response = qualys_post_call(status_url, header, payload)

    return id_scan_date_dict

def convert_timestamp_to_date(timestamp: str) -> str:
    """Convert an ISO 8601 timestamp to a date string in YYYY-MM-DD format."""
    date_object = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
    formatted_date = date_object.strftime("%Y-%m-%d")
    return formatted_date

def getFindingsFromId(idStr,block=0):
    """Get all findings from a given ID."""
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=14)
    start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    if block == 0:
        offset = 1
    else:
        offset = block*1000
    """Get all findings from a given ID."""
    endPoint = "https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/search/was/finding"
    headers = {
        'Content-Type' : "application/json",
        'accept' : "application/json",
        'Authorization': auth_string
        # 'user' : username,
        # 'password' : password
    }
    data = {
        "ServiceRequest": {
            "preferences":
                {
                    "limitResults": 1000,
                    "startFromOffset": offset,
                    "verbose": "true"
                },
            "filters": {
                "Criteria":  [
                    {
                        "field" : "webApp.tags.name",
                        "operator" : "EQUALS",
                        "value" : idStr
                    },
                    # {
                    #     "field" : "type",
                    #     "operator" : "EQUALS",
                    #     "value" : "VULNERABILITY"
                    # },
                    {
                        "field": 'lastTestedDate',
                        "operator" : "GREATER",
                        "value" : start_date_str
                    }
                ]
            }
        }
    }
    we = qualys_call(endPoint,headers,data)
    try:
        findings = we['ServiceResponse']['data']
    except KeyError:
        LOGGER.info("No Findings Found for: " + idStr)
        return []
    findingsList = []
    findingCount = 0
    for x in findings:
        if x['Finding'].get('lastDetectedDate',None):
            last_detected = convert_timestamp_to_date(x['Finding'].get('lastDetectedDate',None))
        else:
            last_detected = None
        if x['Finding'].get('firstDetectedDate',None):
            first_detected = convert_timestamp_to_date(x['Finding'].get('firstDetectedDate',None))
        else:
            first_detected = None
        if x['Finding'].get('lastTestedDate', None):
            last_tested = convert_timestamp_to_date(x['Finding'].get('lastTestedDate', None))
        else:
            last_tested = None
        if x['Finding'].get('fixedDate', None):
            fixed_date = convert_timestamp_to_date(x['Finding'].get('fixedDate', None))
        else:
            fixed_date = None


        findingsList.append({
            'finding_uid':x['Finding'].get('uniqueId',None),
            'finding_type':x['Finding'].get('type', None),
            'webapp_id':int(x['Finding'].get('webApp',{}).get('id',0)),
            'webapp_url': x['Finding'].get('webApp',{}).get('url',None), #new
            'webapp_name': x['Finding'].get('webApp',{}).get('name',None), #new
            'was_org_id':idStr,
            'name':x['Finding']['name'],
            'owasp_category':x['Finding'].get('owasp',{}).get('list',[{}])[0].get('OWASP',{}).get('name','None'),
            'severity':x['Finding'].get('severity', None),
            'times_detected':x['Finding'].get('timesDetected',None),
            'cvss_v3_attack_vector':x['Finding'].get('cvssV3',{}).get('attackVector',None), # new
            'base_score':x['Finding'].get('cvssV3',{}).get('base',0),
            'temporal_score':x['Finding'].get('cvssV3',{}).get('temporal',0),
            'fstatus':x['Finding'].get('status',None),
            'last_detected':last_detected,
            'first_detected':first_detected,
            'potential': x['Finding'].get('potential',False),
            'cwe_list': x['Finding'].get('cwe', {}).get('list',[]), #new
            'wasc_list': list(map(lambda d: d.get('WASC',{}), x['Finding'].get('wasc',{}).get('list',[]))), #new
            'last_tested': last_tested,
            'fixed_date': fixed_date,
            'is_ignored': x['Finding'].get('isIgnored', None),
            'url': x['Finding'].get('url', None),
            'qid': x['Finding'].get('qid', None),
            'response': x['Finding'].get('resultList',{}).get('list',[{}])[0].get('Result',{}).get('payloads',{}).get('list',[{}])[0].get('PayloadInstance',{}).get('response',None)
        })

    for finding in findingsList:
        api_was_finding_insert(finding)
        findingCount += 1

    if we['ServiceResponse']['hasMoreRecords'] == 'true':
        findingCount += getFindingsFromId(idStr,block+1)
    return findingCount



def main():
    recently_scanned = get_recently_completed_scans(2)

    acronym_list = list(recently_scanned.keys())
    LOGGER.info(acronym_list)
    LOGGER.info(len(acronym_list))
    for acronym in acronym_list:

        LOGGER.info('Getting Data for ' + acronym)
        findingCount = getFindingsFromId(acronym)
        LOGGER.info('Saved ' + str(findingCount) + ' findings for ' + acronym)
        # if findingList != []:
        #     for finding in findingList:
        #         api_was_finding_insert(finding)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        LOGGER.info("\nUser has forced a close. Goodbye.")
        sys.exit()
