from datetime import datetime, timedelta
import logging
import os
import sys
import time
import json
import requests

# Setup logging
LOGGER = logging.getLogger(__name__)




pe_api_url = os.environ.get("PE_API_URL")
pe_api_key = os.environ.get("PE_API_KEY")

def api_was_finding_insert(finding_dict):
    """
    Insert a was finding record into the was_finding table.

    On conflict, update the old record with the new data

    Args:
        finding_dict: Dictionary of column names and values to be inserted

    Return:
        Status on if the record was inserted successfully
    """
    # Endpoint info
    endpoint_url = pe_api_url + "was_finding_insert_or_update"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(finding_dict, default=str)

    LOGGER.info(data)
    try:
        # Call endpoint
        was_finding_insert_result = requests.put(
            endpoint_url, headers=headers, data=data
        ).json()

        LOGGER.info(
            "Successfully inserted new record in was_findings table."
        )
        return was_finding_insert_result
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)
    except Exception as errg:
        LOGGER.error(errg)
