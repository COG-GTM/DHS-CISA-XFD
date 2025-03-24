#Standard Library Imports
import time
import json

# Third Party Imports
import requests

def query_all_cves(modified_date=None):
    """Query all CVEs added or changed since provided date."""
    start_time = time.time()
    total_num_pages = 1
    page_num = 1
    total_data = []
    # Retrieve data for each page
    while page_num <= total_num_pages:
        # Endpoint info
        create_task_url = "cves_by_modified_date"
        check_task_url = "cves_by_modified_date/task/"

        data = json.dumps(
            {"modified_datetime": modified_date, "page": page_num, "per_page": 500}
        )
        # Make API call
        result = task_api_call(create_task_url, check_task_url, data, 3)
        # Once task finishes, append result to total list
        print(result)
        total_data += result.get("data")
        total_num_pages = result.get("total_pages")
        LOGGER.info("Retrieved page: " + str(page_num) + " of " + str(total_num_pages))
        page_num += 1
    # Once all data has been retrieved, return overall tuple list
    # total_data = pd.DataFrame.from_dict(total_data)
    total_data = [tuple(dic.values()) for dic in total_data]
    LOGGER.info("Total time to retrieve cves: %s", (time.time() - start_time))
    # total_data["first_seen"] = pd.to_datetime(total_data["first_seen"]).dt.date
    # total_data["last_seen"] = pd.to_datetime(total_data["last_seen"]).dt.date
    return total_data

def api_cve_insert(cve_dict):
    """
    Insert a cve record for  into the cve table with linked products and venders.

    On conflict, update the old record with the new data

    Args:
        cve_dict: Dictionary of column names and values to be inserted

    Return:
        Status on if the record was inserted successfully
    """
    # Endpoint info
    endpoint_url = pe_api_url + "cve_insert_or_update"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(cve_dict, default=str)

    LOGGER.info(data)
    try:
        # Call endpoint
        cve_insert_result = requests.put(
            endpoint_url, headers=headers, data=data
        ).json()
        # print(cve_insert_result)
        LOGGER.info(
            "Successfully inserted new record in cves table with associated cpe products and venders"
        )
        return cve_insert_result
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

def get_cve_and_products(cve_name):
    """
    Query API to retrieve a CVE and its associated products data for the specified CVE.

    Args:
        cve_name: The CVE name or code

    Return:
        CVE data and a dictionary of venders and products
    """
    # Endpoint info
    endpoint_url = pe_api_url + "get_cve"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"cve_name": cve_name})
    try:
        # Call endpoint
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return

        return result
    except requests.exceptions.HTTPError as errh:
        LOGGER.info(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.info(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.info(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.info(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.info(err)