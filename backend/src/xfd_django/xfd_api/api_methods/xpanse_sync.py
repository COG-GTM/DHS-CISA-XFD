from fastapi import Request, HTTPException
import json
from ..utils.csv_utils import create_checksum

from xfd_mini_dl.models import XpanseBusinessUnits, XpanseAlerts, XpanseServicesMdl, XpanseCvesMdl


def create_xpanse_bu(bu_dict):
    bu, created = None, False
    alerts = bu_dict.get("alerts", [])
    try:     
        bu, created = XpanseBusinessUnits.objects.update_or_create(
                xpanse_business_unit_uid=bu_dict["xpanse_business_unit_uid"],
                defaults={
                    "entity_name": bu_dict["entity_name"],
                    "cyhy_db_name": bu_dict["cyhy_db_name"],
                    "state": bu_dict["state"],
                    "county": bu_dict["county"],
                    "city": bu_dict["city"],
                    "sector": bu_dict["sector"],
                    "entity_type": bu_dict["entity_type"],
                    "region": bu_dict["region"],
                    "rating": bu_dict["rating"],
                }
            )
        alerts_to_link = []
        for alert in alerts:
            create_xpanse_alert(alert, bu)
    except Exception as e:
        print("Error creating/updating business unit:", e)
    # TODO Need to create then link alerts
    return bu, created




def create_xpanse_service(service_dict):
    try:
        service, created = XpanseServicesMdl.objects.update_or_create(
            xpanse_service_uid=service_dict["xpanse_service_uid"],
            defaults={
                "service_id": service_dict["service_id"],
                "service_name": service_dict["service_name"],
                "service_type": service_dict["service_type"],
                "ip_address": service_dict["ip_address"],
                "domain": service_dict["domain"],
                "externally_detected_providers": service_dict["externally_detected_providers"],
                "is_active": service_dict["is_active"],
                "first_observed": service_dict["first_observed"],
                "last_observed": service_dict["last_observed"],
                "port": service_dict["port"],
                "protocol": service_dict["protocol"],
                "active_classifications": service_dict["active_classifications"],
                "inactive_classificiations": service_dict["inactive_classifications"],
                "discovery_type": service_dict["discoverytyped"],
                "externally_inferred_vulnerability_score": service_dict["externally_inferred_vulnerability_score"],
                "externally_inferred_cves": service_dict["externally_inferred_cves"],
                "service_key": service_dict["service_key"],
                "service_key_type": service_dict["service_key_type"],
            
            }
        )
        # TODO  Need to create then link Sub-Domains
        return service, created
    except Exception as e:
        

def create_xpanse_alert(alert_dict):
    # Create services
    # Create sub_domains
    # Create cves
    # Create alerts
    try:
        xpanse_alert, created = XpanseAlerts.objects.update_or_create(
        xpanse_alert_uid=alert_dict["xpanse_alert_uid"],
        defaults={
            "time_pulled_from_xpanse": alert_dict["time_pulled_from_xpanse"],
            "alert_id": alert_dict["alert_id"],
            "detection_timestamp": alert_dict["detection_timestamp"],
            "alert_name": alert_dict["alert_name"],
            "description": alert_dict["description"],
            "host_name": alert_dict["host_name"],
            "alert_action": alert_dict["alert_action"],
            "action_pretty": alert_dict["action_pretty"],
            "action_country": alert_dict["action_country"],
            "action_remote_port": alert_dict["action_remote_port"],
        }
        )
    except Exception as e:
    

async def xpanse_sync_post(sync_body, request: Request):
    """Ingest and persist Xpanse data to the data lake."""
    headers = request.headers
    request_checksum = headers.get("x-checksum", None)
    validation_checksum = create_checksum(sync_body.data)
    print("Request Checksum:", request_checksum)
    # Validate Data via X-Checksum header
    if request_checksum is None:
        raise HTTPException(status_code=500, detail="Checksum header not provided")
    if not sync_body.data:
        raise HTTPException(status_code=500, detail="No data provided in request body")
    if request_checksum != validation_checksum:
        raise HTTPException(
            status_code=500,
            detail="Checksum validation failed",
        )
    bus_created = []
    bus_updated = []
    
    # Data is Valid, process data
    # Creat BusinessUnits
    business_units = json.loads(sync_body.data)
    for business_unit in business_units:
        # All source fields mapped
        bu, created = create_xpanse_bu(business_unit)
        if created:
            bus_created.append(bu)
        else:
            bus_updated.append(bu)
        # Alerts
        
        
    
    return {"status_code": 200, "body": "Xpanse sync completed successfully."}
