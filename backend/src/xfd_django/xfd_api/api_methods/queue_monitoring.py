"""API methods to support Queu Monitoring endpoints."""

# Standard Python Libraries
from typing import Optional
from datetime import datetime
import json

# Third-Party Libraries
from fastapi import Request, HTTPException
from fastapi.responses import Response
import httpx
import boto3
import os

from xfd_api.schema_models.queue_monitoring import QueueSearch
from ..auth import (
    get_org_memberships,
    is_global_view_admin,
    is_global_write_admin,
    is_org_admin,
    is_regional_admin,
    is_regional_admin_for_organization,
    matches_user_region,
)

is_local = os.getenv("IS_LOCAL")
base_queue_url = os.getenv("QUEUE_URL").rstrip("/")

# POST: /queues/search
def list_queues(search_data: Optional[QueueSearch], current_user):
    """Fetch queue metadata including message counts."""
    try:
        if not is_global_view_admin(current_user):
            raise HTTPException(status_code=403, detail="Unauthorized access.")

        # Set defaults if search_data is None
        if search_data is None:
            search_data = QueueSearch(pageSize=15, page=1, sort="name", order="ASC", filters={})

        page_size = search_data.pageSize or 15
        page = search_data.page or 1

        # Connect to SQS
        sqs = boto3.client(
            "sqs",
            region_name=os.getenv("AWS_REGION", "us-east-1"),
            endpoint_url=base_queue_url if is_local else None,
        )

        # Get list of queues
        response = sqs.list_queues()
        queue_urls = response.get("QueueUrls", [])

        if not queue_urls:
            return {"result": [], "count": 0}

        queue_data = []
        for queue_url in queue_urls:
            queue_name = queue_url.split("/")[-1]
            try:
                attributes = sqs.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=[
                        "ApproximateNumberOfMessages",
                        "ApproximateNumberOfMessagesNotVisible",
                        "ApproximateNumberOfMessagesDelayed",
                    ],
                ).get("Attributes", {})

                queue_info = {
                    "name": queue_name,
                    "messagesAvailable": int(attributes.get("ApproximateNumberOfMessages", 0)),
                    "messagesInFlight": int(attributes.get("ApproximateNumberOfMessagesNotVisible", 0)),
                    "messagesDelayed": int(attributes.get("ApproximateNumberOfMessagesDelayed", 0)),
                }
                queue_data.append(queue_info)
            except Exception as attr_err:
                print(f"Error fetching attributes for queue {queue_name}: {attr_err}")

        # Apply filters
        filters = search_data.filters or {}
        if "name" in filters:
            queue_data = [q for q in queue_data if filters["name"].lower() in q["name"].lower()]

        # Sort data
        queue_data.sort(key=lambda x: x.get(search_data.sort, ""), reverse=(search_data.order == "DESC"))

        # Paginate results
        paginated_data = queue_data[(page - 1) * page_size : page * page_size]

        return {"result": paginated_data, "count": len(queue_data)}

    except Exception as e:
        print(f"Error fetching queue metadata: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve queue metadata.")
