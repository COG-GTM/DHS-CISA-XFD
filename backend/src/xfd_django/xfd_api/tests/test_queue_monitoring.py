import os
import json
import uuid
from datetime import datetime

import boto3
import pytest
from fastapi.testclient import TestClient

from xfd_api.auth import create_jwt_token
from xfd_api.models import User, UserType
from xfd_django.asgi import app

client = TestClient(app)

# Fake SQS client for a successful search scenario.
class FakeSQSClient:
    def list_queues(self):
        # Simulate one queue URL returned
        return {"QueueUrls": ["http://fake-sqs/queue/testQueue"]}

    def get_queue_attributes(self, QueueUrl, AttributeNames):
        # Return fixed fake attributes for testing
        return {
            "Attributes": {
                "ApproximateNumberOfMessages": "5",
                "ApproximateNumberOfMessagesNotVisible": "2",
                "ApproximateNumberOfMessagesDelayed": "1",
            }
        }


# Fake SQS client returning no queue URLs.
class FakeSQSClientNoResults:
    def list_queues(self):
        return {"QueueUrls": []}

    def get_queue_attributes(self, QueueUrl, AttributeNames):
        return {"Attributes": {}}


@pytest.mark.django_db(transaction=True)
def test_search_queues_success(monkeypatch):
    """
    Test that searching queues returns correct data when SQS provides one queue.
    """
    # Create a GlobalView user
    user = User.objects.create(
        firstName="Admin",
        lastName="User",
        email=f"{uuid.uuid4().hex}@example.com",
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Override boto3.client to return our FakeSQSClient
    monkeypatch.setattr(boto3, "client", lambda service, **kwargs: FakeSQSClient())

    # Patch module-level variables in the endpoint code so that SQS is used in local mode
    monkeypatch.setattr("xfd_api.api_methods.queue_monitoring.is_local", True)
    monkeypatch.setattr("xfd_api.api_methods.queue_monitoring.base_queue_url", "http://fake-sqs")

    search_payload = {
        "pageSize": 15,
        "page": 1,
        "sort": "name",
        "order": "ASC",
        "filters": {},
    }

    response = client.post(
        "/queues/search",
        headers={"Authorization": f"Bearer {create_jwt_token(user)}"},
        json=search_payload,
    )

    print(response.json())  # Debug output if needed
    assert response.status_code == 200
    data = response.json()
    # We expect one queue to be returned
    assert data["count"] == 1
    result = data["result"][0]
    # The queue name is extracted as the last part of the URL ("testQueue")
    assert result["name"] == "testQueue"
    assert result["messagesAvailable"] == 5
    assert result["messagesInFlight"] == 2
    assert result["messagesDelayed"] == 1


@pytest.mark.django_db(transaction=True)
def test_search_queues_no_results(monkeypatch):
    """
    Test that searching queues returns an empty result when no queues are found.
    """
    user = User.objects.create(
        firstName="Admin",
        lastName="User",
        email=f"{uuid.uuid4().hex}@example.com",
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    monkeypatch.setattr(boto3, "client", lambda service, **kwargs: FakeSQSClientNoResults())
    monkeypatch.setattr("xfd_api.api_methods.queue_monitoring.is_local", True)
    monkeypatch.setattr("xfd_api.api_methods.queue_monitoring.base_queue_url", "http://fake-sqs")

    search_payload = {
        "pageSize": 15,
        "page": 1,
        "sort": "name",
        "order": "ASC",
        "filters": {},
    }

    response = client.post(
        "/queues/search",
        headers={"Authorization": f"Bearer {create_jwt_token(user)}"},
        json=search_payload,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 0
    assert data["result"] == []


@pytest.mark.django_db(transaction=True)
def test_search_queues_unauthorized():
    """
    Test that the endpoint returns 401 when no valid authentication is provided.
    """
    search_payload = {
        "pageSize": 15,
        "page": 1,
        "sort": "name",
        "order": "ASC",
        "filters": {},
    }

    response = client.post("/queues/search", json=search_payload)
    assert response.status_code == 401
    detail = response.json()["detail"]
    assert "No valid authentication credentials provided" in detail
