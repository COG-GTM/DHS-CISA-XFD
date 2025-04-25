# tests/test_nist_sync.py

import json
import hashlib
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from xfd_django.asgi import app
from xfd_api.auth import create_jwt_token
from xfd_mini_dl.models import User, UserType, Cve as CveModel
from django.conf import settings

client = TestClient(app)

def compute_checksum(payload_obj):
    json_str = json.dumps(payload_obj, default=str, sort_keys=True)
    return hashlib.sha256((settings.CHECKSUM_SALT + json_str).encode()).hexdigest()


@pytest.mark.django_db(transaction=True)
def test_get_call_all_cves_empty_db():
    # 1) create an admin user for auth with UTC-aware now
    now = datetime.now(timezone.utc)
    user = User.objects.create(
        first_name="T",
        last_name="Admin",
        email=f"{uuid.uuid4()}@example.com",
        user_type=UserType.GLOBAL_ADMIN,
        created_at=now,
        updated_at=now,
    )
    token = create_jwt_token(user)

    # 2) call the endpoint
    response = client.post(
        "/cves",
        headers={"Authorization": f"Bearer {token}"},
    )

    # 3) assertions
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "ok"
    assert body["payload"] == []

    expected = {"status": "ok", "payload": []}
    assert response.headers["X-Salted-Checksum"] == compute_checksum(expected)


@pytest.mark.django_db(transaction=True)
def test_get_call_all_cves_with_data():
    # use UTC-aware now for seeding CVEs
    now = datetime.now(timezone.utc)
    cve1 = CveModel.objects.create(
        id=uuid.uuid4(),
        name="CVE-2025-0001",
        published_at=now,
        modified_at=now,
        status="PUBLISHED",
    )
    cve2 = CveModel.objects.create(
        id=uuid.uuid4(),
        name="CVE-2025-0002",
        published_at=now,
        modified_at=now,
        status="PUBLISHED",
    )

    # create user & token
    user_now = datetime.now(timezone.utc)
    user = User.objects.create(
        first_name="T",
        last_name="Admin",
        email=f"{uuid.uuid4()}@example.com",
        user_type=UserType.GLOBAL_ADMIN,
        created_at=user_now,
        updated_at=user_now,
    )
    token = create_jwt_token(user)

    # call endpoint
    response = client.post(
        "/cves",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201

    body = response.json()
    assert body["status"] == "ok"
    ids = {item["id"] for item in body["payload"]}
    assert ids == {str(cve1.id), str(cve2.id)}

    for item in body["payload"]:
        assert item["status"] == "PUBLISHED"

    expected = {"status": "ok", "payload": body["payload"]}
    assert response.headers["X-Salted-Checksum"] == compute_checksum(expected)


@pytest.mark.django_db(transaction=True)
def test_get_call_all_cves_unauthorized():
    # no Authorization header → 401 Unauthorized
    response = client.post("/cves")
    assert response.status_code == 401
    assert "detail" in response.json()
