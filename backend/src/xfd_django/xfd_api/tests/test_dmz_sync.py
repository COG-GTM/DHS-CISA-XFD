"""Test DMZ Sync API endpoints."""

# Standard Python Libraries
from datetime import datetime, timedelta
import hashlib
import json
import os
import secrets
import uuid

SALT = os.getenv("CHECKSUM_SALT", "default_salt")

# Third-Party Libraries
from django.db import transaction
from fastapi.testclient import TestClient
import pytest
from xfd_api.auth import create_jwt_token
from xfd_django.asgi import app
from xfd_mini_dl.models import (
    CredentialBreaches,
    CredentialExposures,
    DataSource,
    Organization,
    ShodanAssets,
    ShodanVulns,
    User,
    UserType,
)

client = TestClient(app)


@pytest.fixture
def admin_user():
    """Create user fixture."""
    admin_user = User.objects.create(
        first_name="Admin",
        last_name="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        user_type=UserType.GLOBAL_ADMIN,
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )
    yield admin_user
    admin_user.delete()


@pytest.fixture
def data_source():
    """Create data_source_fixture."""
    data_source = DataSource.objects.create(
        name="Test Source",
        description="Test Description",
        last_run=datetime.now(),
    )
    yield data_source
    data_source.delete()


@pytest.fixture
def organization():
    """Create org fixture."""
    organization = Organization.objects.create(
        name="Test_organization",
        acronym="DHS",
        root_domains=[],
        ip_blocks=[],
        is_passive=False,
    )
    transaction.commit()
    assert organization.name == "Test_organization"
    yield organization


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_shodan_sync_success():
    """Test shodan sync success."""
    user = User.objects.create(
        first_name="Test",
        last_name="Admin",
        email=f"{uuid.uuid4()}@example.com",
        user_type=UserType.GLOBAL_ADMIN,
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )

    organization = Organization.objects.create(
        name="SyncOrg",
        acronym="SYNC_ORG",
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )

    data_source = DataSource.objects.create(
        name="Shodan",
        description="Shodan data source",
        last_run=datetime.now().date(),
    )

    ShodanAssets.objects.create(
        organization=organization,
        organization_name="SyncOrg",
        ip_string="8.8.8.8",
        port=443,
        protocol="https",
        timestamp=datetime.now(),
        data_source=data_source,
    )

    ShodanVulns.objects.create(
        organization=organization,
        organization_name="SyncOrg",
        ip_string="8.8.8.8",
        port="443",
        protocol="https",
        timestamp=datetime.now(),
        data_source=data_source,
    )

    payload = {
        "acronym": "SYNC_ORG",
        "page": 1,
        "page_size": 10,
        "since_date": (datetime.now() - timedelta(days=1)).isoformat(),
    }

    response = client.post(
        "/dmz_sync/shodan_sync",
        headers={"Authorization": f"Bearer {create_jwt_token(user)}"},
        json=payload,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "shodan_assets" in body["payload"]["data"]
    assert "shodan_vulns" in body["payload"]["data"]
    assert "X-Salted-Checksum" in response.headers


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_shodan_sync_missing_date():
    """Test shodan sync missing date."""
    user = User.objects.create(
        first_name="Test",
        last_name="Admin",
        email=f"{uuid.uuid4()}@example.com",
        user_type=UserType.GLOBAL_ADMIN,
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )

    payload = {
        "acronym": "SYNC_ORG",
        "page": 1,
        "page_size": 10,
    }

    response = client.post(
        "/dmz_sync/shodan_sync",
        headers={"Authorization": f"Bearer {create_jwt_token(user)}"},
        json=payload,
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "since_date is required."


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_shodan_sync_unauthorized_user():
    """Test shodan sync unauthorized header."""
    user = User.objects.create(
        first_name="Test",
        last_name="Viewer",
        email=f"{uuid.uuid4()}@example.com",
        user_type=UserType.GLOBAL_VIEW,
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )

    payload = {
        "acronym": "SYNC_ORG",
        "page": 1,
        "page_size": 10,
        "since_date": (datetime.now() - timedelta(days=1)).isoformat(),
    }

    response = client.post(
        "/dmz_sync/shodan_sync",
        headers={"Authorization": f"Bearer {create_jwt_token(user)}"},
        json=payload,
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Unauthorized access."


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_shodan_sync_org_not_found():
    """Test shodan sync not found."""
    user = User.objects.create(
        first_name="Test",
        last_name="Admin",
        email=f"{uuid.uuid4()}@example.com",
        user_type=UserType.GLOBAL_ADMIN,
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )

    payload = {
        "acronym": "NON_EXISTENT_ORG",
        "page": 1,
        "page_size": 10,
        "since_date": (datetime.now() - timedelta(days=1)).isoformat(),
    }

    response = client.post(
        "/dmz_sync/shodan_sync",
        headers={"Authorization": f"Bearer {create_jwt_token(user)}"},
        json=payload,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Parent organization not found"


# ===== Cred Sync Endpoint Test =====


@pytest.mark.django_db(databases=["default", "mini_data_lake"], transaction=True)
def test_cred_sync_success(admin_user, organization):
    """Test successful credential synchronization."""
    cred_sync_payload = {
        "since_date": "2023-01-01T00:00:00",
        "page": 1,
        "page_size": 25,
        "acronym": "DHS",
    }

    response = client.post(
        "/dmz_sync/cred_sync",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin_user))},
        json=cred_sync_payload,
    )
    print(response.json())
    assert response.status_code == 200
    data = response.json()
    assert "total_pages" in data
    assert "credential_exposures" in data
    assert isinstance(data["credential_exposures"], list)


@pytest.mark.django_db(databases=["default", "mini_data_lake"], transaction=True)
def test_cred_sync_unauthorized(organization):
    """Test credential synchronization without authorization."""
    cred_sync_payload = {
        "since_date": "2023-01-01T00:00:00",
        "page": 1,
        "page_size": 25,
        "acronym": "DHS",
    }

    response = client.post("/dmz_sync/cred_sync", json=cred_sync_payload)
    print(response.json())
    assert response.status_code == 401
    assert response.json()["detail"] == "No valid authentication credentials provided"


@pytest.mark.django_db(databases=["default", "mini_data_lake"], transaction=True)
def test_cred_sync_invalid_date_format(admin_user):
    """Test credential synchronization with an invalid date format."""
    cred_sync_payload = {
        "since_date": "invalid-date",
        "page": 1,
        "page_size": 25,
        "acronym": "DHS",
    }

    response = client.post(
        "/dmz_sync/cred_sync",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin_user))},
        json=cred_sync_payload,
    )
    print(response.json())
    assert response.status_code == 422
    assert (
        "Input should be a valid datetime or date"
        in response.json()["detail"][0]["msg"]
    )


@pytest.mark.django_db(databases=["default", "mini_data_lake"], transaction=True)
def test_cred_sync_missing_acronym(admin_user):
    """Test credential synchronization with missing parameters."""
    cred_sync_payload = {
        "since_date": "2023-01-01T00:00:00",
    }  # Missing page and page_size

    response = client.post(
        "/dmz_sync/cred_sync",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin_user))},
        json=cred_sync_payload,
    )
    print(response.json())
    assert response.status_code == 422  # Expecting validation error


@pytest.mark.django_db(databases=["default", "mini_data_lake"], transaction=True)
def test_cred_sync_no_results(admin_user):
    """Test credential synchronization when no records match the filter."""
    cred_sync_payload = {
        "since_date": "2030-01-01T00:00:00",  # Future date, no data should match
        "page": 1,
        "page_size": 25,
        "acronym": "DHS",
    }

    response = client.post(
        "/dmz_sync/cred_sync",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin_user))},
        json=cred_sync_payload,
    )
    print(response.json())
    assert response.status_code == 200
    data = response.json()
    assert data["total_pages"] == 1
    assert len(data["credential_exposures"]) == 0


@pytest.mark.django_db(databases=["default", "mini_data_lake"], transaction=True)
def test_checksum_header(admin_user):
    """Ensure the X-Salted-Checksum is correctly computed."""
    payload = {
        "since_date": "2024-01-01T00:00:00",
        "page": 1,
        "page_size": 25,
        "acronym": "DHS",
    }

    response = client.post(
        "/dmz_sync/cred_sync",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin_user))},
        json=payload,
    )
    print(response.json())

    assert response.status_code == 200
    response_json = json.dumps(response.json(), sort_keys=True)
    expected_checksum = hashlib.sha256((SALT + response_json).encode()).hexdigest()
    assert response.headers["X-Salted-Checksum"] == expected_checksum


@pytest.fixture
def setup_test_data(organization):
    """Set up test data with a breach and two associated credential exposures."""
    breach = CredentialBreaches.objects.create(
        breach_name="Test Breach",
        breach_date=datetime(2024, 1, 1),
        added_date=datetime(2024, 2, 1),
        description="Test breach description.",
    )

    credential_1 = CredentialExposures.objects.create(
        email="user1@example.com",
        password="hashedpassword1",  # nosec
        credential_breach=breach,
        created_at=datetime(2024, 2, 1),
        modified_date=datetime(2024, 2, 10),
        breach_name="Test Breach",
        organization=organization,
        sub_domain_string="example.com",
        root_domain="example.com",
    )

    credential_2 = CredentialExposures.objects.create(
        email="user2@example.com",
        password="hashedpassword2",  # nosec
        credential_breach=breach,
        created_at=datetime(2024, 2, 1),
        modified_date=datetime(2024, 2, 10),
        breach_name="Test Breach",
        organization=organization,
        sub_domain_string="example.com",
        root_domain="example.com",
    )

    yield breach, credential_1, credential_2


@pytest.mark.django_db(databases=["default", "mini_data_lake"], transaction=True)
def test_cred_sync_pagination(admin_user, setup_test_data):
    """Ensure that requesting a page_size of 1 only returns one credential exposure."""
    payload = {
        "since_date": "2024-01-01T00:00:00",
        "page": 1,
        "page_size": 1,  # Should only return one record
        "acronym": "DHS",
    }

    response = client.post(
        "/dmz_sync/cred_sync",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin_user))},
        json=payload,
    )
    print(response.json())
    assert response.status_code == 200

    data = response.json()

    # Validate pagination
    assert data["current_page"] == 1
    assert data["total_pages"] >= 2  # Since we have 2 records and page_size=1

    # Validate that only one credential exposure is returned
    assert len(data["credential_exposures"]) == 1

    # Ensure X-Salted-Checksum is correct
    response_json = json.dumps(response.json(), sort_keys=True)
    expected_checksum = hashlib.sha256((SALT + response_json).encode()).hexdigest()
    assert response.headers["X-Salted-Checksum"] == expected_checksum
