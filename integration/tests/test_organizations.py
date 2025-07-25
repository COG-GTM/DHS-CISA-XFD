"""Regression Tests for Organizations Endpoint."""


# test_organizations_api.py

# Standard Python Libraries
from datetime import datetime
import os
import re
import time
import uuid

# Third-Party Libraries
import pytest
import requests

# ——— Configuration ———
BASE_URL = os.environ.get("BACKEND_DOMAIN")
X_API_KEY = os.environ.get("X_API_KEY")
HEADERS = {"X-API-KEY": X_API_KEY}
BAD_HEADERS = {"X-API-KEY": "invalid-key"}
TIMEOUT = 10
BAD_ID = "00000000-0000-0000-0000-000000000000"
INVALID_ORG_ID = "notauuid"
test_payload = {
    "state_name": "Florida",
    "county": "SomeCounty",
    "county_fips": 12345,
    "type": "STATE",
}


@pytest.fixture(scope="session")
def all_organizations():
    """Fetch the full list of organizations once per test session."""
    url = f"{BASE_URL}/organizations"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    assert resp.status_code == 200, f"/organizations returned {resp.status_code}"
    data = resp.json()
    assert isinstance(data, list) and data, "Expected a non-empty list of organizations"
    return data


@pytest.fixture(scope="session")
def sample_org(all_organizations):
    """Pick one organization from the list for downstream tests."""
    return all_organizations[0]


@pytest.fixture(scope="session")
def org_id(sample_org):
    """Retrieve organization id from sample org."""
    return sample_org["id"]


@pytest.fixture(scope="session")
def region_id(sample_org):
    """Retrieve region id from sample org."""
    return sample_org.get("region_id")


@pytest.fixture(scope="session")
def state(sample_org):
    """Retrieve state from sample org."""
    return sample_org.get("state")


@pytest.fixture(scope="session")
def name(sample_org):
    """Retrieve name from sample org."""
    return sample_org["name"]


def assert_auth_failure(resp, context=""):
    """Assert that a response indicates an authentication failure (401 or 403)."""
    assert resp.status_code in (
        401,
        403,
    ), f"{context}Expected 401 or 403, got {resp.status_code}"
    detail = resp.json().get("detail", "")
    assert isinstance(
        detail, str
    ), f"{context}Expected 'detail' as string, got {type(detail)}"


# ========================================
#   GET organizations
# ========================================
@pytest.mark.integration
def test_list_organizations_success():
    """GET /organizations returns 200 and a non-empty list of orgs."""
    url = f"{BASE_URL}/organizations"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"
    data = resp.json()
    assert isinstance(data, list), "Response should be a list"
    assert len(data) > 0, "Expected at least one organization in the list"

    for org in data:
        assert "id" in org, "Each organization must have an 'id'"
        assert "name" in org, "Each organization must have a 'name'"


@pytest.mark.integration
def test_list_organizations_unauthenticated():
    """Unauthenticated request (no API key) should be rejected."""
    url = f"{BASE_URL}/organizations"
    resp = requests.get(url, timeout=TIMEOUT)
    assert_auth_failure(resp, context="[unauthenticated] ")


@pytest.mark.integration
def test_list_organizations_invalid_api_key():
    """Invalid API key should also be rejected."""
    url = f"{BASE_URL}/organizations"
    resp = requests.get(url, headers=BAD_HEADERS, timeout=TIMEOUT)
    assert_auth_failure(resp, context="[invalid key] ")


@pytest.mark.integration
def test_get_organization_with_payload():
    """Get with payload should still return (200)."""
    url = f"{BASE_URL}/organizations"
    resp = requests.get(url, json=test_payload, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code in (
        200,
    ), f"Expected 200 for get with random payload, got {resp.status_code}"


# ========================================
#   GET organizations/tags
# ========================================


@pytest.mark.integration
def test_get_organization_tags_success():
    """GET /organizations/tags returns 200 and a JSON list of tags."""
    url = f"{BASE_URL}/organizations/tags"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"
    assert "application/json" in resp.headers.get(
        "Content-Type", ""
    ), f"Expected JSON response, got {resp.headers.get('Content-Type')}"
    data = resp.json()
    assert isinstance(data, list), f"Expected list, got {type(data).__name__}"

    for tag in data:
        assert isinstance(tag, dict), "Each item should be a dict"
        assert "id" in tag, "Each tag must have an 'id'"
        assert "name" in tag, "Each tag must have a 'name'"


@pytest.mark.integration
def test_get_organization_tags_unauthenticated():
    """No API key → 401 or 403."""
    url = f"{BASE_URL}/organizations/tags"
    resp = requests.get(url, timeout=TIMEOUT)
    assert_auth_failure(resp, context="[unauthenticated] ")


@pytest.mark.integration
def test_get_organization_tags_invalid_api_key():
    """Invalid API key → 401 or 403."""
    url = f"{BASE_URL}/organizations/tags"
    resp = requests.get(url, headers=BAD_HEADERS, timeout=TIMEOUT)
    assert_auth_failure(resp, context="[invalid key] ")


@pytest.mark.integration
def test_get_organization_tags_method_not_allowed():
    """POST to a GET‐only endpoint should return 405 Method Not Allowed."""
    url = f"{BASE_URL}/organizations/tags"
    resp = requests.post(url, headers=HEADERS, timeout=TIMEOUT)

    assert (
        resp.status_code == 405
    ), f"Expected 405 for wrong HTTP method, got {resp.status_code}"


@pytest.mark.integration
def test_get_organization_tags_with_payload():
    """Get with payload should still return (200)."""
    url = f"{BASE_URL}/organizations/tags"
    resp = requests.get(url, json=test_payload, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code in (
        200,
    ), f"Expected 200 for get with random payload, got {resp.status_code}"


# ========================================
#   GET organizations org_id
# ========================================


@pytest.mark.integration
def test_get_organization_success(org_id):
    """Happy path: GET /organizations/{org_id} returns 200 and correct payload."""
    url = f"{BASE_URL}/organizations/{org_id}"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"
    data = resp.json()
    assert data["id"] == org_id
    assert "name" in data


@pytest.mark.integration
def test_get_organization_not_found(org_id):
    """404 when organization does not exist."""
    url = f"{BASE_URL}/organizations/{BAD_ID}"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"
    detail = resp.json().get("detail", "")
    assert "not found" in detail.lower()


@pytest.mark.integration
def test_get_organization_invalid_api_key():
    """Invalid API key → 401 or 403."""
    url = f"{BASE_URL}/organizations/{org_id}"
    resp = requests.get(url, headers=BAD_HEADERS, timeout=TIMEOUT)
    assert_auth_failure(resp, context="[invalid key] ")


@pytest.mark.integration
def test_get_organization_unauthenticated(org_id):
    """Missing API key should yield 401 or 403."""
    url = f"{BASE_URL}/organizations/{org_id}"
    resp = requests.get(url, timeout=TIMEOUT)
    assert_auth_failure(resp, context="[unauthenticated get org] ")


@pytest.mark.integration
def test_get_organization_invalid_id_format():
    """Invalid ID format today returns 500 with a validation detail."""
    url = f"{BASE_URL}/organizations/{INVALID_ORG_ID}"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    # current behavior
    assert (
        resp.status_code == 500
    ), f"Expected 500 for invalid UUID (current behavior), got {resp.status_code}"
    body = resp.json()
    assert "detail" in body, "Expected a detail key in the error response"
    assert (
        "not a valid UUID" in body["detail"]
    ), f"Unexpected detail message: {body['detail']}"


@pytest.mark.integration
def test_get_organization_method_not_allowed(org_id):
    """POST to this GET-only endpoint should return 405."""
    url = f"{BASE_URL}/organizations/{org_id}"
    resp = requests.post(url, headers=HEADERS, timeout=TIMEOUT)

    assert (
        resp.status_code == 405
    ), f"Expected 405 Method Not Allowed, got {resp.status_code}"


@pytest.mark.integration
def test_get_organization_org_id_with_payload(org_id):
    """GET with payload should still return (200)."""
    url = f"{BASE_URL}/organizations/{org_id}"
    resp = requests.get(url, json=test_payload, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"


# ========================================
#   GET organizations states
# ========================================
BAD_STATE = "ZZZ_NOT_A_REAL_STATE"


@pytest.mark.integration
def test_get_organizations_by_state_success(state):
    """Happy path: returns 200 and a list of orgs whose 'state' matches the query."""
    url = f"{BASE_URL}/organizations/state/{state}"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"
    data = resp.json()
    assert isinstance(data, list), f"Expected list, got {type(data).__name__}"
    assert len(data) > 0, "Expected at least one organization for a real state"

    for org in data:
        assert "state" in org, "Each org must include a 'state' field"
        assert org["state"] == state, f"Expected state={state}, got {org['state']}"


@pytest.mark.integration
def test_get_organizations_by_state_empty():
    """Querying a non-existent state should return 404 with a 'No organizations found…' detail."""
    url = f"{BASE_URL}/organizations/state/{BAD_STATE}"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    # current behavior is 404
    assert resp.status_code == 404, f"Expected 404 Not Found, got {resp.status_code}"

    body = resp.json()
    assert "detail" in body, "Expected a 'detail' key in the response body"
    assert body["detail"] == "No organizations found for the given state"


@pytest.mark.integration
def test_get_organizations_by_state_unauthenticated(state):
    """No API key → 401 or 403."""
    url = f"{BASE_URL}/organizations/state/{state}"
    resp = requests.get(url, timeout=TIMEOUT)
    assert_auth_failure(resp, context="[unauthenticated] ")


@pytest.mark.integration
def test_get_organizations_by_state_invalid_api_key(state):
    """Bad API key → 401 or 403."""
    url = f"{BASE_URL}/organizations/state/{state}"
    resp = requests.get(url, headers=BAD_HEADERS, timeout=TIMEOUT)
    assert_auth_failure(resp, context="[invalid key] ")


@pytest.mark.integration
def test_get_organizations_by_state_method_not_allowed(state):
    """POST (wrong HTTP method) → 405 Method Not Allowed."""
    url = f"{BASE_URL}/organizations/state/{state}"
    resp = requests.post(url, headers=HEADERS, timeout=TIMEOUT)

    assert (
        resp.status_code == 405
    ), f"Expected 405 for wrong method, got {resp.status_code}"


@pytest.mark.integration
def test_get_organizations_by_state_numbers():
    """Querying with numbers should return 404 with a 'No organizations found…' detail."""
    url = f"{BASE_URL}/organizations/state/{12345}"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    # current behavior is 404
    assert resp.status_code == 404, f"Expected 404 Not Found, got {resp.status_code}"

    body = resp.json()
    assert "detail" in body, "Expected a 'detail' key in the response body"
    assert body["detail"] == "No organizations found for the given state"


@pytest.mark.integration
def test_get_organization_state_with_payload(state):
    """GET with payload should still return (200)."""
    url = f"{BASE_URL}/organizations/state/{state}"
    resp = requests.get(url, json=test_payload, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"


# ========================================
#   GET organizations region_id
# ========================================


@pytest.mark.integration
def test_get_organizations_by_region_success(region_id):
    """Returns 200 and a non-empty list where each org has the matching region_id."""
    url = f"{BASE_URL}/organizations/region_id/{region_id}"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"
    orgs = resp.json()
    assert isinstance(orgs, list), f"Expected list, got {type(orgs).__name__}"
    assert len(orgs) > 0, "Expected at least one organization for a valid region"

    for org in orgs:
        assert "region_id" in org, "Each organization must include 'region_id'"
        assert (
            org["region_id"] == region_id
        ), f"Expected region_id={region_id}, got {org['region_id']}"


@pytest.mark.integration
def test_get_organizations_by_region_not_found():
    """Non-existent region_id should return 404 with a 'No organizations found...' detail."""
    url = f"{BASE_URL}/organizations/region_id/{BAD_ID}"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 404, f"Expected 404 Not Found, got {resp.status_code}"
    body = resp.json()
    assert "detail" in body, "Expected 'detail' key in error response"
    assert (
        "No organizations found" in body["detail"]
    ), f"Unexpected detail message: {body['detail']}"


@pytest.mark.integration
def test_get_organizations_by_region_unauthenticated(region_id):
    """Missing API key should yield 401 or 403."""
    url = f"{BASE_URL}/organizations/region_id/{region_id}"
    resp = requests.get(url, timeout=TIMEOUT)
    assert_auth_failure(resp, context="[unauthenticated] ")


@pytest.mark.integration
def test_get_organizations_by_region_invalid_api_key(region_id):
    """Invalid API key should be rejected (401 or 403)."""
    url = f"{BASE_URL}/organizations/region_id/{region_id}"
    resp = requests.get(url, headers=BAD_HEADERS, timeout=TIMEOUT)
    assert_auth_failure(resp, context="[invalid key] ")


@pytest.mark.integration
def test_get_organizations_by_region_method_not_allowed(region_id):
    """POST to this GET-only endpoint should return 405."""
    url = f"{BASE_URL}/organizations/region_id/{region_id}"
    resp = requests.post(url, headers=HEADERS, timeout=TIMEOUT)

    assert (
        resp.status_code == 405
    ), f"Expected 405 Method Not Allowed, got {resp.status_code}"


@pytest.mark.integration
def test_get_organizations_by_region_id_numbers():
    """Querying with invalid length should return 404 with a 'No organizations found…' detail."""
    url = f"{BASE_URL}/organizations/region_id/{12345}"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    # current behavior is 404
    assert resp.status_code == 404, f"Expected 404 Not Found, got {resp.status_code}"

    body = resp.json()
    assert "detail" in body, "Expected a 'detail' key in the response body"
    assert body["detail"] == "No organizations found for the given region"


@pytest.mark.integration
def test_get_organizations_by_region_id_invalid_arguement():
    """Querying with invalid arguement should return 404 with a 'No organizations found…' detail."""
    url = f"{BASE_URL}/organizations/region_id/{'cisa'}"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    # current behavior is 404
    assert resp.status_code == 404, f"Expected 404 Not Found, got {resp.status_code}"

    body = resp.json()
    assert "detail" in body, "Expected a 'detail' key in the response body"
    assert body["detail"] == "No organizations found for the given region"


@pytest.mark.integration
def test_get_organization_region_id_with_payload(region_id):
    """GET with payload should still return (200)."""
    url = f"{BASE_URL}/organizations/region_id/{region_id}"
    resp = requests.get(url, json=test_payload, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"


# ========================================
#   POST organizations
# ========================================


def is_iso_zulu(ts: str) -> bool:
    """Rudimentary check for ISO-8601 UTC timestamp ending with 'Z'."""
    return bool(re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$", ts))


@pytest.fixture
def org_payload_and_data(region_id, state):
    """Fixture that creates a test organization and after the test, it deletes the org."""
    # prepare payload
    unique_acronym = f"TST{uuid.uuid4().hex[:6].upper()}"
    unique_name = f"Test Org {uuid.uuid4().hex[:6]}"
    payload = {
        "acronym": unique_acronym,
        "name": unique_name,
        "root_domains": ["ortega.com", "patterson.com"],
        "ip_blocks": ["163.10.148.0/28", "82.140.78.0/26"],
        "is_passive": False,
        "pending_domains": ["martin.com"],
        "country": "IN",
        "state": state,
        "region_id": region_id,
        "state_fips": 71,
        "state_name": "New York",
        "county": "Hunterville",
        "county_fips": 7239,
        "type": "STATE",
    }

    # create
    resp = requests.post(
        f"{BASE_URL}/organizations",
        json=payload,
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    assert resp.status_code == 200, f"Setup POST failed: {resp.status_code}"
    data = resp.json()

    yield payload, data

    # teardown: delete the created org
    org_id = data["id"]
    del_resp = requests.delete(
        f"{BASE_URL}/organizations/{org_id}",
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    # allow 200 (deleted) or 404 (already gone)
    assert del_resp.status_code in (
        200,
        404,
    ), f"Teardown DELETE failed: {del_resp.status_code}"


@pytest.mark.integration
def test_create_organization_full_payload_success(org_payload_and_data):
    """Happy path with full payload: response echoes back every field."""
    payload, data = org_payload_and_data

    # — Auto‐generated fields
    assert data["id"], "Response must include a non-empty 'id'"
    assert is_iso_zulu(data["created_at"])
    assert is_iso_zulu(data["updated_at"])

    # — Echoed fields
    for field in (
        "acronym",
        "name",
        "root_domains",
        "ip_blocks",
        "is_passive",
        "pending_domains",
        "country",
        "state",
        "state_fips",
        "state_name",
        "county",
        "county_fips",
        "type",
    ):
        assert data[field] == payload[field], f"Field {field!r} mismatch"

    # — Defaults
    assert data.get("tags", []) == []
    assert data.get("user_roles", []) == []


# ——— Negative / validation tests ———


@pytest.mark.integration
def test_create_organization_missing_required_fields(region_id, state):
    """Omitting 'acronym' or 'name' should trigger 422 Unprocessable Entity."""
    # omit acronym and name
    payload = {
        "region_id": region_id,
        "state": state,
    }
    url = f"{BASE_URL}/organizations"
    resp = requests.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT)
    assert (
        resp.status_code == 422
    ), f"Expected 422 for missing fields, got {resp.status_code}"
    errors = resp.json().get("detail")
    assert errors, "Expected validation errors in 'detail'"


@pytest.mark.integration
def test_create_organization_invalid_list_types(region_id, state):
    """Supplying wrong types for root_domains or ip_blocks should 422."""
    base = {
        "acronym": "BADTST",
        "name": "Bad Type Test",
        "region_id": region_id,
        "state": state,
    }

    # root_domains as string
    p1 = {**base, "root_domains": "not-a-list", "ip_blocks": ["1.2.3.0/28"]}
    resp1 = requests.post(
        f"{BASE_URL}/organizations", json=p1, headers=HEADERS, timeout=TIMEOUT
    )
    assert (
        resp1.status_code == 422
    ), f"Expected 422 for bad root_domains, got {resp1.status_code}"

    # ip_blocks as integer
    p2 = {**base, "root_domains": ["ok.com"], "ip_blocks": 12345}
    resp2 = requests.post(
        f"{BASE_URL}/organizations", json=p2, headers=HEADERS, timeout=TIMEOUT
    )
    assert (
        resp2.status_code == 422
    ), f"Expected 422 for bad ip_blocks, got {resp2.status_code}"


@pytest.mark.integration
def test_create_organization_unauthenticated(region_id, state):
    """No API key → 401 or 403."""
    payload = {
        "acronym": "NOAUTH",
        "name": "No Auth Org",
        "region_id": region_id,
        "state": state,
    }
    resp = requests.post(f"{BASE_URL}/organizations", json=payload, timeout=TIMEOUT)
    assert resp.status_code in (401, 403), f"Expected 401/403, got {resp.status_code}"


@pytest.mark.integration
def test_create_organization_invalid_api_key(region_id, state):
    """Invalid API key → 401 or 403."""
    payload = {
        "acronym": "BADKEY",
        "name": "Bad Key Org",
        "region_id": region_id,
        "state": state,
    }
    resp = requests.post(
        f"{BASE_URL}/organizations", json=payload, headers=BAD_HEADERS, timeout=TIMEOUT
    )
    assert resp.status_code in (401, 403), f"Expected 401/403, got {resp.status_code}"


# ========================================
#   POST upsert
# ========================================


@pytest.fixture
def org_to_cleanup():
    """Yield a dict that tests can write {'org_id': ...} into.

    After the test, if org_id is set, it will DELETE that org.
    """
    info = {}
    yield info
    org_id = info.get("org_id")
    if org_id:
        resp = requests.delete(
            f"{BASE_URL}/organizations/{org_id}",
            headers=HEADERS,
            timeout=TIMEOUT,
        )
        assert resp.status_code in (
            200,
            404,
        ), f"Cleanup DELETE failed: {resp.status_code}"


def parse_zulu(ts: str) -> datetime:
    """Parse an ISO 8601 Zulu timestamp string into a datetime object."""
    return datetime.fromisoformat(ts.rstrip("Z"))


@pytest.mark.integration
def test_upsert_new_organization(region_id, state, org_to_cleanup):
    """Upsert a new organization with full payload: should create and return 200."""
    unique_acr = f"UPS{uuid.uuid4().hex[:6].upper()}"
    unique_name = f"Upsert Org {uuid.uuid4().hex[:6]}"
    payload = {
        "acronym": unique_acr,
        "name": unique_name,
        "root_domains": ["example.com", "test.com"],
        "ip_blocks": ["10.0.0.0/28"],
        "is_passive": False,
        "pending_domains": [],
        "country": "US",
        "state": state,
        "region_id": str(region_id),
        "state_fips": 12,
        "state_name": "Florida",
        "county": "SomeCounty",
        "county_fips": 12345,
        "type": "STATE",
    }
    url = f"{BASE_URL}/organizations_upsert"
    resp = requests.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT)
    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"
    data = resp.json()

    # register for teardown
    org_to_cleanup["org_id"] = data["id"]

    assert data["acronym"] == unique_acr
    assert data["name"] == unique_name
    assert data["region_id"] == str(region_id)
    assert data["state"] == state

    created = parse_zulu(data["created_at"])
    updated = parse_zulu(data["updated_at"])
    assert updated >= created, "updated_at should not be before created_at"


@pytest.mark.integration
def test_upsert_existing_organization_updates(region_id, state, org_to_cleanup):
    """Upsert same org twice: second call should bump updated_at."""
    acr = f"UPS{uuid.uuid4().hex[:6].upper()}"
    # first payload
    p1 = {
        "acronym": acr,
        "name": "FirstName",
        "root_domains": ["a.com"],
        "ip_blocks": ["10.0.1.0/28"],
        "is_passive": False,
        "pending_domains": [],
        "country": "US",
        "state": state,
        "region_id": str(region_id),
        "state_fips": 12,
        "state_name": "Florida",
        "county": "SomeCounty",
        "county_fips": 12345,
        "type": "STATE",
    }
    url = f"{BASE_URL}/organizations_upsert"
    r1 = requests.post(url, json=p1, headers=HEADERS, timeout=TIMEOUT)
    assert r1.status_code == 200
    d1 = r1.json()

    # register for teardown (we'll delete the final version)
    org_to_cleanup["org_id"] = d1["id"]

    created_1 = parse_zulu(d1["created_at"])
    updated_1 = parse_zulu(d1["updated_at"])

    time.sleep(0.5)

    # second payload (change name and domains)
    p2 = p1.copy()
    p2.update(
        {
            "name": "SecondName",
            "root_domains": ["b.com", "c.org"],
        }
    )
    r2 = requests.post(url, json=p2, headers=HEADERS, timeout=TIMEOUT)
    assert r2.status_code == 200
    d2 = r2.json()

    # same id, updated name, and timestamp bumped
    assert d2["id"] == d1["id"]
    assert d2["name"] == "SecondName"
    assert parse_zulu(d2["created_at"]) == created_1
    assert parse_zulu(d2["updated_at"]) > updated_1


@pytest.mark.integration
def test_upsert_missing_required_fields(region_id, state):
    """Missing 'acronym' or 'name' → 422 validation error."""
    url = f"{BASE_URL}/organizations_upsert"
    payload = {"region_id": region_id, "state": state}
    r = requests.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT)
    assert r.status_code == 422, f"Expected 422, got {r.status_code}"
    assert "detail" in r.json()


@pytest.mark.integration
def test_upsert_unauthenticated(region_id, state):
    """No API key → 401 or 403."""
    url = f"{BASE_URL}/organizations_upsert"
    payload = {
        "acronym": "NOAUTH",
        "name": "No Auth Org",
        "region_id": region_id,
        "state": state,
    }
    r = requests.post(url, json=payload, timeout=TIMEOUT)
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


@pytest.mark.integration
def test_upsert_invalid_api_key(region_id, state):
    """Invalid API key → 401 or 403."""
    url = f"{BASE_URL}/organizations_upsert"
    payload = {
        "acronym": "BADKEY",
        "name": "Bad Key Org",
        "region_id": region_id,
        "state": state,
    }
    r = requests.post(url, json=payload, headers=BAD_HEADERS, timeout=TIMEOUT)
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


@pytest.mark.integration
def test_upsert_method_not_allowed(region_id, state):
    """GET on a POST-only endpoint → 405 Method Not Allowed."""
    url = f"{BASE_URL}/organizations_upsert"
    r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    assert r.status_code == 405, f"Expected 405, got {r.status_code}"


@pytest.mark.integration
def test_upsert_invalid_format_and_value(region_id, state):
    """Invalid types and values → 422 validation error."""
    url = f"{BASE_URL}/organizations_upsert"
    payload = {
        "acronym": 123,
        "name": ["Not", "a", "string"],
        "root_domains": "not-a-list",
        "ip_blocks": ["999.999.999.0/24"],
        "state": None,
        "type": "ALIEN",
    }

    r = requests.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT)
    assert r.status_code == 422, f"Expected 422, got {r.status_code}"
    errors = r.json().get("detail", [])
    assert (
        isinstance(errors, list) and len(errors) > 0
    ), "Expected validation error list"


# ========================================
#   PUT organizations/org_id
# ========================================


@pytest.mark.integration
def test_update_organization_success(region_id, state, org_to_cleanup):
    """Create a new org, then update via PUT, teardown fixture will DELETE the org afterward."""
    # 1) Create
    acr = f"UPD{uuid.uuid4().hex[:6].upper()}"
    name0 = f"Before {uuid.uuid4().hex[:4]}"
    create_payload = {
        "acronym": acr,
        "name": name0,
        "root_domains": ["foo.com"],
        "ip_blocks": ["10.0.0.0/28"],
        "is_passive": False,
        "pending_domains": [],
        "country": "US",
        "state": state,
        "region_id": str(region_id),
        "state_fips": 12,
        "state_name": "Florida",
        "county": "SomeCounty",
        "county_fips": 12345,
        "type": "STATE",
    }
    r1 = requests.post(
        f"{BASE_URL}/organizations",
        json=create_payload,
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    assert r1.status_code == 200, f"Create returned {r1.status_code}"
    d1 = r1.json()
    org_id = d1["id"]

    # register for teardown
    org_to_cleanup["org_id"] = org_id

    created_1 = parse_zulu(d1["created_at"])
    updated_1 = parse_zulu(d1["updated_at"])

    # 2) Wait then update
    time.sleep(0.5)
    name1 = f"After {uuid.uuid4().hex[:4]}"
    update_payload = create_payload.copy()
    update_payload["name"] = name1

    r2 = requests.put(
        f"{BASE_URL}/organizations/{org_id}",
        json=update_payload,
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    assert r2.status_code == 200, f"Expected 200 on update, got {r2.status_code}"
    d2 = r2.json()

    # verify fields
    assert d2["id"] == org_id
    assert d2["name"] == name1
    assert d2["acronym"] == acr
    assert str(d2["region_id"]) == str(region_id)

    created_2 = parse_zulu(d2["created_at"])
    updated_2 = parse_zulu(d2["updated_at"])
    assert created_2 == created_1, "created_at should remain unchanged"
    assert updated_2 >= updated_1, "updated_at should be bumped on update"


@pytest.mark.integration
def test_update_organization_not_found(region_id, state):
    """PUT to a non-existent ID should return 404."""
    acr = f"UPD{uuid.uuid4().hex[:6].upper()}"
    name0 = f"Before {uuid.uuid4().hex[:4]}"
    payload = {
        "acronym": acr,
        "name": name0,
        "root_domains": ["foo.com"],
        "ip_blocks": ["10.0.0.0/28"],
        "is_passive": False,
        "pending_domains": [],
        "country": "US",
        "state": state,
        "region_id": str(region_id),
        "state_fips": 12,
        "state_name": "Florida",
        "county": "SomeCounty",
        "county_fips": 12345,
        "type": "STATE",
    }
    resp = requests.put(
        f"{BASE_URL}/organizations/{BAD_ID}",
        json=payload,
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"
    body = resp.json()
    assert "detail" in body and "not found" in body["detail"].lower()


@pytest.mark.integration
def test_update_organization_unauthenticated(region_id, state):
    """Missing API key → 401 or 403."""
    payload = {"acronym": "A", "name": "B", "region_id": str(region_id), "state": state}
    resp = requests.put(
        f"{BASE_URL}/organizations/{BAD_ID}", json=payload, timeout=TIMEOUT
    )
    assert resp.status_code in (401, 403), f"Expected 401/403, got {resp.status_code}"


@pytest.mark.integration
def test_update_organization_invalid_api_key(region_id, state):
    """Invalid API key → 401 or 403."""
    payload = {"acronym": "A", "name": "B", "region_id": str(region_id), "state": state}
    resp = requests.put(
        f"{BASE_URL}/organizations/{BAD_ID}",
        json=payload,
        headers=BAD_HEADERS,
        timeout=TIMEOUT,
    )
    assert resp.status_code in (401, 403), f"Expected 401/403, got {resp.status_code}"


@pytest.mark.integration
def test_update_organization_invalid_format(region_id, state, org_to_cleanup):
    """PUT with invalid field types or missing fields should return 422 Unprocessable Entity."""
    valid_payload = {
        "acronym": f"INV{uuid.uuid4().hex[:6].upper()}",
        "name": "Valid Org",
        "root_domains": ["valid.com"],
        "ip_blocks": ["10.10.0.0/24"],
        "is_passive": False,
        "pending_domains": [],
        "country": "US",
        "state": state,
        "region_id": str(region_id),
        "state_fips": 10,
        "state_name": "TestState",
        "county": "TestCounty",
        "county_fips": 10101,
        "type": "STATE",
    }

    create_resp = requests.post(
        f"{BASE_URL}/organizations",
        json=valid_payload,
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    assert create_resp.status_code == 200, f"Setup failed: {create_resp.status_code}"
    org_id = create_resp.json()["id"]
    org_to_cleanup["org_id"] = org_id

    # Step 2: Attempt to update with bad types and missing required fields
    invalid_payload = {
        "acronym": 12345,  # should be a string
        "name": ["Not", "A", "String"],  # should be a string
        "root_domains": "not-a-list",  # should be a list of strings
        "ip_blocks": 6789,  # should be a list of CIDR strings
        "region_id": {"bad": "format"},  # should be string
        "state": None,  # should be a string
    }

    update_resp = requests.put(
        f"{BASE_URL}/organizations/{org_id}",
        json=invalid_payload,
        headers=HEADERS,
        timeout=TIMEOUT,
    )

    # Step 3: Validate
    assert (
        update_resp.status_code == 422
    ), f"Expected 422, got {update_resp.status_code}"
    error_detail = update_resp.json().get("detail")
    assert error_detail, "Expected validation errors in response body"


# ========================================
#   DELETE organization
# ========================================


@pytest.mark.integration
def test_delete_organization_success(region_id, state):
    """Create a fresh org, delete it, then verify it’s gone."""
    # 1) Create via POST /organizations
    acr = f"DLP{uuid.uuid4().hex[:6].upper()}"
    name = f"Delete Org {uuid.uuid4().hex[:6]}"
    create_payload = {
        "acronym": acr,
        "name": name,
        "root_domains": ["del.com"],
        "ip_blocks": ["10.0.0.0/28"],
        "is_passive": False,
        "pending_domains": [],
        "country": "US",
        "state": state,
        "region_id": str(region_id),
        "state_fips": 12,
        "state_name": "Florida",
        "county": "SomeCounty",
        "county_fips": 12345,
        "type": "STATE",
    }
    r1 = requests.post(
        f"{BASE_URL}/organizations",
        json=create_payload,
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    assert r1.status_code == 200
    org_id = r1.json()["id"]

    # 2) Delete it
    r2 = requests.delete(
        f"{BASE_URL}/organizations/{org_id}", headers=HEADERS, timeout=TIMEOUT
    )
    assert r2.status_code == 200, f"Expected 200 OK, got {r2.status_code}"
    body = r2.json()

    assert "message" in body, "Expected a 'message' key in delete response"
    assert "status" in body, "Expected a 'status' key in delete response"
    assert body["status"] == "success"
    assert "has been deleted successfully" in body["message"]

    r3 = requests.get(
        f"{BASE_URL}/organizations/{org_id}", headers=HEADERS, timeout=TIMEOUT
    )
    assert r3.status_code == 404, f"Expected 404 for deleted org, got {r3.status_code}"


@pytest.mark.integration
def test_delete_organization_not_found():
    """Deleting a non-existent ID should return 404."""
    r = requests.delete(
        f"{BASE_URL}/organizations/{BAD_ID}", headers=HEADERS, timeout=TIMEOUT
    )
    assert r.status_code == 404, f"Expected 404, got {r.status_code}"
    body = r.json()
    assert "detail" in body and "not found" in body["detail"].lower()


@pytest.mark.integration
def test_delete_organization_invalid():
    """Deleting a invalid id should return 404."""
    r = requests.delete(
        f"{BASE_URL}/organizations/{'cisa'}", headers=HEADERS, timeout=TIMEOUT
    )
    assert r.status_code == 404, f"Expected 404, got {r.status_code}"
    body = r.json()
    assert "detail" in body and "invalid" in body["detail"].lower()


@pytest.mark.integration
def test_delete_organization_unauthenticated():
    """Missing API key → 401 or 403."""
    r = requests.delete(f"{BASE_URL}/organizations/{BAD_ID}", timeout=TIMEOUT)
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


@pytest.mark.integration
def test_delete_organization_invalid_api_key():
    """Invalid API key → 401 or 403."""
    r = requests.delete(
        f"{BASE_URL}/organizations/{BAD_ID}", headers=BAD_HEADERS, timeout=TIMEOUT
    )
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


@pytest.mark.integration
def test_delete_organization_method_not_allowed(region_id):
    """POST to the DELETE endpoint should return 405."""
    r = requests.post(
        f"{BASE_URL}/organizations/{region_id}", headers=HEADERS, timeout=TIMEOUT
    )
    assert r.status_code == 405, f"Expected 405 Method Not Allowed, got {r.status_code}"


@pytest.mark.integration
def test_delete_organization_with_payload_success(region_id, state):
    """Create a fresh org, delete it with payload, then verify it’s gone."""
    # 1) Create via POST /organizations
    acr = f"DLP{uuid.uuid4().hex[:6].upper()}"
    name = f"Delete Org {uuid.uuid4().hex[:6]}"
    create_payload = {
        "acronym": acr,
        "name": name,
        "root_domains": ["del.com"],
        "ip_blocks": ["10.0.0.0/28"],
        "is_passive": False,
        "pending_domains": [],
        "country": "US",
        "state": state,
        "region_id": str(region_id),
        "state_fips": 12,
        "state_name": "Florida",
        "county": "SomeCounty",
        "county_fips": 12345,
        "type": "STATE",
    }
    r1 = requests.post(
        f"{BASE_URL}/organizations",
        json=create_payload,
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    assert r1.status_code == 200
    org_id = r1.json()["id"]

    r2 = requests.delete(
        f"{BASE_URL}/organizations/{org_id}",
        json=create_payload,
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    assert r2.status_code == 200, f"Expected 200 OK, got {r2.status_code}"
    body = r2.json()

    assert "message" in body, "Expected a 'message' key in delete response"
    assert "status" in body, "Expected a 'status' key in delete response"
    assert body["status"] == "success"
    assert "has been deleted successfully" in body["message"]

    r3 = requests.get(
        f"{BASE_URL}/organizations/{org_id}", headers=HEADERS, timeout=TIMEOUT
    )
    assert r3.status_code == 404, f"Expected 404 for deleted org, got {r3.status_code}"


# ========================================
#   GET organizations v2
# ========================================


@pytest.fixture(scope="session")
def all_v2_organizations():
    """Fetch the full list of v2 organizations once per test session."""
    url = f"{BASE_URL}/v2/organizations"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    assert resp.status_code == 200, f"/organizations returned {resp.status_code}"
    data = resp.json()
    assert isinstance(data, list) and data, "Expected a non-empty list of organizations"
    return data


@pytest.fixture(scope="session")
def v2_sample_org(all_v2_organizations):
    """Pick one v2 organization from the list for downstream tests."""
    return all_v2_organizations[0]


@pytest.fixture(scope="session")
def v2_org_id(v2_sample_org):
    """Retrieve organization id from v2 sample org."""
    return v2_sample_org["id"]


@pytest.fixture(scope="session")
def v2_region_id(v2_sample_org):
    """Retrieve region id from v2 sample org."""
    return v2_sample_org.get("region_id")


@pytest.fixture(scope="session")
def v2_state(v2_sample_org):
    """Retrieve state from v2 sample org."""
    return v2_sample_org.get("state")


@pytest.fixture(scope="session")
def v2_name(v2_sample_org):
    """Retrieve name from v2 sample org."""
    return v2_sample_org["name"]


@pytest.mark.integration
def test_list_organizations_v2_no_filters():
    """GET /v2/organizations with no query params returns 200 and a non-empty list."""
    url = f"{BASE_URL}/v2/organizations"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"
    data = resp.json()
    assert isinstance(data, list), f"Expected list, got {type(data).__name__}"
    assert len(data) > 0, "Expected at least one organization"

    for org in data:
        assert "id" in org and "name" in org, "Each org must have id and name"


@pytest.mark.integration
def test_list_organizations_v2_filter_state(v2_state):
    """GET /v2/organizations?state={state} returns only orgs matching that state."""
    url = f"{BASE_URL}/v2/organizations"
    resp = requests.get(
        url,
        headers=HEADERS,
        params={"state": v2_state},
        timeout=TIMEOUT,
    )

    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) > 0, f"Expected at least one org for state={state}"

    for org in data:
        assert (
            org.get("state") == v2_state
        ), f"Expected state={v2_state}, got {org.get('state')}"


@pytest.mark.integration
def test_list_organizations_v2_filter_region(v2_region_id):
    """GET /v2/organizations?region_id={region_id} returns only orgs matching that region."""
    url = f"{BASE_URL}/v2/organizations"
    resp = requests.get(
        url,
        headers=HEADERS,
        params={"region_id": v2_region_id},
        timeout=TIMEOUT,
    )

    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) > 0, f"Expected at least one org for region_id={region_id}"

    for org in data:
        assert str(org.get("region_id")) == str(
            v2_region_id
        ), f"Expected region_id={v2_region_id}, got {org.get('region_id')}"


@pytest.mark.integration
def test_list_organizations_v2_filter_both(v2_state, v2_region_id):
    """GET using both state and region id, returns orgs matching *both* filters."""
    url = f"{BASE_URL}/v2/organizations"
    resp = requests.get(
        url,
        headers=HEADERS,
        params={"state": v2_state, "region_id": v2_region_id},
        timeout=TIMEOUT,
    )

    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert (
        len(data) > 0
    ), f"Expected at least one org for state={state}&region_id={region_id}"

    for org in data:
        assert org.get("state") == v2_state
        assert str(org.get("region_id")) == str(v2_region_id)


@pytest.mark.integration
def test_list_organizations_v2_unauthenticated():
    """Missing API key → 401 or 403."""
    url = f"{BASE_URL}/v2/organizations"
    resp = requests.get(url, timeout=TIMEOUT)
    assert resp.status_code in (
        401,
        403,
    ), f"Expected 401/403 for missing API key, got {resp.status_code}"


@pytest.mark.integration
def test_list_organizations_v2_invalid_api_key():
    """Invalid API key → 401 or 403."""
    url = f"{BASE_URL}/v2/organizations"
    resp = requests.get(url, headers={"X-API-KEY": "invalid-key"}, timeout=TIMEOUT)
    assert resp.status_code in (
        401,
        403,
    ), f"Expected 401/403 for invalid API key, got {resp.status_code}"


@pytest.mark.integration
def test_list_organizations_v2_method_not_allowed():
    """POST on a GET-only endpoint → 405 Method Not Allowed."""
    url = f"{BASE_URL}/v2/organizations"
    resp = requests.post(url, headers=HEADERS, timeout=TIMEOUT)
    assert (
        resp.status_code == 405
    ), f"Expected 405 Method Not Allowed, got {resp.status_code}"


@pytest.mark.integration
def test_list_organizations_v2_invalid_filter_values():
    """Query with invalid state and region_id returns 200 and likely empty list."""
    url = f"{BASE_URL}/v2/organizations"
    params = {"state": "ZZZ", "region_id": "not-an-id"}
    resp = requests.get(url, headers=HEADERS, params=params, timeout=TIMEOUT)

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 0 or all(
        org.get("state") != "ZZZ" and str(org.get("region_id")) != "not-an-id"
        for org in data
    )


# ========================================
#   POST search organizations
# ========================================


def extract_docs(es_hit: dict) -> dict:
    """Given an ES hit, return the document source.

    Some implementations put the fields at the top level,
    others nest them under '_source'.
    """
    return es_hit.get("_source", es_hit)


@pytest.mark.integration
def test_search_organizations_minimal(v2_region_id):
    """Empty search_term + one region, should return 200 and ES‐style hits."""
    url = f"{BASE_URL}/search/organizations"
    payload = {"search_term": "", "regions": [v2_region_id]}

    resp = requests.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT)
    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"

    data = resp.json()
    # top‐level body
    assert "body" in data, "Expected 'body' in ES response"
    assert "hits" in data["body"], "Expected 'hits' in body"
    assert "hits" in data["body"]["hits"], "Expected 'hits' list in body.hits"

    hits = data["body"]["hits"]["hits"]
    assert isinstance(hits, list), f"Expected list, got {type(hits).__name__}"


@pytest.mark.integration
def test_search_organizations_with_term_and_regions(
    v2_sample_org, v2_org_id, v2_state, v2_region_id, v2_name
):
    """Supply both a non-empty search_term and regions filter."""
    url = f"{BASE_URL}/search/organizations"
    payload = {
        "search_term": v2_name,
        "regions": [v2_region_id],
    }
    resp = requests.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT)
    assert resp.status_code == 200

    body = resp.json()["body"]
    hits = body["hits"]["hits"]
    assert len(hits) == 1, f"Expected 1 hit, got {len(hits)}"

    doc = extract_docs(hits[0])
    assert doc["id"] == v2_org_id
    assert doc["name"] == v2_name
    assert doc["state"] == v2_state
    assert doc["region_id"] == v2_region_id
    assert doc["country"] == v2_sample_org.get("country")
    assert "tags" in doc
    assert (
        isinstance(doc.get("suggest"), list) and doc["suggest"]
    ), "Expected non-empty suggest list"


@pytest.mark.integration
def test_search_organizations_missing_regions():
    """Omitting 'regions' yields 422 with a missing-field error for regions."""
    url = f"{BASE_URL}/search/organizations"
    payload = {"search_term": "anything"}
    resp = requests.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 422
    errors = resp.json().get("detail", [])
    assert any(err["loc"][-1] == "regions" for err in errors)


@pytest.mark.integration
def test_search_organizations_missing_search_term(v2_region_id):
    """Omitting 'search_term' yields 422 with a missing-field error for search_term."""
    url = f"{BASE_URL}/search/organizations"
    payload = {"regions": [v2_region_id]}
    resp = requests.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 422
    errors = resp.json().get("detail", [])
    assert any(err["loc"][-1] == "search_term" for err in errors)


@pytest.mark.integration
def test_search_organizations_invalid_body():
    """Wrong types for fields → 422."""
    url = f"{BASE_URL}/search/organizations"
    payload = {"search_term": 123, "regions": "not-a-list"}
    resp = requests.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT)
    assert resp.status_code == 422


@pytest.mark.integration
def test_search_organizations_unauthenticated(v2_region_id):
    """Missing API key → 401 or 403."""
    url = f"{BASE_URL}/search/organizations"
    payload = {"search_term": "", "regions": [v2_region_id]}
    resp = requests.post(url, json=payload, timeout=TIMEOUT)
    assert resp.status_code in (401, 403)


@pytest.mark.integration
def test_search_organizations_invalid_api_key(v2_region_id):
    """Invalid API key → 401 or 403."""
    url = f"{BASE_URL}/search/organizations"
    payload = {"search_term": "", "regions": [v2_region_id]}
    resp = requests.post(url, json=payload, headers=BAD_HEADERS, timeout=TIMEOUT)
    assert resp.status_code in (401, 403)


@pytest.mark.integration
def test_search_organizations_method_not_allowed():
    """GET on a POST-only endpoint → 405."""
    url = f"{BASE_URL}/search/organizations"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    assert resp.status_code == 405


# ========================================
#   POST /v2/organizations/{v2_org_id}/users
# ========================================


@pytest.fixture(scope="function")
def test_user():
    """Creates a temporary user via POST /users.

    Yields the new user record, then deletes it after the test.
    """
    email = f"testuser_{uuid.uuid4().hex[:8]}@example.com"
    payload = {
        "first_name": "Test",
        "last_name": "User",
        "email": email,
        "region_id": "3",
        "state": "Virginia",
        "user_type": "standard",
    }

    # invite the user
    resp = requests.post(
        f"{BASE_URL}/users",
        json=payload,
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    assert resp.status_code == 200, f"User invite failed: {resp.status_code}"
    user = resp.json()

    yield user

    # teardown: delete the user
    del_url = f"{BASE_URL}/users/{user['id']}"
    try:
        del_resp = requests.delete(
            del_url,
            headers=HEADERS,
            timeout=TIMEOUT,
        )
        assert del_resp.status_code in (
            200,
            404,
        ), f"Cleanup DELETE failed: {del_resp.status_code}"
    except requests.exceptions.RequestException as e:
        pytest.skip(f"Could not clean up test user due to request error: {e}")


ROLE_MEMBER = "member"


@pytest.mark.integration
def test_add_user_to_organization_v2_success(v2_org_id, test_user):
    """Happy path: assign test_user['id'] to org_id with role=member."""
    url = f"{BASE_URL}/v2/organizations/{v2_org_id}/users"
    payload = {"user_id": test_user["id"], "role": ROLE_MEMBER}

    resp = requests.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT)
    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"
    data = resp.json()

    assert "id" in data, "Expected an assignment 'id'"
    assert data.get("role") == ROLE_MEMBER

    assert isinstance(data.get("approved"), bool)
    assert "approved_by" in data and "id" in data["approved_by"]

    assert "user" in data and data["user"].get("id") == test_user["id"]

    assert "organization" in data and data["organization"].get("id") == v2_org_id


@pytest.mark.integration
def test_add_user_to_organization_v2_missing_user_id(v2_org_id):
    """Omitting user_id → 422 Unprocessable Entity."""
    url = f"{BASE_URL}/v2/organizations/{v2_org_id}/users"
    payload = {"role": ROLE_MEMBER}
    resp = requests.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 422
    errors = resp.json().get("detail", [])
    assert any(err["loc"][-1] == "user_id" for err in errors)


@pytest.mark.integration
def test_add_user_to_organization_v2_missing_role(v2_org_id, test_user):
    """Omitting role → 422 Unprocessable Entity."""
    url = f"{BASE_URL}/v2/organizations/{v2_org_id}/users"
    payload = {"user_id": test_user["id"]}
    resp = requests.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 422
    errors = resp.json().get("detail", [])
    assert any(err["loc"][-1] == "role" for err in errors)


@pytest.mark.integration
def test_add_user_to_organization_v2_nonexistent_org(test_user):
    """Assigning to a non-existent org_id should return 404."""
    bad_org = "00000000-0000-0000-0000-000000000000"
    url = f"{BASE_URL}/v2/organizations/{bad_org}/users"
    payload = {"user_id": test_user["id"], "role": ROLE_MEMBER}
    resp = requests.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 404
    detail = resp.json().get("detail", "")
    assert "not found" in detail.lower()


@pytest.mark.integration
def test_add_user_to_organization_v2_unauthenticated(v2_org_id, test_user):
    """Missing API key → 401 or 403."""
    url = f"{BASE_URL}/v2/organizations/{v2_org_id}/users"
    payload = {"user_id": test_user["id"], "role": ROLE_MEMBER}
    resp = requests.post(url, json=payload, timeout=TIMEOUT)

    assert resp.status_code in (401, 403)


@pytest.mark.integration
def test_add_user_to_organization_v2_invalid_api_key(v2_org_id, test_user):
    """Invalid API key → 401 or 403."""
    url = f"{BASE_URL}/v2/organizations/{v2_org_id}/users"
    payload = {"user_id": test_user["id"], "role": ROLE_MEMBER}
    resp = requests.post(url, json=payload, headers=BAD_HEADERS, timeout=TIMEOUT)

    assert resp.status_code in (401, 403)


@pytest.mark.integration
def test_add_user_to_organization_v2_method_not_allowed(v2_org_id):
    """GET on a POST-only endpoint → 405 Method Not Allowed."""
    url = f"{BASE_URL}/v2/organizations/{v2_org_id}/users"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 405


@pytest.mark.integration
def test_add_user_to_organization_v2_invalid_format_and_value(v2_org_id):
    """Invalid format (wrong types) and invalid values (bad role) → 422."""
    url = f"{BASE_URL}/v2/organizations/{v2_org_id}/users"
    payload = {
        "user_id": 12345,  # invalid type
    }

    resp = requests.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}"
    errors = resp.json().get("detail", [])
    assert any(err["loc"][-1] == "user_id" for err in errors)


# ========================================
#   POST organziations/org_id/roles/role_id/approve
# ========================================


@pytest.mark.integration
def test_approve_role_success(v2_org_id, test_user):
    """Assign a user to an org, then approve that assignment."""
    # 1) Create the assignment
    assign_url = f"{BASE_URL}/v2/organizations/{v2_org_id}/users"
    assign_payload = {"user_id": test_user["id"], "role": ROLE_MEMBER}
    r1 = requests.post(
        assign_url, json=assign_payload, headers=HEADERS, timeout=TIMEOUT
    )
    assert r1.status_code == 200, f"Assign returned {r1.status_code}"
    assignment = r1.json()
    role_id = assignment["id"]

    # 2) Approve the role
    approve_url = f"{BASE_URL}/organizations/{v2_org_id}/roles/{role_id}/approve"
    r2 = requests.post(approve_url, headers=HEADERS, timeout=TIMEOUT)
    assert r2.status_code == 200, f"Approve returned {r2.status_code}"

    body = r2.json()
    assert "message" in body, "Expected 'message' key"
    assert "status" in body, "Expected 'status' key"
    assert body["status"] == "success"
    assert "approved" in body["message"].lower()


@pytest.mark.integration
def test_approve_role_not_found(v2_org_id):
    """404 when the role_id doesn’t exist on a real org."""
    url = f"{BASE_URL}/organizations/{v2_org_id}/roles/{BAD_ID}/approve"
    resp = requests.post(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"
    detail = resp.json().get("detail", "")
    assert "not found" in detail.lower()


@pytest.mark.integration
def test_approve_role_nonexistent_org(test_user):
    """404 when the organization_id doesn’t exist."""
    url = f"{BASE_URL}/organizations/{BAD_ID}/roles/{BAD_ID}/approve"
    resp = requests.post(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"
    detail = resp.json().get("detail", "")
    assert "not found" in detail.lower()


@pytest.mark.integration
def test_approve_role_unauthenticated(v2_org_id):
    """401 or 403 when no API key is provided."""
    url = f"{BASE_URL}/organizations/{v2_org_id}/roles/{BAD_ID}/approve"
    resp = requests.post(url, timeout=TIMEOUT)
    assert resp.status_code in (401, 403), f"Expected 401/403, got {resp.status_code}"


@pytest.mark.integration
def test_approve_role_invalid_api_key(v2_org_id):
    """401 or 403 when an invalid API key is provided."""
    url = f"{BASE_URL}/organizations/{v2_org_id}/roles/{BAD_ID}/approve"
    resp = requests.post(url, headers=BAD_HEADERS, timeout=TIMEOUT)
    assert resp.status_code in (401, 403), f"Expected 401/403, got {resp.status_code}"


@pytest.mark.integration
def test_approve_role_method_not_allowed(v2_org_id):
    """GET on this endpoint should return 405 Method Not Allowed."""
    url = f"{BASE_URL}/organizations/{v2_org_id}/roles/{BAD_ID}/approve"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    assert resp.status_code == 405, f"Expected 405, got {resp.status_code}"


@pytest.mark.integration
def test_approve_role_invalid_format():
    """Badly formatted org_id or role_id should still return 404 (not found)."""
    bad_org_id = "not-a-uuid"
    bad_role_id = "also-not-a-uuid"

    url = f"{BASE_URL}/organizations/{bad_org_id}/roles/{bad_role_id}/approve"
    resp = requests.post(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"
    detail = resp.json().get("detail", "")
    assert isinstance(detail, str), "Expected string 'detail'"
    assert "not found" in detail.lower(), f"Unexpected error detail: {detail}"


# ========================================
#   POST organziations/org_id/roles/role_id/remove
# ========================================


@pytest.mark.integration
def test_remove_role_success(v2_org_id, test_user):
    """Assign a user to an org, then remove that role."""
    # 1) Create the assignment
    assign_url = f"{BASE_URL}/v2/organizations/{v2_org_id}/users"
    assign_payload = {"user_id": test_user["id"], "role": ROLE_MEMBER}
    r1 = requests.post(
        assign_url, json=assign_payload, headers=HEADERS, timeout=TIMEOUT
    )
    assert r1.status_code == 200, f"Assign returned {r1.status_code}"
    assignment = r1.json()
    role_id = assignment["id"]

    # 2) Remove the role
    remove_url = f"{BASE_URL}/organizations/{v2_org_id}/roles/{role_id}/remove"
    r2 = requests.post(remove_url, headers=HEADERS, timeout=TIMEOUT)
    assert r2.status_code == 200, f"Remove returned {r2.status_code}"

    body = r2.json()
    assert "message" in body, "Expected 'message' key"
    assert "status" in body, "Expected 'status' key"
    assert body["status"] == "success"
    assert "removed" in body["message"].lower()


@pytest.mark.integration
def test_remove_role_not_found(v2_org_id):
    """500 (not 404) when the role_id doesn’t exist on a real organization."""
    url = f"{BASE_URL}/organizations/{v2_org_id}/roles/{BAD_ID}/remove"
    resp = requests.post(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 500, f"Expected 500, got {resp.status_code}"
    detail = resp.json().get("detail", "")
    assert "role matching query does not exist" in detail.lower()


@pytest.mark.integration
def test_remove_role_nonexistent_org():
    """500 (not 404) when the organization_id doesn’t exist."""
    url = f"{BASE_URL}/organizations/{BAD_ID}/roles/{BAD_ID}/remove"
    resp = requests.post(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 500, f"Expected 500, got {resp.status_code}"
    detail = resp.json().get("detail", "")
    assert "role matching query does not exist" in detail.lower()


@pytest.mark.integration
def test_remove_role_unauthenticated(v2_org_id):
    """401 or 403 when no API key is provided."""
    url = f"{BASE_URL}/organizations/{v2_org_id}/roles/{BAD_ID}/remove"
    resp = requests.post(url, timeout=TIMEOUT)
    assert resp.status_code in (401, 403), f"Expected 401/403, got {resp.status_code}"


@pytest.mark.integration
def test_remove_role_invalid_api_key(v2_org_id):
    """401 or 403 when an invalid API key is provided."""
    url = f"{BASE_URL}/organizations/{v2_org_id}/roles/{BAD_ID}/remove"
    resp = requests.post(url, headers=BAD_HEADERS, timeout=TIMEOUT)
    assert resp.status_code in (401, 403), f"Expected 401/403, got {resp.status_code}"


@pytest.mark.integration
def test_remove_role_method_not_allowed(v2_org_id):
    """GET on this POST-only endpoint should return 405 Method Not Allowed."""
    url = f"{BASE_URL}/organizations/{v2_org_id}/roles/{BAD_ID}/remove"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    assert resp.status_code == 405, f"Expected 405, got {resp.status_code}"


@pytest.mark.integration
def test_remove_role_invalid_format():
    """Badly formatted org_id or role_id should still return 404 (not found)."""
    bad_org_id = "not-a-uuid"
    bad_role_id = "also-not-a-uuid"

    url = f"{BASE_URL}/organizations/{bad_org_id}/roles/{bad_role_id}/remove"
    resp = requests.post(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"
    detail = resp.json().get("detail", "")
    assert isinstance(detail, str), "Expected string 'detail'"
    assert "not found" in detail.lower(), f"Unexpected error detail: {detail}"


# ========================================
#   POST organziations/granularScan
# ========================================


@pytest.fixture
def test_scan(v2_org_id):
    """Create a temporary scan via POST /scans using the required payload.

    Yields the new scan record, then deletes it after the test.
    """
    payload = {
        "name": "censys",
        "arguments": {},
        "organizations": [v2_org_id],
        "tags": [],
        "frequency": 86400,
        "frequencyUnit": "day",
        "is_granular": True,
        "is_user_modifiable": True,
        "is_single_scan": False,
        "concurrent_tasks": 1,
    }

    # Create the scan
    resp = requests.post(
        f"{BASE_URL}/scans",
        json=payload,
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    assert resp.status_code == 200, f"Scan creation failed: {resp.status_code}"
    scan = resp.json()

    yield scan

    # Teardown: delete the scan
    try:
        del_resp = requests.delete(
            f"{BASE_URL}/scans/{scan['id']}",
            headers=HEADERS,
            timeout=TIMEOUT,
        )
        assert del_resp.status_code in (
            200,
            404,
        ), f"Scan deletion failed: {del_resp.status_code}"
    except Exception as e:
        print(f"Warning: failed to delete scan {scan.get('id')}: {e}")


@pytest.mark.integration
def test_update_granular_scan_enable_and_cleanup(org_id, test_scan):
    """Enable a granular scan for an organization (enabled=True), then disable it again."""
    scan_id = test_scan["id"]
    url = f"{BASE_URL}/organizations/{org_id}/granularScans/{scan_id}/update"

    resp = requests.post(
        url,
        json={"enabled": True},
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    assert resp.status_code == 200, f"Expected 200 OK on enable, got {resp.status_code}"
    org = resp.json()
    assert org["id"] == org_id

    scans = org.get("granular_scans", [])
    assert any(s["id"] == scan_id for s in scans), "Scan should be present when enabled"

    resp2 = requests.post(
        url,
        json={"enabled": False},
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    assert (
        resp2.status_code == 200
    ), f"Expected 200 OK on disable, got {resp2.status_code}"
    org2 = resp2.json()
    scans2 = org2.get("granular_scans", [])
    assert all(
        s["id"] != scan_id for s in scans2
    ), "Scan should be removed when disabled"


@pytest.mark.integration
def test_update_granular_scan_not_found_scan(org_id):
    """404 when the scan_id doesn’t exist on a real organization."""
    url = f"{BASE_URL}/organizations/{org_id}" f"/granularScans/{BAD_ID}/update"
    resp = requests.post(
        url,
        json={"enabled": True},
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    assert (
        resp.status_code == 404
    ), f"Expected 404 for bad scan_id, got {resp.status_code}"
    detail = resp.json().get("detail", "")
    assert "scan not found" in detail.lower()


@pytest.mark.integration
def test_update_granular_scan_not_found_org(test_scan):
    """404 when the organization_id doesn’t exist."""
    scan_id = test_scan["id"]
    url = f"{BASE_URL}/organizations/{BAD_ID}" f"/granularScans/{scan_id}/update"
    resp = requests.post(
        url,
        json={"enabled": True},
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    assert (
        resp.status_code == 404
    ), f"Expected 404 for bad org_id, got {resp.status_code}"
    detail = resp.json().get("detail", "")
    assert "organization not found" in detail.lower()


@pytest.mark.integration
def test_update_granular_scan_missing_body(org_id, test_scan):
    """Omitting the JSON body → 422 Unprocessable Entity."""
    scan_id = test_scan["id"]
    url = f"{BASE_URL}/organizations/{org_id}/granularScans/{scan_id}/update"
    resp = requests.post(url, headers=HEADERS, timeout=TIMEOUT)

    assert (
        resp.status_code == 422
    ), f"Expected 422 for missing body, got {resp.status_code}"


@pytest.mark.integration
def test_update_granular_scan_invalid_body(org_id, test_scan):
    """Wrong type for 'enabled' → 422 Unprocessable Entity."""
    scan_id = test_scan["id"]
    url = f"{BASE_URL}/organizations/{org_id}/granularScans/{scan_id}/update"
    resp = requests.post(
        url,
        json={"enabled": "not-a-bool"},
        headers=HEADERS,
        timeout=TIMEOUT,
    )

    assert (
        resp.status_code == 422
    ), f"Expected 422 for invalid body, got {resp.status_code}"


@pytest.mark.integration
def test_update_granular_scan_unauthenticated(org_id, test_scan):
    """No API key → 401 or 403."""
    scan_id = test_scan["id"]
    url = f"{BASE_URL}/organizations/{org_id}/granularScans/{scan_id}/update"
    resp = requests.post(url, json={"enabled": True}, timeout=TIMEOUT)

    assert resp.status_code in (401, 403), f"Expected 401/403, got {resp.status_code}"


@pytest.mark.integration
def test_update_granular_scan_invalid_api_key(org_id, test_scan):
    """Invalid API key → 401 or 403."""
    scan_id = test_scan["id"]
    url = f"{BASE_URL}/organizations/{org_id}/granularScans/{scan_id}/update"
    resp = requests.post(
        url,
        json={"enabled": True},
        headers=BAD_HEADERS,
        timeout=TIMEOUT,
    )

    assert resp.status_code in (401, 403), f"Expected 401/403, got {resp.status_code}"


@pytest.mark.integration
def test_update_granular_scan_method_not_allowed(org_id, test_scan):
    """GET on this POST-only endpoint → 405 Method Not Allowed."""
    scan_id = test_scan["id"]
    url = f"{BASE_URL}/organizations/{org_id}/granularScans/{scan_id}/update"
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    assert resp.status_code == 405, f"Expected 405, got {resp.status_code}"


@pytest.mark.integration
def test_update_granular_scan_invalid_uuid_format():
    """Bad UUID format in path params → 422 if validated, or 404 if not found."""
    bad_org_id = "not-a-uuid"
    bad_scan_id = "also-not-a-uuid"
    url = f"{BASE_URL}/organizations/{bad_org_id}/granularScans/{bad_scan_id}/update"

    resp = requests.post(
        url,
        json={"enabled": True},
        headers=HEADERS,
        timeout=TIMEOUT,
    )

    assert resp.status_code in (404, 422), f"Expected 404/422, got {resp.status_code}"
