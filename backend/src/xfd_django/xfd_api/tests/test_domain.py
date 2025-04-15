"""Test domain API."""
# Standard Python Libraries
from datetime import datetime
import secrets

# Third-Party Libraries
from django.db import transaction
from fastapi.testclient import TestClient
import pytest
from xfd_api.auth import create_jwt_token
from xfd_django.asgi import app
from xfd_mini_dl.models import (
    Domain,
    Organization,
    Service,
    User,
    UserType,
    Vulnerability,
)

client = TestClient(app)


bad_id = "960b7db7-f3af-411d-a247-33371"
search_fields = {
    "port": "80",
    "reverse_name": "local.crossfeed.quizzical-wing",
    "ip": "127.116.195.151",
    "organization_name": "Wizardly Agency",
    "tag": "",
}


@pytest.fixture
def user():
    """Create user fixture."""
    user = User.objects.create(
        first_name="",
        last_name="",
        email="{}@example.com".format(secrets.token_hex(4)),
        user_type=UserType.GLOBAL_ADMIN,
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )
    yield user
    user.delete()  # Clean up after the test


@pytest.fixture
def organization():
    """Create org fixture."""
    organization = Organization.objects.create(
        name=search_fields["organization_name"],
        root_domains=["crossfeed.local"],
        ip_blocks=[],
        is_passive=False,
    )
    transaction.commit()
    assert organization.name == search_fields["organization_name"]
    yield organization


@pytest.fixture
def domain(organization):
    """Create domain fixture."""
    domain = Domain.objects.create(
        reverse_name="local.crossfeed.example",
        ip=search_fields["ip"],  # Ensure this IP is the one you expect
        organization=organization,
        name="example.crossfeed.local",
    )
    transaction.commit()
    # Debugging: Ensure the domain is created correctly
    assert domain.ip == search_fields["ip"]
    yield domain


@pytest.fixture
def service(domain):
    """Create service fixture."""
    service = Service.objects.create(
        service_source="shodan",
        port=search_fields["port"],
        service="http",
        products="test test test",
        censys_ipv4_results={},
        intrigue_ident_results={},
        shodan_results={},
        wappalyzer_results=[],
        domain=domain,
    )
    transaction.commit()
    assert service.port == search_fields["port"]
    assert service.domain == domain
    yield service


@pytest.fixture
def vulnerability(domain, service):
    """Create vuln fixture."""
    vulnerability = Vulnerability.objects.create(
        title="Vulnerability title",
        description="Test description",
        references=[],
        needs_population=False,
        state="open",
        substate="unconfirmed",
        source="test",
        notes="test",
        actions=[],
        structured_data={},
        isKev=False,
        domain=domain,
        service=service,
    )
    transaction.commit()
    assert vulnerability.domain == domain
    assert vulnerability.service == service
    yield vulnerability


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_get_domain_by_id(user, domain):
    """Test domain by id."""
    # Get domain by Id.
    response = client.get(
        "/domain/{}".format(domain.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None, "Response is empty"
    assert data["id"] == str(domain.id)
    assert data["ip"] == domain.ip


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_get_domain_by_id_fails_404(user, domain):
    """Test domain by id to fail."""
    # Get domain by Id.
    response = client.get(
        "/domain/{}".format(bad_id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 404


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_search_domain_by_ip(user, vulnerability):
    """Test domain by ip."""
    # Search for the domain by IP
    response = client.post(
        "/domain/search",
        json={"page": 1, "filters": {"ip": search_fields["ip"]}, "page_size": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None, "Response is empty"
    assert "result" in data, "Response does not contain 'result' key"
    assert len(data["result"]) > 0, "No result found for the given IP"

    # Validate result contain the correct IP
    for domain in data["result"]:
        assert domain["ip"] == search_fields["ip"], "Expected IP {}, but got {}".format(
            search_fields["ip"], domain["ip"]
        )


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_search_domain_by_port(user, vulnerability):
    """Test domain by port."""
    response = client.post(
        "/domain/search",
        json={"page": 1, "filters": {"port": search_fields["port"]}, "page_size": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None, "Response is empty"
    assert "result" in data, "Response does not contain 'result' key"
    assert len(data["result"]) > 0, "No result found for the given IP"

    for domain_data in data["result"]:
        domain_id = domain_data.get("id", None)

        assert domain_id is not None, "Domain Id not found in Response"
        services = Service.objects.filter(domain=domain_id)
        for service in services:
            assert (
                str(service.port) == search_fields["port"]
            ), "Domain with ID {} does not have a service with port {}".format(
                domain_id, vulnerability.service.port
            )


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_search_domain_by_service(user, vulnerability):
    """Test domain by service."""
    response = client.post(
        "/domain/search",
        json={
            "page": 1,
            "filters": {"service": str(vulnerability.service.products)},
            "page_size": 25,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200

    data = response.json()
    assert data is not None, "Response body is empty"
    assert "result" in data, "Response does not contain 'result' key"
    assert len(data["result"]) > 0, "No result found for the given service"

    for domain_data in data["result"]:
        domain_id = domain_data.get("id", None)

        assert domain_id is not None, "Domain Id not found in Response"
        services = Service.objects.filter(domain=domain_id)
        service_match = services.filter(id=vulnerability.service.id)
        assert (
            service_match is not None
        ), "Domain with ID {} is not related a service with ID {}".format(
            domain_id, vulnerability.service.id
        )


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_search_domain_by_organization(user, vulnerability):
    """Test domain by org."""
    # Test search domains by organization
    response = client.post(
        "/domain/search",
        json={
            "page": 1,
            "filters": {"organization": str(vulnerability.domain.organization.id)},
            "page_size": 25,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    data = response.json()
    assert "result" in data, "Response does not contain 'result' key"
    assert len(data["result"]) > 0, "No result found for the given organization"

    for domain in data["result"]:
        assert domain["organization"]["name"] == str(
            vulnerability.domain.organization.name
        )


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_search_domain_by_organization_name(user, vulnerability):
    """Test domain by org name."""
    # Test search domains by organization
    response = client.post(
        "/domain/search",
        json={
            "page": 1,
            "filters": {"organization_name": search_fields["organization_name"]},
            "page_size": 25,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    data = response.json()
    assert "result" in data, "Response does not contain 'result' key"
    assert len(data["result"]) > 0, "No result found for the given organization name"

    for domain in data["result"]:
        assert (
            domain["organization"] is not None
        ), "Response domain did not include an Organization ID"
        organization = Organization.objects.get(id=domain["organization"]["id"])
        assert (
            organization.name == search_fields["organization_name"]
        ), "Domain with ID {} did not contain Organization Id {}".format(
            domain["id"], search_fields["organization_name"]
        )


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_search_domain_by_vulnerabilities(user, vulnerability):
    """Test domain by vuln."""
    # Test search domains by vulnerabilities
    response = client.post(
        "/domain/search",
        json={
            "page": 1,
            "filters": {"vulnerabilities": str(vulnerability.title)},
            "page_size": 25,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    data = response.json()
    assert "result" in data, "Response does not contain 'result' key"
    assert len(data["result"]) > 0, "No result found for the given vulnerability"

    for domain in data["result"]:
        assert str(vulnerability.domain.id) == str(
            domain["id"]
        ), "Response domain {} did not relate back to the expected vulnerability {}".format(
            domain["id"], vulnerability.domain.id
        )


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_search_domains_multiple_criteria(user, vulnerability):
    """Test domain by multi-criteria."""
    # Test search domains by multiple criteria
    response = client.post(
        "/domain/search",
        json={
            "page": 1,
            "filters": {"ip": search_fields["ip"], "port": search_fields["port"]},
            "page_size": 25,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    data = response.json()
    assert "result" in data, "Response does not contain 'result' key"
    assert len(data["result"]) > 0, "No result found for the given ip and port"

    for domain in data["result"]:
        assert (
            domain["ip"] == search_fields["ip"]
        ), "Domain with ID {} does not have an IP {}".format(
            domain["id"], search_fields["ip"]
        )
        domain_id = domain.get("id", None)

        assert domain_id is not None, "Domain Id not found in Response"
        services = Service.objects.filter(domain=domain_id)
        for service in services:
            assert (
                str(service.port) == search_fields["port"]
            ), "Domain with ID {} does not have a service with port {}".format(
                domain_id, vulnerability.service.port
            )


@pytest.mark.django_db(transaction=True, databases=["default", "mini_data_lake"])
def test_search_domains_does_not_exist(user, vulnerability):
    """Test domain by domain not existing."""
    # Test search domains if record does not exist
    response = client.post(
        "/domain/search",
        json={"page": 1, "filters": {"ip": "Does not exist"}, "page_size": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data["result"]) == 0, "No result found for the given organization name"
