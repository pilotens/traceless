import json
import logging

from fastapi.testclient import TestClient


def test_liveness_and_security_headers(client: TestClient) -> None:
    response = client.get("/health/live", headers={"X-Request-ID": "test-request-1"})

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "traceless-api",
        "version": "0.1.0",
    }
    assert response.headers["x-request-id"] == "test-request-1"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert "strict-transport-security" not in response.headers


def test_readiness(client: TestClient) -> None:
    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "checks": {"database": "ready"},
    }


def test_request_observability_logs_bounded_route_metadata(
    client: TestClient,
    caplog,
) -> None:
    caplog.set_level(logging.INFO, logger="traceless.http")

    response = client.get(
        "/health/live?secret_query=must-not-be-logged",
        headers={"X-Request-ID": "observability-test"},
    )

    assert response.status_code == 200
    event = json.loads(caplog.records[-1].message)
    assert event["request_id"] == "observability-test"
    assert event["route"] == "/health/live"
    assert event["status_code"] == 200
    assert "secret_query" not in caplog.records[-1].message
    assert "duration_ms" in event


def test_cors_allows_only_configured_origin(client: TestClient) -> None:
    allowed = client.options(
        "/api/v1/systems",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    denied = client.options(
        "/api/v1/systems",
        headers={
            "Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers


def test_api_root_describes_the_operational_security_boundary(client: TestClient) -> None:
    response = client.get("/api/v1")

    assert response.status_code == 200
    payload = response.json()
    assert payload["data_mode"] == "persistent_operational"
    assert payload["authentication"] == "oidc_or_scoped_service_key"
    assert payload["rbac_implemented"] is True
    assert payload["tenant_isolation_implemented"] is True
    assert payload["external_collection"] == "normalized_pull_connector"


def test_removed_synthetic_routes_are_not_exposed(client: TestClient) -> None:
    assert client.get("/api/v1/portfolio/dashboard").status_code == 404
    assert client.get("/api/v1/systems").status_code == 404
