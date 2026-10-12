"""Integration tests for Phase 8: FastAPI Control Plane Endpoints."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.unit.test_pdp import create_request
from zero_trust.api.app import ControlPlaneState, create_app
from zero_trust.config.settings import Settings


@pytest.fixture
def api_client(temp_db_path: Path) -> TestClient:
    """Fixture returning TestClient wired to isolated database."""
    settings = Settings(
        environment="testing",
        debug=True,
        db_path=temp_db_path,
        jwt_secret_key="test-secret-key-that-is-at-least-32-chars-long!",
    )
    state = ControlPlaneState(settings=settings)
    app = create_app(state)
    return TestClient(app)


def test_health_endpoint(api_client: TestClient) -> None:
    """Verify /health diagnostic probe returns 200 OK."""
    response = api_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["architecture"] == "NIST SP 800-207"


def test_policy_crud_endpoints(api_client: TestClient) -> None:
    """Verify policy creation, listing, and deletion over REST."""
    policy_payload = {
        "policy_id": "POL-API-TEST",
        "name": "API Test Policy",
        "description": "Integration test policy",
        "effect": "PERMIT",
        "priority": 50,
        "min_trust_score": 60.0,
        "allowed_roles": ["engineer"],
        "allowed_departments": ["Engineering"],
        "max_sensitivity": "CRITICAL",
        "require_encryption": True,
        "require_edr": True,
        "conditions": {},
    }

    # Create policy
    create_resp = api_client.post("/api/v1/policies", json=policy_payload)
    assert create_resp.status_code == 201
    assert create_resp.json()["policy_id"] == "POL-API-TEST"

    # List policies
    list_resp = api_client.get("/api/v1/policies")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1

    # Delete policy
    del_resp = api_client.delete("/api/v1/policies/POL-API-TEST")
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "DELETED"

    # Non-existent policy deletion returns 404
    del_404 = api_client.delete("/api/v1/policies/POL-NON-EXISTENT")
    assert del_404.status_code == 404


def test_evaluate_access_allow_and_session_creation(api_client: TestClient) -> None:
    """Verify evaluating access request grants token and tracks active session."""
    # First create matching policy
    policy_payload = {
        "policy_id": "POL-ALLOW-ALL",
        "name": "Allow Policy",
        "effect": "PERMIT",
        "priority": 10,
        "min_trust_score": 50.0,
        "allowed_roles": ["employee"],
        "allowed_departments": [],
        "max_sensitivity": "HIGH",
        "require_encryption": True,
        "require_edr": True,
        "conditions": {},
    }
    api_client.post("/api/v1/policies", json=policy_payload)

    # Submit valid access request
    req = create_request(roles=["employee"])
    req_json = req.model_dump(mode="json")

    eval_resp = api_client.post("/api/v1/access/evaluate", json=req_json)
    assert eval_resp.status_code == 200
    res_data = eval_resp.json()
    assert res_data["decision"] == "ALLOW"
    assert res_data["session_token"] is not None

    # Check that session is listed
    sessions_resp = api_client.get("/api/v1/sessions")
    assert sessions_resp.status_code == 200
    sessions = sessions_resp.json()
    assert len(sessions) == 1
    session_id = sessions[0]["session_id"]

    # Revoke the session
    revoke_resp = api_client.post(
        f"/api/v1/sessions/{session_id}/revoke",
        json={"reason": "Suspicious anomaly detected"},
    )
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["status"] == "REVOKED"

    # Verify session is now excluded from active sessions list
    active_resp = api_client.get("/api/v1/sessions?active_only=true")
    assert len(active_resp.json()) == 0


def test_revoke_non_existent_session(api_client: TestClient) -> None:
    """Verify revoking non-existent session returns 404."""
    resp = api_client.post(
        "/api/v1/sessions/invalid-id/revoke",
        json={"reason": "Test non-existent"},
    )
    assert resp.status_code == 404
