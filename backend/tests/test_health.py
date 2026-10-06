"""Test health check endpoint."""

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_health_check_returns_200():
    """Verify GET /health returns 200 and expected schema."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "scamshield-api"
    assert data["version"] == "0.1.0"


def test_root_endpoint_metadata():
    """Verify GET / returns API metadata."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "ScamShield AI"
    assert "version" in data
