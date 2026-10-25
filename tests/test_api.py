import pytest
from fastapi.testclient import TestClient

from darkwatch import main


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DARKWATCH_API_TOKEN", "test-token-that-is-at-least-24-chars")
    monkeypatch.setenv("DARKWATCH_DB_PATH", str(tmp_path / "test.db"))
    main.init_db()
    with TestClient(main.app) as test_client:
        yield test_client


def auth():
    return {"Authorization": "Bearer test-token-that-is-at-least-24-chars"}


def sample_event(**overrides):
    event = {
        "source": "unit-test-agent",
        "event_type": "malware_detected",
        "title": "Test malware signal",
        "description": "Synthetic event used by automated tests.",
        "source_ip": "192.0.2.15",
        "metadata": {"test": True},
    }
    event.update(overrides)
    return event


def test_health_is_public_and_minimal(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "token" not in response.text.lower()


def test_ingest_requires_authentication(client):
    assert client.post("/api/v1/events", json=sample_event()).status_code == 401


def test_ingest_and_read_event(client):
    created = client.post("/api/v1/events", headers=auth(), json=sample_event())
    assert created.status_code == 201
    event = created.json()
    assert event["severity"] == "critical"
    assert event["metadata"] == {"test": True}
    listed = client.get("/api/v1/events", headers=auth())
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["id"] == event["id"]


def test_summary_counts_events_by_severity(client):
    client.post("/api/v1/events", headers=auth(), json=sample_event())
    client.post("/api/v1/events", headers=auth(), json=sample_event(
        event_type="firewall_block", title="Firewall blocked traffic"))
    response = client.get("/api/v1/summary", headers=auth())
    assert response.status_code == 200
    data = response.json()
    assert data["total_events"] == 2
    assert data["by_severity"]["critical"] == 1
    assert data["by_severity"]["low"] == 1


def test_invalid_event_type_is_rejected(client):
    response = client.post("/api/v1/events", headers=auth(), json=sample_event(
        event_type="run_arbitrary_command"))
    assert response.status_code == 422


def test_unknown_fields_are_rejected(client):
    response = client.post("/api/v1/events", headers=auth(), json=sample_event(unexpected="nope"))
    assert response.status_code == 422


def test_limit_is_bounded(client):
    response = client.get("/api/v1/events?limit=201", headers=auth())
    assert response.status_code == 422


def test_severity_filter(client):
    client.post("/api/v1/events", headers=auth(), json=sample_event())
    client.post("/api/v1/events", headers=auth(), json=sample_event(
        event_type="firewall_block", title="Firewall event"))
    response = client.get("/api/v1/events?severity=low", headers=auth())
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["severity"] == "low"
