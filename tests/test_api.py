import pytest
from fastapi.testclient import TestClient

from darkwatch import main


TOKEN = "test-token-that-is-at-least-24-chars"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DARKWATCH_API_TOKEN", TOKEN)
    monkeypatch.setenv("DARKWATCH_DB_PATH", str(tmp_path / "test.db"))
    with TestClient(main.app) as test_client:
        yield test_client


def auth():
    return {"Authorization": f"Bearer {TOKEN}"}


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


def create_event(client, **overrides):
    response = client.post("/api/v1/events", headers=auth(), json=sample_event(**overrides))
    assert response.status_code == 201
    return response.json()


def test_health_is_public_and_minimal(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "token" not in response.text.lower()


def test_dashboard_serves_operator_ui(client):
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "DarkWatch Analyst Dashboard" in response.text
    assert "/api/v1/events" in response.text


def test_ingest_requires_authentication(client):
    assert client.post("/api/v1/events", json=sample_event()).status_code == 401


def test_missing_or_short_server_token_fails_closed(client, monkeypatch):
    monkeypatch.setenv("DARKWATCH_API_TOKEN", "short")
    response = client.get("/api/v1/events", headers=auth())
    assert response.status_code == 503


def test_ingest_and_read_event(client):
    event = create_event(client)
    assert event["severity"] == "critical"
    assert event["metadata"] == {"test": True}
    assert event["triage_status"] == "new"
    listed = client.get("/api/v1/events", headers=auth())
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["id"] == event["id"]


def test_ingestion_creates_audit_record(client):
    event = create_event(client)
    with main.db_session() as db:
        rows = db.execute("SELECT action, event_id FROM audit_log").fetchall()
    assert len(rows) == 1
    assert rows[0]["action"] == "event.ingested"
    assert rows[0]["event_id"] == event["id"]


def test_summary_counts_severity_and_triage_status(client):
    create_event(client)
    create_event(client, event_type="firewall_block", title="Firewall blocked traffic")
    response = client.get("/api/v1/summary", headers=auth())
    assert response.status_code == 200
    data = response.json()
    assert data["total_events"] == 2
    assert data["by_severity"]["critical"] == 1
    assert data["by_severity"]["low"] == 1
    assert data["by_status"]["new"] == 2


def test_invalid_event_type_is_rejected(client):
    response = client.post("/api/v1/events", headers=auth(), json=sample_event(event_type="run_arbitrary_command"))
    assert response.status_code == 422


def test_unknown_fields_are_rejected(client):
    response = client.post("/api/v1/events", headers=auth(), json=sample_event(unexpected="nope"))
    assert response.status_code == 422


def test_metadata_size_is_bounded(client):
    response = client.post("/api/v1/events", headers=auth(), json=sample_event(metadata={"large": "x" * 9000}))
    assert response.status_code == 422


def test_limit_is_bounded(client):
    response = client.get("/api/v1/events?limit=201", headers=auth())
    assert response.status_code == 422


def test_severity_filter(client):
    create_event(client)
    create_event(client, event_type="firewall_block", title="Firewall event")
    response = client.get("/api/v1/events?severity=low", headers=auth())
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["severity"] == "low"


def test_search_and_triage_filter(client):
    create_event(client, title="Repeated login failures", event_type="failed_login")
    other = create_event(client, title="Firewall blocked traffic", event_type="firewall_block")
    client.patch(f"/api/v1/events/{other['id']}/status", headers=auth(), json={"triage_status": "investigating"})
    response = client.get("/api/v1/events?q=login&event_type=failed_login&triage_status=new", headers=auth())
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["title"] == "Repeated login failures"


@pytest.mark.parametrize("triage_status", ["new", "investigating", "resolved"])
def test_status_update_is_audited(client, triage_status):
    event = create_event(client)
    response = client.patch(f"/api/v1/events/{event['id']}/status", headers=auth(),
                            json={"triage_status": triage_status})
    assert response.status_code == 200
    assert response.json()["triage_status"] == triage_status
    with main.db_session() as db:
        audit = db.execute("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    assert audit["action"] == f"event.status.{triage_status}"


def test_invalid_status_and_missing_event(client):
    event = create_event(client)
    invalid = client.patch(f"/api/v1/events/{event['id']}/status", headers=auth(),
                           json={"triage_status": "ignored"})
    missing = client.patch("/api/v1/events/999/status", headers=auth(),
                           json={"triage_status": "resolved"})
    assert invalid.status_code == 422
    assert missing.status_code == 404


def test_notes_are_persisted_and_audited(client):
    event = create_event(client)
    response = client.post(f"/api/v1/events/{event['id']}/notes", headers=auth(),
                           json={"note": "Checked synthetic lab evidence."})
    assert response.status_code == 201
    note = response.json()
    assert note["event_id"] == event["id"]
    assert note["note"] == "Checked synthetic lab evidence."
    listed = client.get(f"/api/v1/events/{event['id']}/notes", headers=auth())
    assert listed.status_code == 200
    assert listed.json() == [note]
    with main.db_session() as db:
        audit = db.execute("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    assert audit["action"] == "event.note.added"


def test_blank_note_and_notes_for_missing_event_rejected(client):
    event = create_event(client)
    blank = client.post(f"/api/v1/events/{event['id']}/notes", headers=auth(), json={"note": "  "})
    missing = client.post("/api/v1/events/999/notes", headers=auth(), json={"note": "note"})
    assert blank.status_code == 422
    assert missing.status_code == 404



def test_event_pagination_uses_offset(client):
    first = create_event(client, title="First event")
    second = create_event(client, title="Second event")
    third = create_event(client, title="Third event")

    response = client.get("/api/v1/events?limit=1&offset=1", headers=auth())

    assert response.status_code == 200
    assert [event["id"] for event in response.json()] == [second["id"]]


def test_unicode_case_insensitive_search(client):
    create_event(client, title="Überwachung fehlgeschlagen", event_type="suspicious_process")

    response = client.get("/api/v1/events?q=überwachung", headers=auth())

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["title"] == "Überwachung fehlgeschlagen"


def test_event_pagination_rejects_negative_offset(client):
    response = client.get("/api/v1/events?offset=-1", headers=auth())

    assert response.status_code == 422


def test_old_database_schema_is_migrated(tmp_path, monkeypatch):
    import sqlite3
    db_path = tmp_path / "old.db"
    connection = sqlite3.connect(db_path)
    connection.execute("""CREATE TABLE security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, event_type TEXT NOT NULL,
        title TEXT NOT NULL, description TEXT NOT NULL, source_ip TEXT, severity TEXT NOT NULL,
        metadata_json TEXT NOT NULL, created_at TEXT NOT NULL)""")
    connection.commit()
    connection.close()
    monkeypatch.setenv("DARKWATCH_DB_PATH", str(db_path))
    main.init_db()
    with main.db_session() as db:
        columns = {row["name"] for row in db.execute("PRAGMA table_info(security_events)")}
    assert "triage_status" in columns
