import pytest
from fastapi.testclient import TestClient

from darkwatch import main


TOKEN = "test-token-that-is-at-least-24-chars"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DARKWATCH_API_TOKEN", TOKEN)
    monkeypatch.delenv("DARKWATCH_API_TOKENS", raising=False)
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
    assert 'id="eventType"' in response.text
    assert "event_type" in response.text


def test_security_headers_are_set_on_dashboard_and_api(client):
    dashboard = client.get("/dashboard")
    assert dashboard.headers["x-content-type-options"] == "nosniff"
    assert dashboard.headers["x-frame-options"] == "DENY"
    assert dashboard.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in dashboard.headers["content-security-policy"]
    assert dashboard.headers["cache-control"] == "no-store"

    api = client.get("/api/v1/events", headers=auth())
    assert api.status_code == 200
    assert api.headers["x-content-type-options"] == "nosniff"
    assert api.headers["cache-control"] == "no-store"


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
        rows = db.execute("SELECT action, event_id, actor FROM audit_log").fetchall()
    assert len(rows) == 1
    assert rows[0]["action"] == "event.ingested"
    assert rows[0]["event_id"] == event["id"]
    assert rows[0]["actor"] == "legacy-shared-token"


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



def test_event_type_filter_normalizes_case_and_whitespace(client):
    event = create_event(client, event_type="suspicious_process")

    response = client.get(
        "/api/v1/events?event_type=%20SUSPICIOUS_PROCESS%20",
        headers=auth(),
    )

    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == [event["id"]]


def test_event_type_filter_rejects_unsupported_values(client):
    response = client.get("/api/v1/events?event_type=unknown_type", headers=auth())

    assert response.status_code == 422
    assert response.json()["detail"] == "Unsupported event_type."



def test_source_ip_is_validated_and_canonicalized(client):
    event = create_event(client, source_ip="2001:0db8:0:0:0:0:0:1")

    assert event["source_ip"] == "2001:db8::1"


def test_invalid_source_ip_is_rejected(client):
    response = client.post(
        "/api/v1/events",
        headers=auth(),
        json=sample_event(source_ip="not-an-ip-address"),
    )

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
        versions = {row["version"] for row in db.execute("SELECT version FROM schema_migrations")}
    assert "triage_status" in columns
    assert versions == {1, 2, 3, 4, 5}
    with main.db_session() as db:
        indexes = {item["name"] for item in db.execute("PRAGMA index_list(security_events)")}
    assert "idx_events_event_type" in indexes


def test_search_finds_matching_event_beyond_first_200_records(client):
    with main.db_session() as db:
        db.execute(
            """INSERT INTO security_events
            (source, event_type, title, description, source_ip, severity,
             metadata_json, created_at, triage_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("legacy-agent", "other", "Needle in older record", "older matching record",
             None, "informational", "{}", "2026-01-01T00:00:00+00:00", "new"),
        )
        db.executemany(
            """INSERT INTO security_events
            (source, event_type, title, description, source_ip, severity,
             metadata_json, created_at, triage_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                ("recent-agent", "other", f"Unrelated event {index}", "no match",
                 None, "informational", "{}", f"2026-02-{(index % 28) + 1:02d}T00:00:00+00:00", "new")
                for index in range(205)
            ],
        )

    response = client.get("/api/v1/events?q=Needle&limit=50", headers=auth())

    assert response.status_code == 200
    assert [event["title"] for event in response.json()] == ["Needle in older record"]


def test_search_treats_sql_like_payload_as_plain_text(client):
    create_event(client, title="Normal event")
    create_event(client, title="Event with ' OR 1=1 -- text")

    response = client.get("/api/v1/events?q=%27%20OR%201%3D1%20--", headers=auth())

    assert response.status_code == 200
    assert [event["title"] for event in response.json()] == ["Event with ' OR 1=1 -- text"]

def test_database_transaction_rolls_back_related_writes_on_failure(client):
    import sqlite3

    create_event(client)
    with main.db_session() as db:
        before = db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]

    with pytest.raises(sqlite3.IntegrityError):
        with main.db_session() as db:
            db.execute(
                "INSERT INTO audit_log(action, event_id, created_at) VALUES (?, ?, ?)",
                ("test.must-rollback", 1, "2026-01-01T00:00:00+00:00"),
            )
            db.execute(
                "INSERT INTO audit_log(action, event_id, created_at) VALUES (?, ?, ?)",
                ("test.invalid-reference", 999999, "2026-01-01T00:00:00+00:00"),
            )

    with main.db_session() as db:
        after = db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        rolled_back = db.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = ?",
            ("test.must-rollback",),
        ).fetchone()[0]
    assert after == before
    assert rolled_back == 0


def test_schema_migration_is_idempotent_and_preserves_existing_events(tmp_path, monkeypatch):
    import sqlite3

    db_path = tmp_path / "legacy-idempotent.db"
    connection = sqlite3.connect(db_path)
    connection.execute("""CREATE TABLE security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, event_type TEXT NOT NULL,
        title TEXT NOT NULL, description TEXT NOT NULL, source_ip TEXT, severity TEXT NOT NULL,
        metadata_json TEXT NOT NULL, created_at TEXT NOT NULL)""")
    connection.execute(
        """INSERT INTO security_events
        (source, event_type, title, description, source_ip, severity, metadata_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        ("legacy-agent", "other", "Preserve this event", "legacy row", None,
         "informational", "{}", "2026-01-01T00:00:00+00:00"),
    )
    connection.commit()
    connection.close()
    monkeypatch.setenv("DARKWATCH_DB_PATH", str(db_path))

    main.init_db()
    main.init_db()

    with main.db_session() as db:
        row = db.execute(
            "SELECT title, triage_status FROM security_events WHERE id = 1"
        ).fetchone()
        columns = {item["name"] for item in db.execute("PRAGMA table_info(security_events)")}
    assert row["title"] == "Preserve this event"
    assert row["triage_status"] == "new"
    assert "triage_status" in columns
    with main.db_session() as db:
        versions = {item["version"] for item in db.execute("SELECT version FROM schema_migrations")}
    assert versions == {1, 2, 3, 4, 5}

@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("get", "/api/v1/events", None),
        ("get", "/api/v1/summary", None),
        ("post", "/api/v1/events", sample_event()),
        ("patch", "/api/v1/events/1/status", {"triage_status": "resolved"}),
        ("post", "/api/v1/events/1/notes", {"note": "unauthorized note"}),
        ("get", "/api/v1/events/1/notes", None),
    ],
)
def test_all_data_routes_require_bearer_authentication(client, method, path, body):
    response = getattr(client, method)(path, json=body) if body is not None else getattr(client, method)(path)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"



def test_named_analyst_token_records_actor_and_role(client, monkeypatch):
    import json
    named_token = "named-analyst-token-that-is-long-enough"
    monkeypatch.setenv("DARKWATCH_API_TOKENS", json.dumps([
        {"token": named_token, "username": "analyst.alice", "role": "analyst"}
    ]))
    response = client.post(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {named_token}"},
        json=sample_event(),
    )
    assert response.status_code == 201
    with main.db_session() as db:
        audit = db.execute("SELECT actor FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    assert audit["actor"] == "analyst.alice"


def test_viewer_cannot_change_triage_status(client, monkeypatch):
    import json
    event = create_event(client)
    viewer_token = "named-viewer-token-that-is-long-enough"
    monkeypatch.setenv("DARKWATCH_API_TOKENS", json.dumps([
        {"token": viewer_token, "username": "read.only", "role": "viewer"}
    ]))
    response = client.patch(
        f"/api/v1/events/{event['id']}/status",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"triage_status": "resolved"},
    )
    assert response.status_code == 403


def test_named_token_configuration_disables_legacy_shared_token(client, monkeypatch):
    import json
    monkeypatch.setenv("DARKWATCH_API_TOKENS", json.dumps([
        {"token": "another-valid-named-token-value", "username": "viewer.one", "role": "viewer"}
    ]))
    response = client.get("/api/v1/events", headers=auth())
    assert response.status_code == 401


def test_legacy_audit_schema_migrates_actor_column(tmp_path, monkeypatch):
    import sqlite3
    db_path = tmp_path / "legacy-audit.db"
    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE security_events (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, event_type TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, source_ip TEXT, severity TEXT NOT NULL, metadata_json TEXT NOT NULL, created_at TEXT NOT NULL, triage_status TEXT NOT NULL DEFAULT 'new')")
    connection.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, event_id INTEGER, created_at TEXT NOT NULL, FOREIGN KEY(event_id) REFERENCES security_events(id))")
    connection.commit()
    connection.close()
    monkeypatch.setenv("DARKWATCH_DB_PATH", str(db_path))
    main.init_db()
    with main.db_session() as db:
        columns = {row["name"] for row in db.execute("PRAGMA table_info(audit_log)")}
    assert "actor" in columns


def test_request_body_limit_rejects_oversized_json(client):
    oversized = sample_event(description="x" * (17 * 1024))
    response = client.post("/api/v1/events", headers=auth(), json=oversized)
    assert response.status_code == 413
    assert "16384-byte limit" in response.text


def test_named_token_config_rejects_invalid_role_type(client, monkeypatch):
    import json
    monkeypatch.setenv("DARKWATCH_API_TOKENS", json.dumps([
        {"token": "another-valid-named-token-value", "username": "broken.user", "role": []}
    ]))
    response = client.get("/api/v1/events", headers=auth())
    assert response.status_code == 503


def test_sqlite_backup_is_consistent_and_verifiable(tmp_path):
    import sqlite3
    from darkwatch.backup import backup_database, verify_database

    source = tmp_path / "source.db"
    destination = tmp_path / "backups" / "backup.db"
    destination.parent.mkdir()
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE security_events (id INTEGER PRIMARY KEY, title TEXT NOT NULL)")
        db.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY, action TEXT NOT NULL)")
        db.execute("CREATE TABLE analyst_notes (id INTEGER PRIMARY KEY, note TEXT NOT NULL)")
        db.execute("INSERT INTO security_events VALUES (1, 'synthetic test event')")
        db.execute("INSERT INTO audit_log VALUES (1, 'synthetic test action')")
        db.execute("INSERT INTO analyst_notes VALUES (1, 'synthetic test note')")

    result = backup_database(source, destination)
    assert result == destination.resolve()
    assert verify_database(destination) == {
        "integrity": "ok",
        "security_events": 1,
        "audit_log": 1,
        "analyst_notes": 1,
    }
    with sqlite3.connect(destination) as restored:
        assert restored.execute("SELECT title FROM security_events WHERE id = 1").fetchone()[0] == "synthetic test event"
        assert restored.execute("SELECT action FROM audit_log WHERE id = 1").fetchone()[0] == "synthetic test action"
        assert restored.execute("SELECT note FROM analyst_notes WHERE id = 1").fetchone()[0] == "synthetic test note"
    with pytest.raises(FileExistsError):
        backup_database(source, destination)


def test_sqlite_backup_refuses_same_source_and_destination(tmp_path):
    from darkwatch.backup import backup_database

    source = tmp_path / "same.db"
    source.touch()
    with pytest.raises(ValueError):
        backup_database(source, source)


def test_request_body_limit_rejects_oversized_stream_without_content_length():
    import asyncio
    from darkwatch.main import RequestBodyLimitMiddleware

    async def downstream(scope, receive, send):
        await receive()
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"accepted"})

    messages = [
        {"type": "http.request", "body": b"a" * 10, "more_body": True},
        {"type": "http.request", "body": b"b" * 10, "more_body": False},
    ]
    sent = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "headers": []}
    middleware = RequestBodyLimitMiddleware(downstream, max_body_bytes=16)
    asyncio.run(middleware(scope, receive, send))
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 413
    assert b"16-byte limit" in sent[1]["body"]


def test_audit_hash_chain_detects_tampering(client):
    from darkwatch.main import verify_audit_chain

    event = create_event(client)
    response = client.patch(
        f"/api/v1/events/{event['id']}/status",
        headers=auth(),
        json={"triage_status": "investigating"},
    )
    assert response.status_code == 200
    with main.db_session() as db:
        assert verify_audit_chain(db) == (True, None)
        db.execute("UPDATE audit_log SET action = 'tampered.action' WHERE id = 1")
        assert verify_audit_chain(db)[0] is False


def test_audit_hash_chain_links_records_in_order(client):
    from darkwatch.main import verify_audit_chain

    event = create_event(client)
    client.patch(
        f"/api/v1/events/{event['id']}/status",
        headers=auth(),
        json={"triage_status": "resolved"},
    )
    with main.db_session() as db:
        rows = db.execute(
            "SELECT previous_hash, entry_hash FROM audit_log ORDER BY id ASC"
        ).fetchall()
        assert len(rows) == 2
        assert rows[1]["previous_hash"] == rows[0]["entry_hash"]
        assert verify_audit_chain(db) == (True, None)


def test_audit_chain_migration_backfills_existing_rows(tmp_path, monkeypatch):
    import sqlite3
    db_path = tmp_path / "audit-backfill.db"
    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE security_events (id INTEGER PRIMARY KEY, source TEXT NOT NULL, event_type TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, source_ip TEXT, severity TEXT NOT NULL, metadata_json TEXT NOT NULL, created_at TEXT NOT NULL, triage_status TEXT NOT NULL DEFAULT 'new')")
    connection.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY, action TEXT NOT NULL, event_id INTEGER, created_at TEXT NOT NULL)")
    connection.execute("INSERT INTO security_events VALUES (1, 'test', 'other', 'test event', '', NULL, 'informational', '{}', '2026-01-01T00:00:00+00:00', 'new')")
    connection.execute("INSERT INTO audit_log VALUES (1, 'legacy.action', 1, '2026-01-01T00:00:01+00:00')")
    connection.commit()
    connection.close()
    monkeypatch.setenv("DARKWATCH_DB_PATH", str(db_path))
    main.init_db()
    with main.db_session() as db:
        row = db.execute("SELECT actor, previous_hash, entry_hash FROM audit_log WHERE id = 1").fetchone()
        assert row["actor"] == "legacy"
        assert row["previous_hash"] == "0" * 64
        assert len(row["entry_hash"]) == 64
        assert main.verify_audit_chain(db) == (True, None)
