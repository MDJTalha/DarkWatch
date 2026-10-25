"""Migration failure-path tests using disposable SQLite databases."""

import sqlite3

import pytest

from darkwatch import main


def test_failed_migration_does_not_record_unapplied_versions(tmp_path, monkeypatch):
    db_path = tmp_path / "broken-legacy.db"
    with sqlite3.connect(db_path) as db:
        db.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        # Deliberately inconsistent legacy state: version 1 is recorded, but its
        # required security_events table is absent. Migration 2 must fail closed.
        db.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (1, 'synthetic')"
        )

    monkeypatch.setenv("DARKWATCH_DB_PATH", str(db_path))

    with pytest.raises(sqlite3.OperationalError, match="no such table: security_events"):
        main.init_db()

    with sqlite3.connect(db_path) as db:
        versions = {row[0] for row in db.execute("SELECT version FROM schema_migrations")}
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}

    assert versions == {1}
    assert "security_events" not in tables
    assert "audit_log" not in tables


def test_future_schema_version_refusal_leaves_database_unchanged(tmp_path, monkeypatch):
    db_path = tmp_path / "future-schema.db"
    with sqlite3.connect(db_path) as db:
        db.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        db.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (999, 'synthetic')"
        )
        db.execute("CREATE TABLE sentinel (value TEXT NOT NULL)")
        db.execute("INSERT INTO sentinel(value) VALUES ('preserve')")

    monkeypatch.setenv("DARKWATCH_DB_PATH", str(db_path))

    with pytest.raises(RuntimeError, match="newer than this application supports"):
        main.init_db()

    with sqlite3.connect(db_path) as db:
        versions = db.execute("SELECT version, applied_at FROM schema_migrations").fetchall()
        sentinel = db.execute("SELECT value FROM sentinel").fetchall()
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}

    assert versions == [(999, "synthetic")]
    assert sentinel == [("preserve",)]
    assert tables == {"schema_migrations", "sentinel"}
