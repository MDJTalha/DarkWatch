"""Focused edge-case tests for the local audit hash-chain verifier."""

import sqlite3

from darkwatch.main import audit_entry_hash, verify_audit_chain


def make_audit_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute(
        """CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY,
            action TEXT NOT NULL,
            event_id INTEGER,
            created_at TEXT NOT NULL,
            actor TEXT,
            previous_hash TEXT,
            entry_hash TEXT
        )"""
    )
    return db


def insert_entry(db, row_id, action, event_id, created_at, actor, previous_hash):
    entry_hash = audit_entry_hash(
        action, event_id, created_at, actor or "legacy", previous_hash
    )
    db.execute(
        """INSERT INTO audit_log
           (id, action, event_id, created_at, actor, previous_hash, entry_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (row_id, action, event_id, created_at, actor, previous_hash, entry_hash),
    )
    return entry_hash


def test_empty_audit_chain_is_valid():
    db = make_audit_db()
    try:
        assert verify_audit_chain(db) == (True, None)
    finally:
        db.close()


def test_verifier_reports_first_row_when_genesis_link_is_wrong():
    db = make_audit_db()
    try:
        insert_entry(db, 7, "event.ingested", 12, "2026-01-01T00:00:00+00:00", "sensor-a", "f" * 64)
        assert verify_audit_chain(db) == (False, 7)
    finally:
        db.close()


def test_verifier_reports_first_row_with_modified_entry_hash():
    db = make_audit_db()
    try:
        insert_entry(db, 1, "event.ingested", 12, "2026-01-01T00:00:00+00:00", "sensor-a", "0" * 64)
        db.execute("UPDATE audit_log SET entry_hash = ? WHERE id = 1", ("a" * 64,))
        assert verify_audit_chain(db) == (False, 1)
    finally:
        db.close()


def test_verifier_accepts_legacy_null_actor_using_legacy_fallback():
    db = make_audit_db()
    try:
        insert_entry(db, 1, "legacy.action", None, "2025-01-01T00:00:00+00:00", None, "0" * 64)
        assert verify_audit_chain(db) == (True, None)
    finally:
        db.close()


def test_verifier_detects_broken_link_after_valid_first_row():
    db = make_audit_db()
    try:
        first_hash = insert_entry(
            db, 1, "event.ingested", 12, "2026-01-01T00:00:00+00:00", "sensor-a", "0" * 64
        )
        insert_entry(
            db, 2, "event.status.resolved", 12, "2026-01-01T00:01:00+00:00", "analyst-a", "b" * 64
        )
        assert first_hash != "b" * 64
        assert verify_audit_chain(db) == (False, 2)
    finally:
        db.close()
