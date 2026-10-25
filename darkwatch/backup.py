"""Safe SQLite backup and verification helpers for DarkWatch.

This module intentionally operates only on explicit paths. It never selects or
modifies the application's configured database implicitly.
"""
from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path


def backup_database(source_path: str | Path, destination_path: str | Path) -> Path:
    """Create a consistent SQLite backup without overwriting an existing file."""
    source = Path(source_path).expanduser().resolve()
    destination = Path(destination_path).expanduser().resolve()
    if source == destination:
        raise ValueError("Source and destination must be different paths.")
    if not source.is_file():
        raise FileNotFoundError(f"SQLite source database does not exist: {source}")
    if destination.exists():
        raise FileExistsError(f"Backup destination already exists: {destination}")
    if not destination.parent.is_dir():
        raise FileNotFoundError(f"Backup destination directory does not exist: {destination.parent}")

    created_destination = False
    try:
        source_uri = source.as_uri() + "?mode=ro"
        with sqlite3.connect(source_uri, uri=True, timeout=10) as source_db:
            with sqlite3.connect(str(destination), timeout=10) as backup_db:
                created_destination = True
                source_db.backup(backup_db)
                integrity = backup_db.execute("PRAGMA integrity_check").fetchone()[0]
                if integrity != "ok":
                    raise sqlite3.DatabaseError(f"Backup integrity check failed: {integrity}")
                foreign_key_errors = backup_db.execute("PRAGMA foreign_key_check").fetchall()
                if foreign_key_errors:
                    raise sqlite3.DatabaseError("Backup contains foreign-key violations.")
        return destination
    except Exception:
        if created_destination:
            destination.unlink(missing_ok=True)
        raise


def verify_database(path: str | Path) -> dict[str, int | str]:
    """Check a database's integrity and return basic event/audit/note counts."""
    database = Path(path).expanduser().resolve()
    if not database.is_file():
        raise FileNotFoundError(f"SQLite database does not exist: {database}")
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=10) as db:
        integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise sqlite3.DatabaseError(f"SQLite integrity check failed: {integrity}")
        foreign_key_errors = db.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_key_errors:
            raise sqlite3.DatabaseError("SQLite database contains foreign-key violations.")
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        counts: dict[str, int | str] = {"integrity": integrity}
        for table in ("security_events", "audit_log", "analyst_notes"):
            counts[table] = int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) if table in tables else 0
        return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Create and verify an explicit-path DarkWatch SQLite backup.")
    parser.add_argument("--source", required=True, help="Existing SQLite database path")
    parser.add_argument("--destination", required=True, help="New backup path; must not already exist")
    args = parser.parse_args()
    backup_path = backup_database(args.source, args.destination)
    result = verify_database(backup_path)
    print(f"Backup verified: {backup_path}")
    print(f"Integrity: {result['integrity']}")
    print(f"Events: {result['security_events']}; audit rows: {result['audit_log']}; notes: {result['analyst_notes']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
