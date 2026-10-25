"""Failure-path tests for DarkWatch's explicit-path SQLite backup helpers."""

import sqlite3

import pytest

from darkwatch.backup import backup_database, verify_database


def test_backup_rejects_missing_source_without_creating_destination(tmp_path):
    source = tmp_path / "missing.db"
    destination = tmp_path / "backup.db"

    with pytest.raises(FileNotFoundError, match="source database does not exist"):
        backup_database(source, destination)

    assert not destination.exists()


def test_backup_rejects_missing_destination_directory_without_creating_files(tmp_path):
    source = tmp_path / "source.db"
    destination = tmp_path / "missing-directory" / "backup.db"
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE synthetic (id INTEGER PRIMARY KEY)")

    with pytest.raises(FileNotFoundError, match="destination directory does not exist"):
        backup_database(source, destination)

    assert source.is_file()
    assert not destination.parent.exists()
    assert not destination.exists()


def test_backup_does_not_modify_source_database(tmp_path):
    source = tmp_path / "source.db"
    destination = tmp_path / "backup.db"
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE synthetic (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT INTO synthetic(value) VALUES ('preserve-me')")

    before = source.read_bytes()
    backup_database(source, destination)

    assert source.read_bytes() == before
    with sqlite3.connect(destination) as db:
        assert db.execute("SELECT value FROM synthetic").fetchone() == ("preserve-me",)


def test_verify_database_rejects_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError, match="SQLite database does not exist"):
        verify_database(tmp_path / "missing.db")


def test_verify_database_rejects_non_sqlite_file(tmp_path):
    invalid_database = tmp_path / "not-a-database.db"
    invalid_database.write_text("not a SQLite database", encoding="utf-8")

    with pytest.raises(sqlite3.DatabaseError):
        verify_database(invalid_database)
