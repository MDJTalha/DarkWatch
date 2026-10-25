"""DarkWatch Phase 1 API.

Stores normalized events supplied by trusted integrations. Does not scan networks,
execute submitted commands, or claim to prevent attacks.
"""
import hmac
import json
import os
import sqlite3
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Iterator, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

APP_VERSION = "0.1.0"
EVENT_TYPES = {
    "failed_login", "malware_detected", "suspicious_process", "firewall_block",
    "configuration_change", "data_exfiltration_suspected", "other",
}
SEVERITY_BY_TYPE = {
    "failed_login": "medium", "malware_detected": "critical",
    "suspicious_process": "high", "firewall_block": "low",
    "configuration_change": "medium", "data_exfiltration_suspected": "critical",
    "other": "informational",
}
Severity = Literal["informational", "low", "medium", "high", "critical"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def database_path() -> Path:
    return Path(os.getenv("DARKWATCH_DB_PATH", "./data/darkwatch.db")).expanduser()


def connect_db() -> sqlite3.Connection:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


@contextmanager
def db_session() -> Iterator[sqlite3.Connection]:
    connection = connect_db()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    with db_session() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL, event_type TEXT NOT NULL, title TEXT NOT NULL,
            description TEXT NOT NULL, source_ip TEXT, severity TEXT NOT NULL,
            metadata_json TEXT NOT NULL, created_at TEXT NOT NULL)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_events_created_at ON security_events(created_at DESC)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity)")
        db.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, event_id INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(event_id) REFERENCES security_events(id))""")


class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(min_length=1, max_length=120)
    event_type: str
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    source_ip: str | None = Field(default=None, max_length=45)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source", "title")
    @classmethod
    def reject_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value.strip()

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in EVENT_TYPES:
            raise ValueError("unsupported event_type")
        return normalized

    @field_validator("metadata")
    @classmethod
    def limit_metadata_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        if len(encoded) > 8000:
            raise ValueError("metadata must serialize to 8000 characters or fewer")
        return value


class EventOut(BaseModel):
    id: int
    source: str
    event_type: str
    title: str
    description: str
    source_ip: str | None
    severity: Severity
    metadata: dict[str, Any]
    created_at: str


class SummaryOut(BaseModel):
    total_events: int
    by_severity: dict[str, int]


def require_api_token(authorization: str | None = Header(default=None)) -> None:
    configured = os.getenv("DARKWATCH_API_TOKEN", "")
    if len(configured) < 24:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured with a sufficiently long token.",
        )
    expected = f"Bearer {configured}"
    supplied_bytes = authorization.encode("utf-8") if authorization is not None else b""
    if not hmac.compare_digest(supplied_bytes, expected.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"], "source": row["source"], "event_type": row["event_type"],
        "title": row["title"], "description": row["description"],
        "source_ip": row["source_ip"], "severity": row["severity"],
        "metadata": json.loads(row["metadata_json"]), "created_at": row["created_at"],
    }


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


app = FastAPI(
    title="DarkWatch API",
    description="Defensive security event ingestion and triage foundation.",
    version=APP_VERSION,
    lifespan=lifespan,
)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    """Minimal liveness endpoint; reveals no secrets or internal configuration."""
    return {"status": "ok", "service": "darkwatch", "version": APP_VERSION}


@app.post(
    "/api/v1/events", response_model=EventOut, status_code=status.HTTP_201_CREATED,
    tags=["events"], dependencies=[Depends(require_api_token)],
)
def ingest_event(payload: EventIn) -> dict[str, Any]:
    severity = SEVERITY_BY_TYPE[payload.event_type]
    created_at = utc_now()
    with db_session() as db:
        cursor = db.execute(
            """INSERT INTO security_events
            (source, event_type, title, description, source_ip, severity, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (payload.source, payload.event_type, payload.title, payload.description,
             payload.source_ip, severity,
             json.dumps(payload.metadata, ensure_ascii=True, separators=(",", ":")), created_at),
        )
        event_id = int(cursor.lastrowid)
        db.execute(
            "INSERT INTO audit_log(action, event_id, created_at) VALUES (?, ?, ?)",
            ("event.ingested", event_id, created_at),
        )
        row = db.execute("SELECT * FROM security_events WHERE id = ?", (event_id,)).fetchone()
        assert row is not None
        return row_to_event(row)


@app.get(
    "/api/v1/events", response_model=list[EventOut], tags=["events"],
    dependencies=[Depends(require_api_token)],
)
def list_events(
    limit: int = Query(default=50, ge=1, le=200),
    severity: Severity | None = None,
) -> list[dict[str, Any]]:
    with db_session() as db:
        if severity:
            rows = db.execute(
                "SELECT * FROM security_events WHERE severity = ? ORDER BY id DESC LIMIT ?",
                (severity, limit),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [row_to_event(row) for row in rows]


@app.get(
    "/api/v1/summary", response_model=SummaryOut, tags=["analytics"],
    dependencies=[Depends(require_api_token)],
)
def summary() -> dict[str, Any]:
    with db_session() as db:
        total = db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        counts = {s: 0 for s in ("informational", "low", "medium", "high", "critical")}
        for row in db.execute(
            "SELECT severity, COUNT(*) AS count FROM security_events GROUP BY severity"
        ).fetchall():
            counts[row["severity"]] = row["count"]
        return {"total_events": total, "by_severity": counts}
