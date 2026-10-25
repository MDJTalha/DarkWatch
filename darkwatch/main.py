"""DarkWatch Phase 2 API: defensive event intake and analyst workflow."""
import hmac
import ipaddress
import json
import os
import sqlite3
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Iterator, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

APP_VERSION = "0.2.0"
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
TriageStatus = Literal["new", "investigating", "resolved"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def database_path() -> Path:
    return Path(os.getenv("DARKWATCH_DB_PATH", "./data/darkwatch.db")).expanduser()


def connect_db() -> sqlite3.Connection:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.create_function(
        "unicode_casefold", 1,
        lambda value: str(value).casefold() if value is not None else "",
        deterministic=True,
    )
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
            metadata_json TEXT NOT NULL, created_at TEXT NOT NULL,
            triage_status TEXT NOT NULL DEFAULT 'new')""")
        columns = {row["name"] for row in db.execute("PRAGMA table_info(security_events)")}
        if "triage_status" not in columns:
            db.execute("ALTER TABLE security_events ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'new'")
        db.execute("CREATE INDEX IF NOT EXISTS idx_events_created_at ON security_events(created_at DESC)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_events_status ON security_events(triage_status)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_events_event_type ON security_events(event_type)")
        db.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, event_id INTEGER,
            created_at TEXT NOT NULL, actor TEXT NOT NULL DEFAULT 'legacy',
            FOREIGN KEY(event_id) REFERENCES security_events(id))""")
        audit_columns = {row["name"] for row in db.execute("PRAGMA table_info(audit_log)")}
        if "actor" not in audit_columns:
            db.execute("ALTER TABLE audit_log ADD COLUMN actor TEXT NOT NULL DEFAULT 'legacy'")
        db.execute("""CREATE TABLE IF NOT EXISTS analyst_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL,
            note TEXT NOT NULL, created_at TEXT NOT NULL,
            FOREIGN KEY(event_id) REFERENCES security_events(id) ON DELETE CASCADE)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_notes_event_id ON analyst_notes(event_id, id)")


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

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("source_ip must be a valid IPv4 or IPv6 address")
        try:
            return str(ipaddress.ip_address(normalized))
        except ValueError as exc:
            raise ValueError("source_ip must be a valid IPv4 or IPv6 address") from exc

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
    triage_status: TriageStatus


class StatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    triage_status: TriageStatus


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: str = Field(min_length=1, max_length=4000)

    @field_validator("note")
    @classmethod
    def reject_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("note must not be blank")
        return value.strip()


class NoteOut(BaseModel):
    id: int
    event_id: int
    note: str
    created_at: str


class SummaryOut(BaseModel):
    total_events: int
    by_severity: dict[str, int]
    by_status: dict[str, int]


ALLOWED_ROLES = {"admin", "analyst", "ingestor", "viewer"}


def configured_analysts() -> list[dict[str, str]] | None:
    """Load named identities from a secret-injected JSON array; never log token values."""
    raw = os.getenv("DARKWATCH_API_TOKENS")
    if raw is None:
        return None
    try:
        entries = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail="Named API token configuration is invalid.") from exc
    if not isinstance(entries, list) or not entries:
        raise HTTPException(status_code=503, detail="Named API token configuration must be a non-empty JSON array.")
    seen_users: set[str] = set()
    seen_tokens: set[str] = set()
    normalized: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise HTTPException(status_code=503, detail="Named API token configuration is invalid.")
        token, username, role = entry.get("token"), entry.get("username"), entry.get("role")
        if not isinstance(token, str) or len(token) < 24 or not isinstance(username, str) or not username.strip() or len(username) > 100 or not isinstance(role, str) or role not in ALLOWED_ROLES:
            raise HTTPException(status_code=503, detail="Each named API identity requires a token of at least 24 characters, username, and supported role.")
        username = username.strip()
        if username in seen_users or token in seen_tokens:
            raise HTTPException(status_code=503, detail="Named API usernames and tokens must be unique.")
        seen_users.add(username)
        seen_tokens.add(token)
        normalized.append({"token": token, "username": username, "role": role})
    return normalized


def require_api_token(request: Request, authorization: str | None = Header(default=None)) -> dict[str, str]:
    named = configured_analysts()
    supplied = authorization.removeprefix("Bearer ") if authorization and authorization.startswith("Bearer ") else ""
    identity = None
    if named is not None:
        for entry in named:
            if hmac.compare_digest(supplied.encode("utf-8"), entry["token"].encode("utf-8")):
                identity = {"username": entry["username"], "role": entry["role"]}
    else:
        configured = os.getenv("DARKWATCH_API_TOKEN", "")
        if len(configured) < 24:
            raise HTTPException(status_code=503, detail="API authentication is not configured with a sufficiently long token.")
        if hmac.compare_digest(supplied.encode("utf-8"), configured.encode("utf-8")):
            identity = {"username": "legacy-shared-token", "role": "admin"}
    if identity is None:
        raise HTTPException(status_code=401, detail="Invalid or missing bearer token.", headers={"WWW-Authenticate": "Bearer"})
    request.state.analyst = identity
    return identity


def require_roles(*roles: str):
    def dependency(identity: dict[str, str] = Depends(require_api_token)) -> dict[str, str]:
        if identity["role"] not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role for this operation.")
        return identity
    return dependency


def row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"], "source": row["source"], "event_type": row["event_type"],
        "title": row["title"], "description": row["description"],
        "source_ip": row["source_ip"], "severity": row["severity"],
        "metadata": json.loads(row["metadata_json"]), "created_at": row["created_at"],
        "triage_status": row["triage_status"],
    }


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


app = FastAPI(title="DarkWatch API", description="Defensive security event ingestion and triage foundation.",
              version=APP_VERSION, lifespan=lifespan)


class RequestBodyLimitMiddleware:
    """Enforce a hard cap while receiving request chunks, including chunked requests."""

    def __init__(self, app, max_body_bytes: int = 16 * 1024):
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        content_length = next(
            (value for key, value in scope.get("headers", []) if key.lower() == b"content-length"),
            None,
        )
        if content_length is not None:
            try:
                if int(content_length) > self.max_body_bytes:
                    body = b'{"detail":"Request body exceeds 16384-byte limit."}'
                    await send({"type": "http.response.start", "status": 413,
                                "headers": [(b"content-type", b"application/json"),
                                            (b"content-length", str(len(body)).encode("ascii"))]})
                    await send({"type": "http.response.body", "body": body})
                    return
            except ValueError:
                body = b'{"detail":"Invalid Content-Length header."}'
                await send({"type": "http.response.start", "status": 400,
                            "headers": [(b"content-type", b"application/json"),
                                        (b"content-length", str(len(body)).encode("ascii"))]})
                await send({"type": "http.response.body", "body": body})
                return

        received = 0
        too_large = False
        response_started = False
        too_large_body = b'{"detail":"Request body exceeds 16384-byte limit."}'

        async def limited_receive():
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    too_large = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        async def limited_send(message):
            nonlocal response_started
            if too_large:
                if message["type"] == "http.response.start" and not response_started:
                    response_started = True
                    await send({"type": "http.response.start", "status": 413,
                                "headers": [(b"content-type", b"application/json"),
                                            (b"content-length", str(len(too_large_body)).encode("ascii"))]})
                elif message["type"] == "http.response.body" and response_started:
                    await send({"type": "http.response.body", "body": too_large_body, "more_body": False})
                return
            await send(message)

        await self.app(scope, limited_receive, limited_send)

app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=16 * 1024)


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.url.path.startswith("/api/") or request.url.path == "/dashboard":
        response.headers["Cache-Control"] = "no-store"
    if request.url.path == "/dashboard":
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self' data:; form-action 'self'; "
            "base-uri 'none'; frame-ancestors 'none'"
        )
    return response


def get_event(db: sqlite3.Connection, event_id: int) -> sqlite3.Row:
    row = db.execute("SELECT * FROM security_events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Event not found.")
    return row


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "darkwatch", "version": APP_VERSION}


@app.get("/dashboard", response_class=HTMLResponse, tags=["dashboard"])
def dashboard() -> str:
    """Small local dashboard; token is entered by the operator and kept in page memory only."""
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DarkWatch Analyst Dashboard</title><style>
body{font:16px system-ui,sans-serif;background:#101820;color:#eef3f6;margin:0;padding:24px}main{max-width:1100px;margin:auto}
h1{color:#66d9c8}input,select,button{font:inherit;padding:10px;margin:4px;border-radius:6px;border:1px solid #52616b;background:#192832;color:#fff}
button{cursor:pointer;background:#176b61}table{border-collapse:collapse;width:100%;margin-top:18px}th,td{text-align:left;padding:10px;border-bottom:1px solid #354650;vertical-align:top}
.cards{display:flex;gap:12px;flex-wrap:wrap}.card{background:#192832;padding:16px;border-radius:8px;min-width:130px}
small{color:#b9c8ce}.error{color:#ff9b9b}form{margin:12px 0}.wrap{overflow:auto}
</style></head><body><main><h1>DarkWatch</h1><p>Security event triage · local operator dashboard</p>
<form id="auth"><label>API token <input id="token" type="password" autocomplete="current-password" required minlength="24"></label><button>Connect</button></form>
<p id="message" role="status">Enter your configured API token to load stored events. Token is not saved.</p>
<div class="cards" id="summary"></div><form id="filters"><input id="q" placeholder="Search title, source, description">
<select id="severity"><option value="">All severities</option><option>informational</option><option>low</option><option>medium</option><option>high</option><option>critical</option></select>
<select id="state"><option value="">All statuses</option><option>new</option><option>investigating</option><option>resolved</option></select><select id="eventType"><option value="">All event types</option><option value="failed_login">Failed login</option><option value="malware_detected">Malware detected</option><option value="suspicious_process">Suspicious process</option><option value="firewall_block">Firewall block</option><option value="configuration_change">Configuration change</option><option value="data_exfiltration_suspected">Suspected data exfiltration</option><option value="other">Other</option></select><button>Apply filters</button></form>
<div><button id="previous" type="button" disabled>Previous</button> <span id="pageInfo" aria-live="polite">Page 1</span> <button id="next" type="button" disabled>Next</button></div>
<div class="wrap"><table><thead><tr><th>ID / Time</th><th>Event</th><th>Severity</th><th>Triage</th><th>Actions</th></tr></thead><tbody id="events"></tbody></table></div>
<script>
let token='', offset=0, pageSize=50; const el=id=>document.getElementById(id);
async function api(path,options={}){const r=await fetch(path,{...options,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json',...(options.headers||{})}});if(!r.ok)throw new Error((await r.text()).slice(0,300));return r.json()}
function message(s,bad=false){el('message').textContent=s;el('message').className=bad?'error':''}
async function load(){try{const q=el('q').value.trim(),sev=el('severity').value,state=el('state').value,eventType=el('eventType').value;const params=new URLSearchParams({limit:String(pageSize+1),offset:String(offset)});if(q)params.set('q',q);if(sev)params.set('severity',sev);if(state)params.set('triage_status',state);if(eventType)params.set('event_type',eventType);const [summary,events]=await Promise.all([api('/api/v1/summary'),api('/api/v1/events?'+params.toString())]);
el('summary').replaceChildren();[['Events',summary.total_events],...Object.entries(summary.by_severity),...Object.entries(summary.by_status)].forEach(([k,v])=>{const d=document.createElement('div');d.className='card';const b=document.createElement('strong');b.textContent=v;const p=document.createElement('div');p.textContent=k.replaceAll('_',' ');d.append(b,p);el('summary').append(d)});
const pageEvents=events.slice(0,pageSize);el('events').replaceChildren();pageEvents.forEach(e=>{const tr=document.createElement('tr');const values=[e.id+' · '+e.created_at,e.title+'\n'+e.source,e.severity,e.triage_status];values.forEach(v=>{const td=document.createElement('td');td.textContent=v;tr.append(td)});
const td=document.createElement('td');const sel=document.createElement('select');['new','investigating','resolved'].forEach(s=>{const o=document.createElement('option');o.value=s;o.textContent=s;o.selected=e.triage_status===s;sel.append(o)});
sel.addEventListener('change',async()=>{try{await api('/api/v1/events/'+e.id+'/status',{method:'PATCH',body:JSON.stringify({triage_status:sel.value})});message('Event '+e.id+' status updated.');await load()}catch(err){message(err.message,true)}});
const note=document.createElement('button');note.textContent='Add note';note.addEventListener('click',async()=>{const n=prompt('Investigation note (do not include credentials or unnecessary personal data):');if(n===null)return;try{await api('/api/v1/events/'+e.id+'/notes',{method:'POST',body:JSON.stringify({note:n})});message('Note saved for event '+e.id)}catch(err){message(err.message,true)}});td.append(sel,note);tr.append(td);el('events').append(tr)});
el('previous').disabled=offset===0;el('next').disabled=events.length<=pageSize;el('pageInfo').textContent='Showing '+pageEvents.length+' events · offset '+offset;message('Connected. Showing this page of matching events.')}catch(err){message('Unable to load dashboard: '+err.message,true)}}
el('auth').addEventListener('submit',async e=>{e.preventDefault();token=el('token').value;offset=0;await load()});el('filters').addEventListener('submit',e=>{e.preventDefault();offset=0;load()});el('previous').addEventListener('click',()=>{offset=Math.max(0,offset-pageSize);load()});el('next').addEventListener('click',()=>{offset+=pageSize;load()});
</script></main></body></html>"""


@app.post("/api/v1/events", response_model=EventOut, status_code=201, tags=["events"], dependencies=[Depends(require_api_token)])
def ingest_event(payload: EventIn, identity: dict[str, str] = Depends(require_roles("admin", "analyst", "ingestor"))) -> dict[str, Any]:
    severity = SEVERITY_BY_TYPE[payload.event_type]
    created_at = utc_now()
    with db_session() as db:
        cursor = db.execute("""INSERT INTO security_events
            (source,event_type,title,description,source_ip,severity,metadata_json,created_at,triage_status)
            VALUES (?,?,?,?,?,?,?,?, 'new')""",
            (payload.source,payload.event_type,payload.title,payload.description,payload.source_ip,
             severity,json.dumps(payload.metadata,ensure_ascii=True,separators=(",",":")),created_at))
        event_id = int(cursor.lastrowid)
        db.execute("INSERT INTO audit_log(action,event_id,created_at,actor) VALUES (?,?,?,?)",("event.ingested",event_id,created_at,identity["username"]))
        return row_to_event(get_event(db,event_id))


@app.get("/api/v1/events", response_model=list[EventOut], tags=["events"], dependencies=[Depends(require_api_token)])
def list_events(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=10000000),
    severity: Severity | None = None,
    triage_status: TriageStatus | None = None,
    event_type: str | None = Query(default=None, max_length=60),
    q: str | None = Query(default=None, min_length=1, max_length=200),
) -> list[dict[str, Any]]:
    if event_type is not None:
        event_type = event_type.strip().lower()
        if event_type not in EVENT_TYPES:
            raise HTTPException(status_code=422, detail="Unsupported event_type.")
    sql = "SELECT * FROM security_events WHERE 1=1"
    params: list[Any] = []
    if severity:
        sql += " AND severity = ?"; params.append(severity)
    if triage_status:
        sql += " AND triage_status = ?"; params.append(triage_status)
    if event_type:
        sql += " AND event_type = ?"; params.append(event_type)
    if q:
        sql += " AND (instr(unicode_casefold(title), unicode_casefold(?)) > 0 OR instr(unicode_casefold(source), unicode_casefold(?)) > 0 OR instr(unicode_casefold(description), unicode_casefold(?)) > 0)"
        params.extend([q] * 3)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"; params.extend([limit, offset])
    with db_session() as db:
        return [row_to_event(r) for r in db.execute(sql,params).fetchall()]


@app.patch("/api/v1/events/{event_id}/status", response_model=EventOut, tags=["triage"], dependencies=[Depends(require_api_token)])
def update_status(event_id: int, payload: StatusUpdate, identity: dict[str, str] = Depends(require_roles("admin", "analyst"))) -> dict[str, Any]:
    now = utc_now()
    with db_session() as db:
        get_event(db,event_id)
        db.execute("UPDATE security_events SET triage_status = ? WHERE id = ?",(payload.triage_status,event_id))
        db.execute("INSERT INTO audit_log(action,event_id,created_at,actor) VALUES (?,?,?,?)",(f"event.status.{payload.triage_status}",event_id,now,identity["username"]))
        return row_to_event(get_event(db,event_id))


@app.post("/api/v1/events/{event_id}/notes", response_model=NoteOut, status_code=201, tags=["triage"], dependencies=[Depends(require_api_token)])
def add_note(event_id: int, payload: NoteIn, identity: dict[str, str] = Depends(require_roles("admin", "analyst"))) -> dict[str, Any]:
    now = utc_now()
    with db_session() as db:
        get_event(db,event_id)
        cursor = db.execute("INSERT INTO analyst_notes(event_id,note,created_at) VALUES (?,?,?)",(event_id,payload.note,now))
        note_id = int(cursor.lastrowid)
        db.execute("INSERT INTO audit_log(action,event_id,created_at,actor) VALUES (?,?,?,?)",("event.note.added",event_id,now,identity["username"]))
        row = db.execute("SELECT * FROM analyst_notes WHERE id = ?",(note_id,)).fetchone()
        return dict(row)


@app.get("/api/v1/events/{event_id}/notes", response_model=list[NoteOut], tags=["triage"], dependencies=[Depends(require_api_token)])
def list_notes(event_id: int) -> list[dict[str, Any]]:
    with db_session() as db:
        get_event(db,event_id)
        return [dict(r) for r in db.execute("SELECT * FROM analyst_notes WHERE event_id = ? ORDER BY id ASC",(event_id,)).fetchall()]


@app.get("/api/v1/summary", response_model=SummaryOut, tags=["analytics"], dependencies=[Depends(require_api_token)])
def summary() -> dict[str, Any]:
    with db_session() as db:
        total = db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        severities = {s: 0 for s in ("informational","low","medium","high","critical")}
        statuses = {s: 0 for s in ("new","investigating","resolved")}
        for row in db.execute("SELECT severity,COUNT(*) AS n FROM security_events GROUP BY severity"):
            severities[row["severity"]] = row["n"]
        for row in db.execute("SELECT triage_status,COUNT(*) AS n FROM security_events GROUP BY triage_status"):
            statuses[row["triage_status"]] = row["n"]
        return {"total_events":total,"by_severity":severities,"by_status":statuses}
