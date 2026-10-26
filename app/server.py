"""Personal MCP server for your NAS, reachable by Claude through Cloudflare Tunnel and Access.

Security model:
- Cloudflare Access sits in front (login, optional MFA, OAuth for the Claude connector).
- This server checks the Access JWT on every request itself (signature, audience, issuer,
  expiry, e-mail). That is the second line of defense, also against requests from inside Docker.
- Fixed, typed tools; no free-form SQL.
- Every write goes to the audit_log table.
- No published port: only cloudflared reaches the server, through the Docker network.

The example tools keep notes in SQLite. Replace them with your own (see README).
"""
import contextvars
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Optional

import jwt
import uvicorn
from jwt import PyJWKClient
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

PUBLIC_HOST = os.environ["PUBLIC_HOST"]                       # e.g. mcp.example.com
TEAM = os.environ.get("CF_ACCESS_TEAM_DOMAIN", "")            # e.g. myteam.cloudflareaccess.com
AUD = os.environ.get("CF_ACCESS_AUD", "")                     # Application Audience (AUD) tag
ALLOWED_EMAILS = {e.strip().lower() for e in os.environ.get("ALLOWED_EMAILS", "").split(",") if e.strip()}
DB_PATH = os.environ.get("DB_PATH", "/data/mcp.db")
PORT = int(os.environ.get("PORT", "8000"))

# For local tests only: skips the JWT check. Refused unless PUBLIC_HOST is a localhost name.
AUTH_DISABLED = os.environ.get("AUTH_DISABLED", "").lower() in ("1", "true", "yes")
if AUTH_DISABLED and not PUBLIC_HOST.split(":")[0] in ("localhost", "127.0.0.1"):
    raise SystemExit("AUTH_DISABLED is only allowed with PUBLIC_HOST=localhost")
if not AUTH_DISABLED and not (TEAM and AUD and ALLOWED_EMAILS):
    raise SystemExit("CF_ACCESS_TEAM_DOMAIN, CF_ACCESS_AUD and ALLOWED_EMAILS must be set")

# ---------------------------------------------------------------- storage
_db_lock = threading.Lock()
_db = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
_db.row_factory = sqlite3.Row
_db.executescript("""
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    text       TEXT NOT NULL,
    tags       TEXT NOT NULL DEFAULT '',      -- comma separated, lower case
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    at     TEXT NOT NULL,
    actor  TEXT NOT NULL,
    tool   TEXT NOT NULL,
    args   TEXT NOT NULL
);
""")

# the e-mail of the current request, set by the auth middleware (a ContextVar also reaches worker threads)
_actor: contextvars.ContextVar[str] = contextvars.ContextVar("actor", default="unknown")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _audit(tool: str, args: dict):
    _db.execute("INSERT INTO audit_log (at, actor, tool, args) VALUES (?, ?, ?, ?)",
                (_now(), _actor.get(), tool, json.dumps(args, default=str)))


def _tags(tags: Optional[list[str]]) -> str:
    clean = sorted({t.strip().lower().lstrip("#") for t in (tags or []) if t.strip()})
    if any("," in t for t in clean):
        raise ValueError("tags must not contain commas")
    return ",".join(clean)


def _note(row: sqlite3.Row) -> dict:
    return {"id": row["id"], "text": row["text"],
            "tags": [t for t in row["tags"].split(",") if t], "created_at": row["created_at"]}


# ---------------------------------------------------------------- MCP server and tools
mcp = FastMCP(
    "nas-mcp-server",
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[PUBLIC_HOST, f"127.0.0.1:{PORT}", f"localhost:{PORT}"],
        allowed_origins=["https://claude.ai", "https://claude.com", f"https://{PUBLIC_HOST}"],
    ),
)


@mcp.tool()
def note_add(text: str, tags: Optional[list[str]] = None) -> dict:
    """Save a note. Tags are optional words without '#', e.g. ["nas", "todo"]."""
    text = text.strip()
    if not text:
        raise ValueError("text must not be empty")
    if len(text) > 20000:
        raise ValueError("text is too long (max 20000 characters)")
    with _db_lock:
        cur = _db.execute("INSERT INTO notes (text, tags, created_at) VALUES (?, ?, ?)",
                          (text, _tags(tags), _now()))
        _audit("note_add", {"id": cur.lastrowid, "tags": tags})
        row = _db.execute("SELECT * FROM notes WHERE id = ?", (cur.lastrowid,)).fetchone()
    return _note(row)


@mcp.tool()
def note_search(query: Optional[str] = None, tag: Optional[str] = None, limit: int = 20) -> list:
    """Find notes, newest first. query searches the text (case-insensitive), tag filters by one tag.
    Without arguments the newest notes are returned."""
    limit = max(1, min(limit, 100))
    sql, params = "SELECT * FROM notes WHERE 1 = 1", []
    if query:
        sql += " AND text LIKE ? ESCAPE '\\'"
        params.append("%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if tag:
        sql += " AND ',' || tags || ',' LIKE ?"
        params.append("%," + tag.strip().lower().lstrip("#") + ",%")
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with _db_lock:
        return [_note(r) for r in _db.execute(sql, params).fetchall()]


@mcp.tool()
def note_delete(id: int) -> dict:
    """Delete a note by its id."""
    with _db_lock:
        row = _db.execute("SELECT * FROM notes WHERE id = ?", (id,)).fetchone()
        if row is None:
            raise ValueError(f"note {id} not found")
        _db.execute("DELETE FROM notes WHERE id = ?", (id,))
        _audit("note_delete", {"id": id, "text": row["text"][:200]})
    return {"deleted": _note(row)}


@mcp.tool()
def server_info() -> dict:
    """Health and size of the server: number of notes and audit entries, server time."""
    with _db_lock:
        notes = _db.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
        audit = _db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    return {"notes": notes, "audit_entries": audit, "server_time_utc": _now()}


# ---------------------------------------------------------------- Cloudflare Access check
_jwks = PyJWKClient(f"https://{TEAM}/cdn-cgi/access/certs", cache_keys=True, lifespan=3600) if TEAM else None


def _email_if_valid(token: str) -> Optional[str]:
    try:
        key = _jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=AUD, issuer=f"https://{TEAM}",
                            options={"require": ["exp", "iat", "aud", "iss"]})
    except Exception:
        return None
    email = str(claims.get("email", "")).lower()
    return email if email in ALLOWED_EMAILS else None


class AccessAuth:
    """ASGI middleware: every request except /healthz needs a valid Cloudflare Access JWT."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if scope["path"] == "/healthz":
            return await _respond(send, 200, b"ok")
        if AUTH_DISABLED:
            _actor.set("local-test")
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        token = headers.get("cf-access-jwt-assertion") or \
            headers.get("authorization", "").removeprefix("Bearer ").strip()
        email = _email_if_valid(token) if token else None
        if email is None:
            return await _respond(send, 401, b"unauthorized")
        _actor.set(email)
        return await self.app(scope, receive, send)


async def _respond(send, status: int, body: bytes):
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": body})


app = AccessAuth(mcp.streamable_http_app())

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
