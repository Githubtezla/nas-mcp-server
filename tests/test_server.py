"""End-to-end test without Cloudflare: runs the real server in-process and calls it over HTTP.

The Cloudflare signing keys are replaced by a locally generated RSA key, so the JWT check
runs exactly as in production, just with our own tokens.
Run inside the image:  python tests/test_server.py   (needs server.py in the working dir or /app)
"""
import importlib
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

PORT = 8765
TEAM = "test-team.cloudflareaccess.com"
AUD = "test-aud-123"
EMAIL = "owner@example.com"

os.environ.update({
    "PUBLIC_HOST": f"localhost:{PORT}", "PORT": str(PORT), "CF_ACCESS_TEAM_DOMAIN": TEAM,
    "CF_ACCESS_AUD": AUD, "ALLOWED_EMAILS": EMAIL + ", second@example.com",
    "DB_PATH": os.path.join(tempfile.mkdtemp(), "test.db"),
})
sys.path[:0] = [os.getcwd(), "/app"]
server = importlib.import_module("server")

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeJWKS:
    def get_signing_key_from_jwt(self, token):
        class K:
            pass
        k = K()
        k.key = key.public_key()
        return k


server._jwks = FakeJWKS()


def token(**over):
    now = int(time.time())
    claims = {"email": EMAIL, "aud": AUD, "iss": f"https://{TEAM}", "iat": now, "exp": now + 300}
    claims.update(over)
    return jwt.encode(claims, key, algorithm="RS256")


import uvicorn  # noqa: E402

cfg = uvicorn.Config(server.app, host="127.0.0.1", port=PORT, log_level="warning")
srv = uvicorn.Server(cfg)
threading.Thread(target=srv.run, daemon=True).start()
for _ in range(50):
    if srv.started:
        break
    time.sleep(0.1)

URL = f"http://localhost:{PORT}/mcp"
results = []


def rpc(method, params=None, tok=None, rid=1, header="cf-access-jwt-assertion"):
    body = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}).encode()
    req = urllib.request.Request(URL, data=body, method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    if tok:
        req.add_header(header, ("Bearer " + tok) if header == "authorization" else tok)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (f"  ({detail})" if detail and not ok else ""), flush=True)


INIT = {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}

# --- access control
check("healthz without token", urllib.request.urlopen(f"http://localhost:{PORT}/healthz").status == 200)
s, _ = rpc("initialize", INIT)
check("no token -> 401", s == 401, s)
s, _ = rpc("initialize", INIT, tok="not-a-jwt")
check("garbage token -> 401", s == 401, s)
s, _ = rpc("initialize", INIT, tok=token(email="intruder@example.com"))
check("wrong e-mail -> 401", s == 401, s)
s, _ = rpc("initialize", INIT, tok=token(aud="other-app"))
check("wrong audience -> 401", s == 401, s)
s, _ = rpc("initialize", INIT, tok=token(iss="https://evil.cloudflareaccess.com"))
check("wrong issuer -> 401", s == 401, s)
s, _ = rpc("initialize", INIT, tok=token(exp=int(time.time()) - 60))
check("expired token -> 401", s == 401, s)
other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
forged = jwt.encode({"email": EMAIL, "aud": AUD, "iss": f"https://{TEAM}", "iat": int(time.time()),
                     "exp": int(time.time()) + 300}, other, algorithm="RS256")
s, _ = rpc("initialize", INIT, tok=forged)
check("token signed with another key -> 401", s == 401, s)

# --- MCP protocol with a valid token
T = token()
s, r = rpc("initialize", INIT, tok=T)
check("initialize with valid token", s == 200 and r["result"]["serverInfo"]["name"] == "nas-mcp-server", (s, r))
s, r = rpc("initialize", INIT, tok=token(email="Second@Example.com"), header="authorization")
check("second allowed e-mail via Authorization header", s == 200, s)
s, r = rpc("tools/list", tok=T, rid=2)
names = sorted(t["name"] for t in r["result"]["tools"]) if s == 200 else []
check("tools/list", names == ["note_add", "note_delete", "note_search", "server_info"], names)


def call(name, args, rid=3):
    s, r = rpc("tools/call", {"name": name, "arguments": args}, tok=T, rid=rid)
    if s != 200:
        return s, None, True
    res = r["result"]
    if res.get("isError"):
        return s, None, True
    if "structuredContent" in res:
        data = res["structuredContent"]
        data = data.get("result", data)
    else:
        # FastMCP returns a dict as one JSON text item and a list as one item per element
        items = [json.loads(c["text"]) for c in res.get("content", []) if c.get("type") == "text"]
        data = items if name == "note_search" else (items[0] if items else None)
    return s, data, False


s, n1, err = call("note_add", {"text": "Buy 100% coffee_beans", "tags": ["#Shopping", "home"]})
check("note_add", s == 200 and not err and n1["tags"] == ["home", "shopping"], (s, n1))
s, n2, err = call("note_add", {"text": "Check NAS backup", "tags": ["nas"]})
check("note_add second", s == 200 and not err, (s, n2))
s, found, err = call("note_search", {"query": "100%"})
check("note_search with % literal", not err and len(found) == 1 and found[0]["id"] == n1["id"], found)
s, found, err = call("note_search", {"query": "coffee_"})
check("note_search with _ literal", not err and len(found) == 1, found)
s, found, err = call("note_search", {"tag": "nas"})
check("note_search by tag", not err and [n["id"] for n in found] == [n2["id"]], found)
s, found, err = call("note_search", {})
check("note_search newest first", not err and [n["id"] for n in found] == [n2["id"], n1["id"]], found)
s, _, err = call("note_add", {"text": "   "})
check("empty note rejected", err)
s, d, err = call("note_delete", {"id": n1["id"]})
check("note_delete", not err and d["deleted"]["id"] == n1["id"], d)
s, _, err = call("note_delete", {"id": 99999})
check("delete unknown id rejected", err)
s, info, err = call("server_info", {})
check("server_info", not err and info["notes"] == 1 and info["audit_entries"] == 3, info)

rows = server._db.execute("SELECT actor, tool FROM audit_log ORDER BY id").fetchall()
check("audit log records e-mail and tools",
      [(r["actor"], r["tool"]) for r in rows] == [(EMAIL, "note_add"), (EMAIL, "note_add"), (EMAIL, "note_delete")],
      [tuple(r) for r in rows])

# --- DNS rebinding protection: foreign Host header
req = urllib.request.Request(URL, data=json.dumps({"jsonrpc": "2.0", "id": 9, "method": "initialize",
                             "params": INIT}).encode(), method="POST",
                             headers={"Content-Type": "application/json", "Host": "evil.example.com",
                                      "Accept": "application/json, text/event-stream",
                                      "cf-access-jwt-assertion": T})
try:
    urllib.request.urlopen(req, timeout=10)
    check("foreign Host header rejected", False, "accepted")
except urllib.error.HTTPError as e:
    check("foreign Host header rejected", e.code in (400, 421), e.code)

srv.should_exit = True
print(f"\n{sum(results)}/{len(results)} checks passed", flush=True)
sys.exit(0 if all(results) else 1)
