# nas-mcp-server

Run your own MCP server on your NAS and use it as a custom connector in Claude (web, desktop and mobile), without opening a single port. Cloudflare Tunnel carries the traffic out of your network, Cloudflare Access handles login, MFA and the OAuth flow for the connector, and the server checks every request itself as a second line of defense.

The template ships with a small notes example (SQLite, four tools, audit log) that you replace with your own tools: your home automation, your documents, your databases.

## How it works

```
Claude ──HTTPS──> mcp.example.com ──> Cloudflare Access ──> Cloudflare Tunnel ──> cloudflared ──> mcp:8000
                  (your domain)       login, MFA, OAuth     outbound only          (container)     (container)
                                                                                                     │
                                                                              checks the Access JWT, │
                                                                              runs the tool, writes  ▼
                                                                              the audit log      ./data/mcp.db
```

- **No open ports.** `cloudflared` only connects outward. The MCP container publishes no port; only `cloudflared` reaches it over the Docker network.
- **Cloudflare Access in front.** Only the e-mail addresses in your Access policy get through, optionally with MFA. Access also acts as the OAuth server Claude talks to when you add the connector.
- **Defense in depth.** The server verifies the `Cf-Access-Jwt-Assertion` token on every request: signature against your team's public keys, audience, issuer, expiry and an allow list of e-mails. A request that bypasses Access, for example from another container, gets `401`.
- **Narrow tools.** Fixed, typed tools with validation; no free-form SQL. Every write is recorded in `audit_log` with the e-mail of the caller.
- **Hardened containers.** Non-root users, read-only file systems, no Linux capabilities, `no-new-privileges`, memory limits, the tunnel token readable only by `cloudflared`.

## Status

The same authentication, transport and container setup has been running since October 2026 as the backend of a personal connector with several dozen tools on a UGREEN NAS. This repository is a cleaned-up template of it. Before publishing, the template was tested with the 23 automated checks in `tests/test_server.py` (MCP protocol, all tools, and the JWT check with locally generated keys: missing, forged, expired, wrong audience, wrong issuer and wrong e-mail are rejected), and the compose stack was started up to a healthy server. The Cloudflare steps below were not repeated with a fresh account for this template; menu names in the Cloudflare dashboard change from time to time.

Versions: Python 3.12, mcp 1.30.0, PyJWT 2.15.1, uvicorn 0.54.0, cloudflared 2026.10.0.

## Requirements

- A NAS or server with Docker Compose v2 (Synology, QNAP, UGREEN, Unraid, TrueNAS, any Linux).
- A domain whose DNS is managed by Cloudflare (the free plan is enough).
- Cloudflare Zero Trust (the free plan covers a personal setup).
- A Claude plan that supports custom connectors.

## Setup

### 1. Get the files

```bash
git clone https://github.com/Githubtezla/nas-mcp-server.git
cd nas-mcp-server
cp .env.example .env
```

### 2. Create the tunnel

In the Cloudflare Zero Trust dashboard, under Networks, Tunnels:

1. Create a tunnel of type **Cloudflared**, name it, choose **Docker** as the environment.
2. Copy the long token from the shown `docker run` command into `secrets/cf_tunnel_token` (one line). Do not run that command; the compose file starts `cloudflared` for you.
3. Add a **public hostname**: subdomain `mcp` (or any), your domain, service type `HTTP`, URL `mcp:8000`. That is the service name inside the compose project, not an IP.

Put the hostname into `.env` as `PUBLIC_HOST`, for example `mcp.example.com`.

### 3. Protect it with Access

Under Access, Applications, add a **self-hosted** application:

1. Application domain: the same hostname, for example `mcp.example.com`.
2. Policy: **Allow**, include **Emails**, your address only. No bypass rule.
3. Turn on **managed OAuth** for the application (the setting that lets MCP clients log in through Access), and allow exactly these redirect URIs:
   - `https://claude.ai/api/mcp/auth_callback`
   - `https://claude.com/api/mcp/auth_callback`

   Leave localhost or loopback redirects off.
4. Optional but recommended: require MFA for this application (an authenticator app).
5. Open the application's overview and copy the **Application Audience (AUD) tag**.

Fill in `.env`:

| Variable | Example | Where to find it |
| --- | --- | --- |
| `PUBLIC_HOST` | `mcp.example.com` | your public hostname |
| `CF_ACCESS_TEAM_DOMAIN` | `myteam.cloudflareaccess.com` | Zero Trust settings, your team domain |
| `CF_ACCESS_AUD` | long hex string | the application's AUD tag |
| `ALLOWED_EMAILS` | `you@example.com` | the same address(es) as in the Access policy, comma separated |
| `TZ` | `Europe/Berlin` | your time zone |

Optional: a WAF rate limiting rule for the hostname (for example 60 requests per 10 seconds per IP) keeps noisy clients out.

### 4. Start it

```bash
docker compose up -d
docker compose logs -f
```

`fixperms` runs once and exits (that is normal), then `mcp` becomes healthy and `cloudflared` connects. In the Zero Trust dashboard the tunnel shows as healthy.

Opening `https://mcp.example.com/mcp` in a browser should now lead to the Cloudflare Access login, never directly to the server.

### 5. Add the connector in Claude

In Claude, under Settings, Connectors, add a custom connector with the URL `https://mcp.example.com/mcp`. Claude opens the Cloudflare Access login; after that the four example tools are available. Try: "Save a note that the NAS backup runs at 4 am".

## Writing your own tools

All tools live in `app/server.py`. A tool is a typed Python function with a docstring; the docstring is what Claude reads to decide when to use it:

```python
@mcp.tool()
def light_set(room: str, on: bool) -> dict:
    """Switch the light in a room on or off. room is one of: kitchen, office."""
    if room not in ("kitchen", "office"):
        raise ValueError("unknown room")
    # ... call your home automation here ...
    with _db_lock:
        _audit("light_set", {"room": room, "on": on})
    return {"room": room, "on": on}
```

Then rebuild:

```bash
docker compose up -d --build mcp
```

Tips from running this for a while:

- Keep tools narrow and typed. "Add a note" is better than "run this SQL". If you need ad-hoc queries, give them a separate read-only database user.
- Log every write with `_audit`, including enough to undo it.
- Put API keys of other services into files under `secrets/` and mount them only into the `mcp` container; never into `.env` or the image.
- Other services the tools talk to (a notes app, a document manager) can join the compose network; they do not need ports in your LAN for that.

## Testing

Run the automated checks inside the image (no Cloudflare needed):

```bash
docker compose run --rm --no-deps -v ./tests:/tests:ro mcp python /tests/test_server.py
```

For manual experiments with an MCP client on your own machine, the server can run without the JWT check, but only with `PUBLIC_HOST=localhost:8000` and `AUTH_DISABLED=true`; it refuses to start that way with a public hostname. Publish the port only for that test.

## Things that cost me time

- **The connector keeps the old tool list.** After adding or renaming tools, disconnect and reconnect the connector in Claude's settings. A chat that was already open keeps its old list even then; use a new chat. New parameters on existing tools work immediately.
- **"Revoke existing tokens" changes the AUD tag.** That button in the Access application issues a new audience tag. The server then rejects everything with `401` until `CF_ACCESS_AUD` is updated and the container restarted.
- **An "Authentication method = SMS" rule locks everyone out.** SMS is not a login method of Access itself; such a rule matches nobody.
- **"Invalid Host header".** The MCP SDK's DNS rebinding protection only accepts the hosts listed in `allowed_hosts` and rejects everything else with this message. `PUBLIC_HOST` must match the hostname exactly.
- **The server needs outbound internet.** It downloads Cloudflare's signing keys (`https://<team>/cdn-cgi/access/certs`). Do not put it on an internal-only Docker network; put databases there instead.
- **Login loops in Claude** usually come from the Access application: check the policy, the redirect URIs and the session duration.
- **Stateless HTTP.** The server runs with `stateless_http=True` and JSON responses, which works well behind Cloudflare and with several Claude clients at once.

## Security notes

- Access in front plus the JWT check in the server means a single misconfiguration does not open your tools to the internet. Keep both.
- `ALLOWED_EMAILS` and the Access policy should list the same addresses.
- `data/mcp.db` holds your notes and the audit log; include it in your backups. `secrets/` and `.env` should not go into cloud backups.
- Anyone who can use the connector can do whatever your tools allow. Write tools as if they could be called by mistake: validate input, prefer reversible actions, log everything.

## Credits and license

- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk), [PyJWT](https://github.com/jpadilla/pyjwt), [uvicorn](https://www.uvicorn.org), [cloudflared](https://github.com/cloudflare/cloudflared).
- Not affiliated with Cloudflare or Anthropic.
- Released under the [MIT License](LICENSE).
