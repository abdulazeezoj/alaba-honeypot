# honeypot

A SSH + web honeypot that captures connection attempts, credentials, and
shell commands from automated scanners and attackers, enriches the source
IPs with geolocation data, and visualizes everything on a live dashboard.

> **Use responsibly.** This logs real connection attempts and credentials
> from whoever connects to it. Deploy it only on infrastructure you own or
> are authorized to monitor (a VPS, lab network, or research environment),
> point it only at *your* exposed ports, and follow your hosting provider's
> and local law's rules on logging network traffic. Don't use it to
> impersonate a third-party service in order to harvest real users'
> credentials.

## Stack

| Layer | Tool |
|---|---|
| Project layout | `uv init --package`, Python 3.12+ |
| SSH decoy | Paramiko (`ServerInterface`, fake interactive shell) |
| Web decoy + API | Flask |
| Templates | Jinja2 (bundled with Flask) |
| Storage | SQLite3 (stdlib) |
| Geolocation | httpx (async client) + ip-api.com free tier |
| Async scheduling | asyncio (background event loop, separate thread) |
| Dashboard charts | Chart.js (CDN) |

## Project layout

```
honeypot/
├── pyproject.toml
├── data/                      # SQLite DB lives here (gitignored)
├── .vscode/settings.json      # points Pylance at the uv venv + src/
└── src/honeypot/
    ├── run.py                 # entrypoint: starts SSH thread + Flask app
    ├── db.py                  # SQLite schema + read/write helpers
    ├── ssh_server.py          # Paramiko fake SSH server
    ├── geoip.py                # async ip-api.com enrichment worker
    ├── keys/host_key          # generated SSH host key (gitignored)
    └── web/
        ├── __init__.py        # Flask app factory: decoy + dashboard + API
        └── templates/
            ├── login.html     # decoy login portal
            └── dashboard.html # Chart.js operator dashboard
```

## Setup

```bash
uv sync
```

Open the folder in VS Code with the Python and Pylance extensions installed;
`.vscode/settings.json` already points the interpreter at `.venv` and adds
`src/` to Pylance's analysis path.

## Running

```bash
uv run honeypot
```

This starts:
- the fake SSH server on `0.0.0.0:2222` (binding port 22 directly needs root;
  either run with elevated privileges and `--ssh-port 22`, or front it with
  an iptables/nginx-stream redirect from 22 → 2222)
- the Flask app on `0.0.0.0:8080`, serving:
  - `/` and `/login` — the decoy admin login portal
  - `/dashboard` — the live Chart.js dashboard
  - `/api/*` — JSON endpoints the dashboard polls

Options:

```bash
uv run honeypot --ssh-port 2222 --web-port 8080 --no-geo
```

`--no-geo` disables ip-api.com enrichment entirely (useful if you're offline
or want to stay well under the free-tier rate limit during testing).

## How it works

**SSH side** (`ssh_server.py`): each TCP connection is handed to its own
thread running a Paramiko `Transport`. `check_auth_password` logs every
username/password pair tried and always returns `AUTH_SUCCESSFUL`, so the
client proceeds to a shell instead of retrying or giving up — that's where
the interesting behavior (recon commands, malware download attempts, etc.)
shows up. The shell is fake: every line is logged to `commands`, and a
small set of canned responses (`whoami`, `ls`, `uname -a`, ...) make it look
plausible without ever touching a real filesystem or process.

**Web side** (`web/__init__.py`): a Flask app serves a decoy login form
styled like a generic admin console. Every visit and every submitted
credential pair is logged to `web_hits`. The form always rejects, so
scripted credential-stuffing tools keep trying (and keep generating data).

**Storage** (`db.py`): plain SQLite, WAL mode, thread-local connections (one
per handler thread, since `sqlite3` connections can't cross threads).
Four tables: `connections`, `credentials`, `commands`, `web_hits`, plus a
`geo_cache` table keyed by IP.

**Geolocation** (`geoip.py`): a dedicated background thread runs its own
asyncio event loop and an `httpx.AsyncClient`. The SSH/Flask handler threads
call `enricher.submit(ip)`, which is non-blocking — it just queues the IP
on the geo thread's loop via `call_soon_threadsafe`. A sliding-window rate
limiter keeps lookups under ip-api.com's free-tier cap (45/min; we use 40
to leave headroom). On startup, `backfill_missing()` uses ip-api.com's
batch endpoint (up to 100 IPs/request) to catch up on any IPs already in
the DB that don't have geo data yet.

**Dashboard** (`web/templates/dashboard.html`): polls `/api/summary`,
`/api/timeseries`, `/api/geo-distribution`, `/api/credentials/top`,
`/api/connections`, and `/api/commands` every 5 seconds and redraws three
Chart.js visualizations (attack frequency line chart, geographic
distribution bar chart) plus three live tables (top credential pairs,
recent connections, recent commands).

## API reference

| Endpoint | Description |
|---|---|
| `GET /api/summary` | Total connections, unique IPs, credential/command counts, last-24h count |
| `GET /api/connections?limit=` | Recent SSH connections joined with geo data |
| `GET /api/credentials?limit=` | Raw credential attempts, most recent first |
| `GET /api/credentials/top?limit=` | Username/password pairs grouped by frequency |
| `GET /api/commands?limit=` | Shell commands typed by connected clients |
| `GET /api/timeseries?hours=` | Hourly connection counts for the trend chart |
| `GET /api/geo-distribution` | Connection counts grouped by country |
| `GET /api/map-points` | Geo-tagged IPs with lat/lon, for a future map view |

## Notes on ip-api.com

The free tier is HTTP-only (not HTTPS), rate-limited to 45 requests/minute,
and intended for non-commercial use. If you need HTTPS, higher volume, or
commercial terms, see ip-api.com's paid plans.
