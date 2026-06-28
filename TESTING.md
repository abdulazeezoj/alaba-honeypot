# TESTING.md

How to verify the honeypot actually captures what it's supposed to capture,
without needing a real attacker. This guide works the same way on **Windows
PowerShell**, **macOS**, and **Linux**.

## Why this guide is structured the way it is

Most of the verification logic lives in small Python scripts under
`scripts/manual_tests/`, not in inline shell one-liners. That's deliberate:
bash and PowerShell quote strings, escape characters, and handle background
processes differently enough that a command that works in one breaks
silently (or loudly) in the other. Python doesn't have that problem — `uv
run python scripts/manual_tests/01_check_schema.py` is the exact same
command on every platform. Every script below was run against this codebase
to confirm it works as described.

The only places this guide forks into separate PowerShell/bash commands are
genuinely shell-native things: deleting a file, running a process in the
background, stopping it. Everything else is one command, copy-pasted once.

All commands assume you're in the project root with dependencies installed:

```
cd honeypot
uv sync
```

---

## 0. Resetting between test runs

Run this before starting, and again any time you want a clean slate.

**PowerShell:**
```powershell
Remove-Item -ErrorAction SilentlyContinue data\honeypot.db, data\honeypot.db-wal, data\honeypot.db-shm
```

**macOS / Linux (bash/zsh):**
```bash
rm -f data/honeypot.db data/honeypot.db-wal data/honeypot.db-shm
```

This wipes captured data but keeps the SSH host key
(`src/honeypot/keys/host_key`), so your SSH client won't re-trigger a
host-key warning on the next connection. To also force a fresh host key:

**PowerShell:**
```powershell
Remove-Item -ErrorAction SilentlyContinue src\honeypot\keys\host_key
```

**macOS / Linux:**
```bash
rm -f src/honeypot/keys/host_key
```

---

## 1. Sanity check: does it even start?

```
uv run honeypot --help
```

Expect the argparse usage block (`--ssh-port`, `--web-port`, `--no-geo`,
etc). If this fails, dependencies didn't install — rerun `uv sync` and check
for errors. This command's output is identical on every platform.

You'll start the SSH server and the web server **separately** for the rest
of this guide, each in its own scripts (`scripts/manual_tests/07_run_ssh_server.py`
and `08_run_web_server.py`), rather than `uv run honeypot` directly — that
way each piece can be tested in isolation and you can see exactly which log
lines belong to which component. Once you've worked through the guide,
`uv run honeypot` runs both together for normal use.

---

## 2. Unit-level checks (no network involved)

These isolate each module so if something's broken later, you already know
it isn't the database or key generation. No server needs to be running for
this section.

**Database schema:**
```
uv run python scripts/manual_tests/01_check_schema.py
```
Expect a list of six table names ending in `OK: all tables present`.

**SSH host key generation:**
```
uv run python scripts/manual_tests/02_check_host_key.py
```
Run it twice — the fingerprint printed should be identical both times (the
key is generated once and reused from `src/honeypot/keys/host_key`, not
regenerated per run).

**Flask routes (uses Flask's built-in test client, no real server needed):**
```
uv run python scripts/manual_tests/03_check_flask_routes.py
```
Expect a JSON summary dict followed by `OK: routes respond`.

---

## 3. Testing the SSH honeypot like an attacker would

### 3a. Start the SSH server

Open a **second terminal window** (PowerShell or bash, your choice — they
don't need to match) and run:

```
uv run python scripts/manual_tests/07_run_ssh_server.py
```

Leave it running. You should see:
```
... SSH honeypot listening on 127.0.0.1:2222
```

Do everything else in this section from your **first terminal**.

### 3b. Connect with a real SSH client

If you have an `ssh` client installed (OpenSSH ships with Windows 10+,
macOS, and virtually all Linux distros):

```
ssh -p 2222 root@127.0.0.1
```

- You'll get a host-key warning the first time (expected — it's a freshly
  generated key, not a known one). Accept it.
- Type **any** password. It will be accepted — that's intentional. The
  honeypot wants you to get in so it can observe what you do next, rather
  than bouncing you after one failed attempt.
- You'll land in a fake shell with a `root@ubuntu-prod-01:~#` prompt. Try:
  ```
  whoami
  ls
  uname -a
  pwd
  some_made_up_command
  exit
  ```
  `whoami`, `ls`, `uname -a`, `id`, and `pwd` return canned responses;
  anything else returns a `command not found` line. `exit` ends the session
  cleanly.

If you don't have an `ssh` client handy (or just want a repeatable,
scripted version of the same thing), use 3c instead.

### 3c. Scripted equivalent (works identically everywhere)

```
uv run python scripts/manual_tests/04_ssh_single_attempt.py
```

Expect output like:
```
authenticated
banner: 'Welcome to Ubuntu 22.04.3 LTS ...\r\n\r\nroot@ubuntu-prod-01:~# '
whoami: 'whoami\r\n\r\nroot\r\nroot@ubuntu-prod-01:~# '
ls: 'ls\r\n\r\nbin  boot  dev  ...  var\r\nroot@ubuntu-prod-01:~# '
session closed
```

A `Connection reset by peer` (or, on Windows, a similar connection-aborted
message) printed in the **server's** terminal right after this is normal —
it's just the client disconnecting after `exit`, not a failure.

### 3d. Verify the attempt landed in the database

```
uv run python scripts/manual_tests/05_check_capture.py
```

You should see one row per connection you made, one credential row with
the username/password you typed, and one command row per line you typed
(including `exit`).

### 3e. Brute-force simulation (multiple attackers, one script)

To generate enough varied data for the dashboard charts to look meaningful:

```
uv run python scripts/manual_tests/06_brute_force_sim.py
```

Expect six lines like `root:toor -> logged in and ran id`.

---

## 4. Testing the web decoy

### 4a. Start the web server

In your **second terminal** (stop the SSH server with `Ctrl+C` first, or
open a third terminal — either works):

```
uv run python scripts/manual_tests/08_run_web_server.py
```

Leave it running. You should see Flask's startup banner ending in
`Running on http://127.0.0.1:8080`.

### 4b. Hit the fake login page

```
uv run python scripts/manual_tests/09_web_decoy_get.py
```

Expect `status: 200` followed by `OK: decoy login page served`.

If you'd rather see it rendered, open `http://127.0.0.1:8080/` in a browser
— same effect, just visual.

### 4c. Submit fake credentials

```
uv run python scripts/manual_tests/10_web_decoy_post.py
```

Expect `status: 200`. The form always rejects (you'll see "Invalid username
or password" if you load `/login` in a browser), but the attempt is logged
regardless.

### 4d. Confirm it was captured

```
uv run python scripts/manual_tests/11_check_web_hits.py
```

You should see a `GET /` row and `POST /login` rows with the
usernames/passwords you submitted, most recent first.

### 4e. Simulate a scripted credential-stuffing bot

```
uv run python scripts/manual_tests/12_credential_stuffing_sim.py
```

Expect four lines like `admin:admin -> 200`. Re-run step 4d afterward to
see all four attempts logged.

---

## 5. Testing the dashboard and API

With the web server still running and some data captured from sections 3
and 4:

```
uv run python scripts/manual_tests/13_check_api_endpoints.py
```

Expect six lines, one per endpoint, each showing a `200` status and an item
count. `/api/geo-distribution` will show `0 items` until the geo enricher
has successfully resolved at least one IP (see section 6) — that's expected
for local testing against `127.0.0.1`, since loopback/private addresses are
intentionally skipped (see 6c).

Then open the dashboard itself in a browser:
```
http://127.0.0.1:8080/dashboard
```

Check:
- The five stat tiles at the top show non-zero numbers.
- The attack-frequency line chart shows a point for each hour you generated
  traffic in.
- The credentials table lists what you submitted in sections 3e/4e, sorted
  by frequency.
- The page auto-refreshes every 5 seconds — leave it open, run
  `scripts/manual_tests/04_ssh_single_attempt.py` again (with the SSH
  server running), and confirm a new row appears without reloading the
  page.

---

## 6. Testing geolocation enrichment

This needs real outbound internet access to `ip-api.com` on port 80 (HTTP,
not HTTPS). If you're behind a corporate proxy or a locked-down firewall,
some or all of this section may not work — that's a network/firewall issue,
not a bug in the code, and is unrelated to PowerShell vs. bash.

### 6a. Live lookup against a known IP

```
uv run python scripts/manual_tests/14_geo_live_lookup.py
```

Expect something like:
```python
{'ip': '8.8.8.8', 'country': 'United States', 'region': 'Virginia',
 'city': 'Ashburn', 'isp': 'Google LLC', 'lat': 39.03, 'lon': -77.5, ...}
```

If you get a `403` or a connection error instead, check that outbound HTTP
on port 80 to `ip-api.com` is actually allowed from your network.

### 6b. Backfill on startup

First insert a connection with no geo data yet:
```
uv run python scripts/manual_tests/15_geo_backfill.py
```

Then run the backfill:
```
uv run python scripts/manual_tests/16_geo_backfill_run.py
```

This confirms `backfill_missing()` finds IPs already in `connections` that
have no matching `geo_cache` row and resolves them via ip-api.com's batch
endpoint — this is what runs automatically when you start the full app with
`uv run honeypot` (unless you pass `--no-geo`).

### 6c. Confirm private/loopback IPs are skipped (no wasted API calls)

```
uv run python scripts/manual_tests/17_geo_skip_check.py
```

Expect `OK: private-range filtering works as expected`.

This matters because every SSH/web test you run against `127.0.0.1` in this
guide will **not** trigger a real ip-api.com call — that's by design, not a
bug. To see real enrichment end-to-end, point a test client at the
honeypot's actual public IP, or just run 6a directly (it already targets
`8.8.8.8`).

---

## 7. Load / concurrency check (optional)

Confirms the SSH server's one-thread-per-connection model holds up under
several simultaneous clients, and that SQLite's WAL mode handles concurrent
writers without locking errors.

With the SSH server still running (section 3a):

```
uv run python scripts/manual_tests/18_concurrency_sim.py
```

Expect `all 20 concurrent connections finished` after a few seconds, with
no Python tracebacks printed above it (a handful of socket-reset messages
in the **server's** terminal are expected — see the note in 3c).

Then check the counts:

```
uv run python scripts/manual_tests/19_concurrency_check.py
```

The numbers should reflect everything run earlier in this guide plus these
20 new connections.

---

## 8. Stopping the servers

**PowerShell:** click into the terminal running the server and press
`Ctrl+C`.

**macOS / Linux:** same — `Ctrl+C` in the foreground terminal. If you
backgrounded it with `&`, use `kill %1` or `kill <pid>` instead.

---

## Platform notes

- **PowerShell's `curl` is not real curl.** PowerShell aliases `curl` to
  `Invoke-WebRequest`, which has different flags and behavior than the
  Unix `curl` binary. This guide avoids the problem entirely by using
  Python's standard-library `urllib` for every HTTP request in the test
  scripts — it behaves identically on every platform, so there's no
  PowerShell-specific HTTP syntax to get wrong.
- **No `.venv` activation needed.** Every command in this guide uses `uv
  run`, which finds and uses the project's virtual environment
  automatically — you never need `.venv\Scripts\Activate.ps1` or `source
  .venv/bin/activate` for anything in this document.
- **Binding port 22 / port 2222 on Windows:** Windows doesn't restrict
  low-numbered ports the way Linux does, so you generally won't need
  administrator privileges to bind port 22 directly — though OpenSSH
  Server, if installed and running as a Windows service, may already be
  using it, in which case you'll need a different port anyway. On
  macOS/Linux, binding port 22 itself requires root; see the main
  README for the iptables-redirect alternative.
- **Geolocation 403s from restricted networks**: ip-api.com isn't reachable
  from every environment (corporate proxies, locked-down containers, some
  CI runners, school/work networks that block non-HTTPS traffic). The code
  already handles lookup failures by logging and moving on — it won't crash
  the SSH or web server on either platform. Test with `--no-geo` if you
  just want to validate capture logic without depending on outbound network
  access.
- **`172.x.x.x` skip range**: only `172.16.0.0`–`172.31.255.255` is treated
  as private (per RFC 1918); other `172.x` addresses are treated as public
  and will be looked up normally. This logic runs in pure Python and
  behaves identically on every platform.
