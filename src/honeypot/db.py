"""
SQLite persistence layer for the honeypot.

All captured telemetry (connections, credential attempts, shell commands,
and geolocation enrichment) is written here. SQLite is used via the
stdlib `sqlite3` module with WAL mode enabled so the SSH server threads
and the Flask dashboard can read/write concurrently without locking
each other out for long.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "honeypot.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS connections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip   TEXT NOT NULL,
    source_port INTEGER,
    protocol    TEXT NOT NULL DEFAULT 'ssh',
    started_at  TEXT NOT NULL,
    closed_at   TEXT
);

CREATE TABLE IF NOT EXISTS credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id INTEGER NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
    username      TEXT NOT NULL,
    password      TEXT,
    auth_method   TEXT NOT NULL DEFAULT 'password',
    accepted      INTEGER NOT NULL DEFAULT 0,
    attempted_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS commands (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id INTEGER NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
    command       TEXT NOT NULL,
    issued_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS web_hits (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip    TEXT NOT NULL,
    path         TEXT NOT NULL,
    method       TEXT NOT NULL,
    username     TEXT,
    password     TEXT,
    user_agent   TEXT,
    occurred_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS geo_cache (
    ip          TEXT PRIMARY KEY,
    country     TEXT,
    region      TEXT,
    city        TEXT,
    isp         TEXT,
    lat         REAL,
    lon         REAL,
    looked_up_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_connections_started_at ON connections(started_at);
CREATE INDEX IF NOT EXISTS idx_connections_source_ip ON connections(source_ip);
CREATE INDEX IF NOT EXISTS idx_credentials_username ON credentials(username);
CREATE INDEX IF NOT EXISTS idx_web_hits_occurred_at ON web_hits(occurred_at);
"""

_local = threading.local()


def utcnow() -> str:
    """ISO-8601 UTC timestamp, used consistently for every row we write."""
    return datetime.now(timezone.utc).isoformat()


def get_connection() -> sqlite3.Connection:
    """
    Return a thread-local SQLite connection.

    Each SSH client is handled on its own thread (see ssh_server.py), and
    Flask's dev server / WSGI workers each get their own thread too, so a
    thread-local connection avoids passing connections across threads
    (which sqlite3 forbids by default) while still letting every thread
    talk to the same on-disk database.
    """
    conn = getattr(_local, "conn", None)
    if conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        _local.conn = conn
    return conn


@contextmanager
def cursor():
    conn = get_connection()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


def init_db() -> None:
    """Create tables/indexes if they don't already exist. Safe to call repeatedly."""
    with cursor() as cur:
        cur.executescript(_SCHEMA)


# --------------------------------------------------------------------------
# Write paths (called from the SSH server and the Flask decoy login route)
# --------------------------------------------------------------------------

def open_connection(source_ip: str, source_port: int | None, protocol: str = "ssh") -> int | None:
    with cursor() as cur:
        cur.execute(
            "INSERT INTO connections (source_ip, source_port, protocol, started_at) "
            "VALUES (?, ?, ?, ?)",
            (source_ip, source_port, protocol, utcnow()),
        )

        return cur.lastrowid


def close_connection(connection_id: int) -> None:
    with cursor() as cur:
        cur.execute(
            "UPDATE connections SET closed_at = ? WHERE id = ?",
            (utcnow(), connection_id),
        )


def log_credential(
    connection_id: int,
    username: str,
    password: str | None,
    auth_method: str = "password",
    accepted: bool = False,
) -> None:
    with cursor() as cur:
        cur.execute(
            "INSERT INTO credentials (connection_id, username, password, auth_method, accepted, attempted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (connection_id, username, password, auth_method, int(accepted), utcnow()),
        )


def log_command(connection_id: int, command: str) -> None:
    with cursor() as cur:
        cur.execute(
            "INSERT INTO commands (connection_id, command, issued_at) VALUES (?, ?, ?)",
            (connection_id, command, utcnow()),
        )


def log_web_hit(
    source_ip: str,
    path: str,
    method: str,
    username: str | None = None,
    password: str | None = None,
    user_agent: str | None = None,
) -> None:
    with cursor() as cur:
        cur.execute(
            "INSERT INTO web_hits (source_ip, path, method, username, password, user_agent, occurred_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (source_ip, path, method, username, password, user_agent, utcnow()),
        )


def upsert_geo(ip: str, geo: "GeoInfo") -> None:
    with cursor() as cur:
        cur.execute(
            """
            INSERT INTO geo_cache (ip, country, region, city, isp, lat, lon, looked_up_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                country = excluded.country,
                region = excluded.region,
                city = excluded.city,
                isp = excluded.isp,
                lat = excluded.lat,
                lon = excluded.lon,
                looked_up_at = excluded.looked_up_at
            """,
            (ip, geo.country, geo.region, geo.city, geo.isp, geo.lat, geo.lon, utcnow()),
        )


def get_cached_geo(ip: str) -> sqlite3.Row | None:
    with cursor() as cur:
        cur.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,))
        return cur.fetchone()


def ips_missing_geo() -> list[str]:
    """Distinct source IPs (SSH + web) that have no geo_cache entry yet."""
    with cursor() as cur:
        cur.execute(
            """
            SELECT DISTINCT source_ip FROM (
                SELECT source_ip FROM connections
                UNION
                SELECT source_ip FROM web_hits
            )
            WHERE source_ip NOT IN (SELECT ip FROM geo_cache)
            """
        )
        return [row["source_ip"] for row in cur.fetchall()]


@dataclass
class GeoInfo:
    country: str | None = None
    region: str | None = None
    city: str | None = None
    isp: str | None = None
    lat: float | None = None
    lon: float | None = None


# --------------------------------------------------------------------------
# Read paths (called by the Flask dashboard API)
# --------------------------------------------------------------------------

def fetch_recent_connections(limit: int = 100) -> list[sqlite3.Row]:
    with cursor() as cur:
        cur.execute(
            """
            SELECT c.*, g.country, g.region, g.city, g.isp, g.lat, g.lon
            FROM connections c
            LEFT JOIN geo_cache g ON g.ip = c.source_ip
            ORDER BY c.started_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return cur.fetchall()


def fetch_recent_web_hits(limit: int = 100) -> list[sqlite3.Row]:
    with cursor() as cur:
        cur.execute(
            """
            SELECT w.*, g.country, g.region, g.city, g.isp, g.lat, g.lon
            FROM web_hits w
            LEFT JOIN geo_cache g ON g.ip = w.source_ip
            ORDER BY w.occurred_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return cur.fetchall()


def fetch_credentials(limit: int = 200) -> list[sqlite3.Row]:
    with cursor() as cur:
        cur.execute(
            """
            SELECT id,
                   connection_id,
                   source_ip,
                   username,
                   password,
                   auth_method,
                   accepted,
                   attempted_at,
                   source
            FROM (
                SELECT cr.id,
                       cr.connection_id,
                       co.source_ip,
                       cr.username,
                       cr.password,
                       cr.auth_method,
                       cr.accepted,
                       cr.attempted_at,
                       'ssh' AS source
                FROM credentials cr
                JOIN connections co ON co.id = cr.connection_id

                UNION ALL

                SELECT w.id,
                       NULL AS connection_id,
                       w.source_ip,
                       w.username,
                       w.password,
                       'form' AS auth_method,
                       0 AS accepted,
                       w.occurred_at AS attempted_at,
                       'web' AS source
                FROM web_hits w
                WHERE w.username IS NOT NULL OR w.password IS NOT NULL
            )
            ORDER BY attempted_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return cur.fetchall()


def fetch_top_credentials(limit: int = 20) -> list[sqlite3.Row]:
    with cursor() as cur:
        cur.execute(
            """
            SELECT username, password, COUNT(*) AS hits
            FROM (
                SELECT username, password
                FROM credentials

                UNION ALL

                SELECT username, password
                FROM web_hits
                WHERE username IS NOT NULL OR password IS NOT NULL
            )
            WHERE COALESCE(username, '') <> '' OR COALESCE(password, '') <> ''
            GROUP BY username, password
            ORDER BY hits DESC
            LIMIT ?
            """,
            (limit,),
        )
        return cur.fetchall()


def fetch_commands(limit: int = 200) -> list[sqlite3.Row]:
    with cursor() as cur:
        cur.execute(
            """
            SELECT cm.*, co.source_ip
            FROM commands cm
            JOIN connections co ON co.id = cm.connection_id
            ORDER BY cm.issued_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return cur.fetchall()


def fetch_attack_timeseries(hours: int = 24) -> list[sqlite3.Row]:
    """Hourly bucketed SSH + web event counts for the last N hours."""
    with cursor() as cur:
        cur.execute(
            """
            SELECT strftime('%Y-%m-%dT%H:00:00', occurred_at) AS bucket,
                   COUNT(*) AS count
            FROM (
                SELECT started_at AS occurred_at FROM connections
                UNION ALL
                SELECT occurred_at FROM web_hits
            )
            WHERE datetime(occurred_at) >= datetime('now', ?)
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            (f"-{hours} hours",),
        )
        return cur.fetchall()


def fetch_geo_distribution() -> list[sqlite3.Row]:
    with cursor() as cur:
        cur.execute(
            """
            SELECT g.country, COUNT(*) AS count
            FROM (
                SELECT source_ip FROM connections
                UNION ALL
                SELECT source_ip FROM web_hits
            ) e
            JOIN geo_cache g ON g.ip = e.source_ip
            WHERE g.country IS NOT NULL
            GROUP BY g.country
            ORDER BY count DESC
            LIMIT 15
            """
        )
        return cur.fetchall()


def fetch_summary_stats() -> dict:
    with cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM connections")
        total_connections = cur.fetchone()["n"]

        cur.execute(
            """
            SELECT COUNT(DISTINCT source_ip) AS n
            FROM (
                SELECT source_ip FROM connections
                UNION ALL
                SELECT source_ip FROM web_hits
            )
            """
        )
        unique_ips = cur.fetchone()["n"]

        cur.execute("SELECT COUNT(*) AS n FROM credentials")
        ssh_creds = cur.fetchone()["n"]

        cur.execute(
            """
            SELECT COUNT(*) AS n
            FROM web_hits
            WHERE username IS NOT NULL OR password IS NOT NULL
            """
        )
        web_creds = cur.fetchone()["n"]

        cur.execute("SELECT COUNT(*) AS n FROM commands")
        total_commands = cur.fetchone()["n"]

        cur.execute("SELECT COUNT(*) AS n FROM web_hits")
        total_web_hits = cur.fetchone()["n"]

        cur.execute(
            """
            SELECT COUNT(*) AS n
            FROM (
                SELECT started_at AS occurred_at FROM connections
                UNION ALL
                SELECT occurred_at FROM web_hits
            )
            WHERE datetime(occurred_at) >= datetime('now', '-24 hours')
            """
        )
        last_24h = cur.fetchone()["n"]

        return {
            "total_connections": total_connections,
            "unique_ips": unique_ips,
            "total_credentials": ssh_creds + web_creds,
            "total_commands": total_commands,
            "total_web_hits": total_web_hits,
            "last_24h": last_24h,
        }


def fetch_map_points() -> list[sqlite3.Row]:
    with cursor() as cur:
        cur.execute(
            """
            SELECT g.ip, g.country, g.region, g.city, g.lat, g.lon, COUNT(*) AS hits
            FROM geo_cache g
            JOIN (
                SELECT source_ip FROM connections
                UNION ALL
                SELECT source_ip FROM web_hits
            ) e ON e.source_ip = g.ip
            WHERE g.lat IS NOT NULL AND g.lon IS NOT NULL
            GROUP BY g.ip
            """
        )
        return cur.fetchall()
