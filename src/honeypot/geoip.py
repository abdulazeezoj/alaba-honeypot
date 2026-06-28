"""
Async IP geolocation enrichment via ip-api.com (free tier).

Design notes:
- The free tier of ip-api.com is rate limited to 45 requests/minute from a
  single IP. We respect that with a simple token-bucket style throttle
  rather than firing requests as fast as asyncio.gather() would otherwise
  allow.
- ip-api.com also offers a batch endpoint (POST /batch, up to 100 IPs per
  call), which we prefer when enriching a backlog of many IPs at once
  (e.g. on startup) since it costs far fewer requests against the quota
  than looking up one IP at a time.
- Lookups never block the SSH accept/auth loop: the SSH server only writes
  the raw connection row and hands the IP off to this module, which runs
  enrichment in its own background asyncio event loop on a dedicated
  thread.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections import deque

import httpx

from honeypot import db

logger = logging.getLogger("honeypot.geoip")

IP_API_SINGLE_URL = "http://ip-api.com/json/{ip}"
IP_API_BATCH_URL = "http://ip-api.com/batch"
FIELDS = "status,message,country,regionName,city,isp,lat,lon,query"

# Free tier: 45 requests/minute. Keep a safety margin.
MAX_REQUESTS_PER_MINUTE = 40

# Private/reserved ranges show up constantly in honeypot logs (local testing,
# scanners behind NAT relays that leak internal hops, etc.) and ip-api.com
# will just return a "private range" failure for them, wasting a request.
_PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.")


def _is_skippable(ip: str) -> bool:
    if ip.startswith(_PRIVATE_PREFIXES):
        return True
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            return 16 <= second_octet <= 31
        except (IndexError, ValueError):
            return False
    return False


class RateLimiter:
    """Simple sliding-window limiter: at most `max_calls` calls per `period` seconds."""

    def __init__(self, max_calls: int, period: float = 60.0):
        self.max_calls = max_calls
        self.period = period
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            while self._timestamps and now - self._timestamps[0] > self.period:
                self._timestamps.popleft()
            if len(self._timestamps) >= self.max_calls:
                sleep_for = self.period - (now - self._timestamps[0])
                if sleep_for > 0:
                    await asyncio.sleep(sleep_for)
            self._timestamps.append(time.monotonic())


class GeoEnricher:
    """
    Owns a background event loop (on its own thread) plus a queue of IPs
    waiting to be looked up. The SSH server and Flask routes are synchronous
    code, so they call `submit(ip)` (non-blocking, thread-safe) instead of
    awaiting anything directly.
    """

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._queue: asyncio.Queue[str] | None = None
        self._limiter = RateLimiter(MAX_REQUESTS_PER_MINUTE)
        self._started = threading.Event()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="geoip-loop")
        self._thread.start()
        self._started.wait(timeout=5)

    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._queue = asyncio.Queue()
        self._started.set()
        self._loop.create_task(self._worker())
        self._loop.run_forever()

    async def _worker(self) -> None:
        async with httpx.AsyncClient(timeout=10.0) as client:
            while True:
                ip = await self._queue.get()
                try:
                    await self._lookup_one(client, ip)
                except Exception:
                    logger.exception("geo lookup failed for %s", ip)

    async def _lookup_one(self, client: httpx.AsyncClient, ip: str) -> None:
        if db.get_cached_geo(ip) is not None:
            return
        if _is_skippable(ip):
            return

        await self._limiter.acquire()
        url = IP_API_SINGLE_URL.format(ip=ip)
        resp = await client.get(url, params={"fields": FIELDS})
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "success":
            logger.info("geo lookup unavailable for %s: %s", ip, data.get("message"))
            return

        geo = db.GeoInfo(
            country=data.get("country"),
            region=data.get("regionName"),
            city=data.get("city"),
            isp=data.get("isp"),
            lat=data.get("lat"),
            lon=data.get("lon"),
        )
        db.upsert_geo(ip, geo)
        logger.info("enriched %s -> %s, %s", ip, geo.city, geo.country)

    def submit(self, ip: str) -> None:
        """Thread-safe, non-blocking: queue an IP for enrichment."""
        if not self._started.is_set() or self._loop is None or self._queue is None:
            return
        if _is_skippable(ip):
            return
        self._loop.call_soon_threadsafe(self._queue.put_nowait, ip)

    async def _batch_lookup(self, ips: list[str]) -> None:
        """Use ip-api.com's batch endpoint for a backlog of IPs (max 100/call)."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            for chunk_start in range(0, len(ips), 100):
                chunk = ips[chunk_start : chunk_start + 100]
                await self._limiter.acquire()
                payload = [{"query": ip, "fields": FIELDS} for ip in chunk]
                resp = await client.post(IP_API_BATCH_URL, json=payload)
                resp.raise_for_status()
                for entry in resp.json():
                    if entry.get("status") != "success":
                        continue
                    ip = entry.get("query")
                    geo = db.GeoInfo(
                        country=entry.get("country"),
                        region=entry.get("regionName"),
                        city=entry.get("city"),
                        isp=entry.get("isp"),
                        lat=entry.get("lat"),
                        lon=entry.get("lon"),
                    )
                    db.upsert_geo(ip, geo)

    def backfill_missing(self) -> None:
        """
        Look up any IPs already in the DB that don't have geo data yet
        (e.g. captured while this service was offline, or before this
        feature existed). Safe to call on startup.
        """
        missing = [ip for ip in db.ips_missing_geo() if not _is_skippable(ip)]
        if not missing or self._loop is None:
            return
        logger.info("backfilling geo data for %d IP(s)", len(missing))
        asyncio.run_coroutine_threadsafe(self._batch_lookup(missing), self._loop)


# Module-level singleton, started once from run.py
enricher = GeoEnricher()
