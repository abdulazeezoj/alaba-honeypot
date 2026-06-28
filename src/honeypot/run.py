"""
Entrypoint: starts the geo-enrichment worker, the SSH honeypot (on a
background thread), and the Flask app (foreground, serving both the decoy
login portal and the dashboard) in one process.

Usage:
    uv run honeypot
    uv run honeypot --ssh-port 2222 --web-port 8080
"""

from __future__ import annotations

import argparse
import logging
import threading

from honeypot import db, ssh_server
from honeypot.geoip import enricher
from honeypot.web import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("honeypot")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SSH + web honeypot with live dashboard")
    parser.add_argument("--ssh-host", default="0.0.0.0", help="Bind address for the fake SSH server")
    parser.add_argument("--ssh-port", type=int, default=2222, help="Port for the fake SSH server (default 2222; use a reverse proxy/iptables rule to expose it as 22)")
    parser.add_argument("--web-host", default="0.0.0.0", help="Bind address for the Flask app")
    parser.add_argument("--web-port", type=int, default=8080, help="Port for the decoy login portal + dashboard")
    parser.add_argument("--no-geo", action="store_true", help="Disable ip-api.com geolocation enrichment")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    db.init_db()

    if not args.no_geo:
        enricher.start()
        enricher.backfill_missing()
        logger.info("geolocation enrichment enabled (ip-api.com)")
    else:
        logger.info("geolocation enrichment disabled (--no-geo)")

    ssh_thread = threading.Thread(
        target=ssh_server.serve,
        kwargs={"host": args.ssh_host, "port": args.ssh_port},
        daemon=True,
        name="ssh-honeypot",
    )
    ssh_thread.start()
    logger.info("SSH honeypot thread started on %s:%d", args.ssh_host, args.ssh_port)

    app = create_app()
    logger.info("dashboard + decoy portal available at http://%s:%d", args.web_host, args.web_port)
    logger.info("dashboard: http://%s:%d/dashboard", args.web_host, args.web_port)
    app.run(host=args.web_host, port=args.web_port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
