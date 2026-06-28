"""
Flask application: serves two distinct surfaces from one app.

1. The decoy: a fake login portal (`/`, `/login`) designed to be the thing
   an attacker scanning the web port actually hits. Every visit and every
   submitted credential is logged exactly like the SSH side.

2. The dashboard: `/dashboard` (HTML) and `/api/*` (JSON) for the Chart.js
   visualisations -- attack frequency over time, geographic distribution,
   and credential frequency tables. This is the operator-facing view and
   is intentionally placed at a separate, non-obvious path.
"""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from honeypot import db
from honeypot.geoip import enricher


def _client_ip() -> str:
    # Respect X-Forwarded-For if this is sitting behind a reverse proxy,
    # otherwise fall back to the direct peer address.
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def create_app() -> Flask:
    app = Flask(__name__)
    db.init_db()

    # ---------------------------------------------------------------
    # Decoy surface
    # ---------------------------------------------------------------

    @app.route("/")
    def decoy_index():
        ip = _client_ip()
        db.log_web_hit(ip, "/", "GET", user_agent=request.headers.get("User-Agent"))
        enricher.submit(ip)
        return render_template("login.html")

    @app.route("/login", methods=["GET", "POST"])
    def decoy_login():
        ip = _client_ip()
        enricher.submit(ip)

        if request.method == "GET":
            db.log_web_hit(ip, "/login", "GET", user_agent=request.headers.get("User-Agent"))
            return render_template("login.html")

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db.log_web_hit(
            ip,
            "/login",
            "POST",
            username=username,
            password=password,
            user_agent=request.headers.get("User-Agent"),
        )
        # Always reject. The point isn't to grant access -- it's to collect
        # the attempted credentials and let the attacker keep trying.
        return render_template("login.html", error="Invalid username or password.")

    # ---------------------------------------------------------------
    # Dashboard surface
    # ---------------------------------------------------------------

    @app.route("/dashboard")
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/api/summary")
    def api_summary():
        return jsonify(db.fetch_summary_stats())

    @app.route("/api/connections")
    def api_connections():
        limit = request.args.get("limit", 100, type=int)
        rows = db.fetch_recent_connections(limit=limit)
        return jsonify([dict(row) for row in rows])

    @app.route("/api/web-hits")
    def api_web_hits():
        limit = request.args.get("limit", 100, type=int)
        rows = db.fetch_recent_web_hits(limit=limit)
        return jsonify([dict(row) for row in rows])

    @app.route("/api/credentials")
    def api_credentials():
        limit = request.args.get("limit", 200, type=int)
        rows = db.fetch_credentials(limit=limit)
        return jsonify([dict(row) for row in rows])

    @app.route("/api/credentials/top")
    def api_top_credentials():
        limit = request.args.get("limit", 20, type=int)
        rows = db.fetch_top_credentials(limit=limit)
        return jsonify([dict(row) for row in rows])

    @app.route("/api/commands")
    def api_commands():
        limit = request.args.get("limit", 200, type=int)
        rows = db.fetch_commands(limit=limit)
        return jsonify([dict(row) for row in rows])

    @app.route("/api/timeseries")
    def api_timeseries():
        hours = request.args.get("hours", 24, type=int)
        rows = db.fetch_attack_timeseries(hours=hours)
        return jsonify([dict(row) for row in rows])

    @app.route("/api/geo-distribution")
    def api_geo_distribution():
        rows = db.fetch_geo_distribution()
        return jsonify([dict(row) for row in rows])

    @app.route("/api/map-points")
    def api_map_points():
        rows = db.fetch_map_points()
        return jsonify([dict(row) for row in rows])

    return app
