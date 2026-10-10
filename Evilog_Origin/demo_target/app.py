"""
AI Conference Demo Website — self-contained Flask app.
Run with: python app.py
"""
import os
import argparse
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash

from data import (
    SPEAKERS,
    SESSIONS,
    AGENDA_DAYS,
    TICKET_TYPES,
    MOCK_USERS,
    get_speaker,
    get_sessions_for_speaker,
    get_sessions_by_day,
    search_sessions,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "demo-secret-change-in-production")

# Logging: single text file for critical operations and errors
_log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(_log_dir, exist_ok=True)
_log_path = os.path.join(_log_dir, "app.log")
logger = logging.getLogger("app")
logger.setLevel(logging.INFO)
_fh = logging.FileHandler(_log_path, encoding="utf-8")
_fh.setLevel(logging.INFO)
_fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s"))
logger.addHandler(_fh)

# --- lightweight per-endpoint metrics (real observability, for Axis-1 live test) ---
from collections import defaultdict as _dd
from datetime import datetime as _dt
_metrics = _dd(lambda: {"req": 0, "err": 0})


@app.after_request
def _count(resp):
    # route(endpoint) 단위로 집계; 404 등 미매칭은 하나의 'not_found' 버킷으로 정규화
    key = request.endpoint if request.endpoint else "not_found"
    if key not in ("_metrics_endpoint",):
        _metrics[key]["req"] += 1
        if resp.status_code >= 400:
            _metrics[key]["err"] += 1
    return resp


@app.route("/api/data")
def _api_data():
    # 진짜 고장난 엔드포인트(실제 근본원인) — 백엔드 장애로 500 발생
    raise RuntimeError("backend datastore connection pool exhausted")


@app.route("/internal/metrics")
def _metrics_endpoint():
    ts = _dt.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [f"{ts} endpoint={k} http_requests_total={v['req']} http_errors_total={v['err']}"
             for k, v in sorted(_metrics.items())]
    return ("\n".join(lines) + "\n"), 200, {"Content-Type": "text/plain"}


@app.route("/")
def index():
    return render_template("index.html", speakers=SPEAKERS[:3], sessions=SESSIONS[:4])


@app.route("/agenda")
def agenda():
    day = request.args.get("day", type=int, default=1)
    day_sessions = get_sessions_by_day(day) if day in (1, 2) else get_sessions_by_day(1)
    return render_template(
        "agenda.html",
        days=AGENDA_DAYS,
        active_day=day,
        sessions=day_sessions,
        get_speaker=get_speaker,
    )


@app.route("/sessions")
def sessions_list():
    q = request.args.get("q", "").strip()
    sessions = search_sessions(q) if q else SESSIONS
    return render_template(
        "sessions.html",
        sessions=sessions,
        query=q,
        get_speaker=get_speaker,
    )


@app.route("/sessions/<session_id>")
def session_detail(session_id):
    s = next((x for x in SESSIONS if x["id"] == session_id), None)
    if not s:
        return render_template("404.html"), 404
    return render_template("session_detail.html", s=s, speaker=get_speaker(s["speaker_id"]))


@app.route("/speakers")
def speakers():
    return render_template("speakers.html", speakers=SPEAKERS)


@app.route("/speakers/<speaker_id>")
def speaker_detail(speaker_id):
    speaker = get_speaker(speaker_id)
    if not speaker:
        return render_template("404.html"), 404
    talks = get_sessions_for_speaker(speaker_id)
    return render_template("speaker_detail.html", speaker=speaker, sessions=talks)


@app.route("/tickets", methods=["GET", "POST"])
def tickets():
    if request.method == "POST":
        ticket_type = request.form.get("ticket_type")
        email = request.form.get("email", "").strip()
        name = request.form.get("name", "").strip()
        if not ticket_type or ticket_type not in {t["id"] for t in TICKET_TYPES}:
            logger.warning("Ticket validation failed reason=invalid_type")
            flash("Please select a valid ticket type.", "error")
            return redirect(url_for("tickets"))
        if not email or not name:
            logger.warning("Ticket validation failed reason=missing_name_or_email")
            flash("Name and email are required.", "error")
            return redirect(url_for("tickets"))
        session["last_ticket_order"] = {"type": ticket_type, "email": email, "name": name}
        logger.info("Ticket order submitted type=%s", ticket_type)
        return redirect(url_for("tickets_confirm"))
    return render_template("tickets.html", ticket_types=TICKET_TYPES)


@app.route("/tickets/confirm")
def tickets_confirm():
    order = session.get("last_ticket_order")
    if not order:
        logger.warning("Tickets confirm accessed without order redirect=tickets")
        return redirect(url_for("tickets"))
    ticket = next((t for t in TICKET_TYPES if t["id"] == order["type"]), None)
    return render_template("tickets_confirm.html", order=order, ticket=ticket)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = MOCK_USERS.get(email)
        if user and user["password"] == password:
            session["user"] = {"email": email, "name": user["name"]}
            logger.info("Login successful email=%s", email)
            flash(f"Welcome back, {user['name']}!", "success")
            return redirect(request.args.get("next") or url_for("index"))
        logger.warning("Login failed email=%s", email)
        flash("Invalid email or password. Try demo@example.com / demo for demo.", "error")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    email = session.get("user", {}).get("email", "unknown")
    session.pop("user", None)
    logger.info("User logged out email=%s", email)
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/profile")
def profile():
    if "user" not in session:
        logger.warning("Profile access denied redirect=login")
        flash("Please log in to view your profile.", "warning")
        return redirect(url_for("login", next=url_for("profile")))
    return render_template("profile.html", user=session["user"])


@app.errorhandler(404)
def not_found(e):
    logger.warning("404 Not Found path=%s referrer=%s", request.path, request.referrer)
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(e):
    logger.error("Uncaught exception", exc_info=True)
    return render_template("404.html"), 500


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", type=str, default="localhost")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug)
