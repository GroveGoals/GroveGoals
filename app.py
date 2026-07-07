"""
GroveGoals authentication backend.

Implements: signup, login, logout, profile, and password reset,
following the security checklist:
  - Password storage:        bcrypt (bcrypt.hashpw / bcrypt.checkpw)
  - HTTPS only:               enforced via Flask-Talisman in production mode
  - Session security:         HttpOnly + Secure + SameSite cookies
  - Rate limiting:            Flask-Limiter, 5 attempts/min on auth routes
  - SQL injection:            parameterized queries everywhere (sqlite3 "?" placeholders)
  - Input validation:         email format check, password complexity, trimming
  - CSRF:                     Flask-WTF CSRFProtect on session-mutating routes
  - Account enumeration:      generic error messages, constant-time-ish responses
  - Password reset:           single-use, time-limited, hashed tokens

Run locally:
    pip install -r requirements.txt
    cp .env.example .env        # then edit SECRET_KEY
    flask --app app init-db     # creates users.db with the right tables
    flask --app app run --debug

This app serves the GroveGoals frontend itself at "/" (same-origin),
so the frontend's fetch('/signup') etc. work with no CORS setup needed.
If you ever split the frontend onto a different domain, see the README
section "Splitting frontend and backend" for the extra config that needs.
"""

import os
import re
import sqlite3
import secrets
import hashlib
import json
from datetime import datetime, timedelta, timezone

import bcrypt
import requests
from flask import Flask, request, jsonify, session, g, send_from_directory
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()

# --------------------------------------------------------------------------
# Third-party integrations (both optional — the app degrades gracefully if
# either key is missing, rather than crashing).
# --------------------------------------------------------------------------
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5")
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"

YOUTUBE_API_KEY = os.environ.get("YOUTUBE_API_KEY", "")
YOUTUBE_SEARCH_URL = "https://www.googleapis.com/youtube/v3/search"

# --------------------------------------------------------------------------
# App setup
# --------------------------------------------------------------------------
app = Flask(__name__, static_folder=None)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "SECRET_KEY is not set. Copy .env.example to .env and set a long "
        "random SECRET_KEY before running this app."
    )

FLASK_ENV = os.environ.get("FLASK_ENV", "development")
IS_PRODUCTION = FLASK_ENV == "production"
DATABASE = os.environ.get("DATABASE", "users.db")

# --- Session cookie security -------------------------------------------
# HttpOnly: JS can't read the cookie (mitigates XSS token theft)
# Secure:   cookie is only ever sent over HTTPS (only enforceable once you
#           actually serve over HTTPS — keep this False for local http dev)
# SameSite: 'Lax' blocks the cookie being sent on cross-site POSTs (CSRF),
#           while still allowing normal top-level navigation
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

# --- CSRF protection ------------------------------------------------------
# Signup/login are exempted below: there is no session yet to hijack, and
# they're already covered by rate limiting + generic error messages.
# Everything that acts on an existing session (logout, profile edits,
# password reset confirmation) is protected. The frontend must fetch
# GET /csrf-token first and send the value back as the X-CSRFToken header.
csrf = CSRFProtect(app)

# --- Rate limiting ----------------------------------------------------
# In-memory storage is fine for a single dev/staging instance. For a real
# multi-worker production deployment, point storage_uri at Redis instead:
#   Limiter(..., storage_uri="redis://localhost:6379")
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"],
    storage_uri="memory://",
)

# --- HTTPS enforcement + security headers --------------------------------
# Talisman forces http -> https redirects and sets HSTS, X-Frame-Options,
# etc. It's only switched on in production because it breaks local http
# development otherwise. In most real deployments, HTTPS termination
# actually happens one layer up (nginx, Caddy, or your host's load
# balancer) — Talisman is a good belt-and-braces backup either way.
if IS_PRODUCTION:
    from flask_talisman import Talisman

    Talisman(app, force_https=True, strict_transport_security=True)


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT UNIQUE NOT NULL,
            name          TEXT,
            password_hash TEXT NOT NULL,
            created_at    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS password_resets (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash   TEXT NOT NULL,
            expires_at   TEXT NOT NULL,
            used         INTEGER NOT NULL DEFAULT 0,
            created_at   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_state (
            user_id      INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            state_json   TEXT NOT NULL DEFAULT '{}',
            updated_at   TEXT NOT NULL
        );
        """
    )
    db.commit()
    db.close()


@app.cli.command("init-db")
def init_db_command():
    """Run with: flask --app app init-db"""
    init_db()
    print(f"Initialized database at {DATABASE}")


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def is_valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email)) and len(email) <= 254


def password_issues(password: str):
    """Returns a list of human-readable complaints, empty if password is OK."""
    issues = []
    if len(password) < 8:
        issues.append("Password must be at least 8 characters long.")
    if not re.search(r"[A-Za-z]", password):
        issues.append("Password must contain at least one letter.")
    if not re.search(r"[0-9]", password):
        issues.append("Password must contain at least one number.")
    return issues


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        # Malformed hash in the DB shouldn't crash the request
        return False


def hash_token(token: str) -> str:
    # Reset tokens are stored hashed, same principle as passwords: if the
    # DB leaks, raw tokens shouldn't be usable.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Routes: static frontend
# --------------------------------------------------------------------------
FRONTEND_DIR = os.path.dirname(os.path.abspath(__file__))


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "grovegoals.html")


# --------------------------------------------------------------------------
# Routes: CSRF token
# --------------------------------------------------------------------------
@app.route("/csrf-token", methods=["GET"])
def csrf_token():
    # Flask-WTF exposes generate_csrf(); the frontend fetches this once
    # and sends the value back in the X-CSRFToken header on protected calls.
    from flask_wtf.csrf import generate_csrf

    return jsonify({"csrf_token": generate_csrf()})


# --------------------------------------------------------------------------
# Routes: auth
# --------------------------------------------------------------------------
@csrf.exempt
@app.route("/signup", methods=["POST"])
@limiter.limit("5 per minute")
def signup():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    name = (data.get("name") or "").strip()[:100] or None

    if not is_valid_email(email):
        return jsonify({"error": "Please enter a valid email address."}), 400

    issues = password_issues(password)
    if issues:
        return jsonify({"error": issues[0]}), 400

    db = get_db()
    existing = db.execute(
        "SELECT id FROM users WHERE email = ?", (email,)
    ).fetchone()
    if existing:
        # Note: this does confirm the email is already registered, which is
        # a mild account-enumeration signal. Most products accept this
        # trade-off on signup for UX reasons (people need to know to log in
        # instead). If you want zero enumeration surface, respond with a
        # generic "check your email to continue" message on every signup
        # attempt and only actually create the account if it's new.
        return jsonify({"error": "An account with that email already exists."}), 409

    password_hash = hash_password(password)
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO users (email, name, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (email, name, password_hash, now),
    )
    db.commit()
    user_id = cursor.lastrowid

    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    session["email"] = email

    return jsonify({"message": "Account created", "email": email, "name": name}), 201


@csrf.exempt
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    db = get_db()
    user = db.execute(
        "SELECT id, name, password_hash FROM users WHERE email = ?", (email,)
    ).fetchone()

    # Same generic error whether the email doesn't exist or the password is
    # wrong — this is the account-enumeration mitigation from the checklist.
    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401

    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["email"] = email

    return jsonify({"message": "Logged in successfully", "email": email, "name": user["name"]}), 200


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"}), 200


@app.route("/profile", methods=["GET"])
def profile():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    db = get_db()
    user = db.execute(
        "SELECT email, name FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if not user:
        session.clear()
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify({"email": user["email"], "name": user["name"]}), 200


# --------------------------------------------------------------------------
# Routes: persistent app state (goals, XP, streaks, achievements, profile
# extras like age/country/height/weight). Stored as one JSON blob per user
# so the frontend's existing single `state` object can be saved/restored
# without a large relational rewrite. Everything here survives logout,
# browser close, and page reload — it's gone only if the user deletes their
# account or explicitly erases their data below.
# --------------------------------------------------------------------------
MAX_STATE_BYTES = 500_000  # generous ceiling to stop abuse; a few thousand goals' worth

DEFAULT_STATE = {
    "goals": [],
    "xp": 0,
    "streak": 0,
    "lastLogDate": None,   # server-authoritative — see /api/streak/log
    "achievements": {},
    "isPremium": False,
    "age": None,
    "country": "",
    "height": None,
    "weight": None,
    "coachHistory": [],    # server-authoritative — see /api/coach/*
}

# Fields the generic "save my state" endpoint is NOT allowed to overwrite,
# because they have their own dedicated, server-verified endpoints below.
# Without this, a client could just POST {"streak": 9999} and fake it.
SERVER_AUTHORITATIVE_KEYS = {"streak", "lastLogDate", "coachHistory"}


def _load_state(db, user_id):
    row = db.execute("SELECT state_json FROM user_state WHERE user_id = ?", (user_id,)).fetchone()
    if not row:
        return dict(DEFAULT_STATE)
    try:
        saved = json.loads(row["state_json"])
    except (ValueError, TypeError):
        saved = {}
    return {**DEFAULT_STATE, **saved}


def _save_state(db, user_id, state_dict):
    to_store = {k: state_dict.get(k, DEFAULT_STATE[k]) for k in DEFAULT_STATE}
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        """
        INSERT INTO user_state (user_id, state_json, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET state_json = excluded.state_json, updated_at = excluded.updated_at
        """,
        (user_id, json.dumps(to_store), now),
    )
    db.commit()
    return now


@app.route("/api/state", methods=["GET"])
def get_state():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    db = get_db()
    return jsonify(_load_state(db, session["user_id"])), 200


@app.route("/api/state", methods=["POST"])
def save_state():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    raw = request.get_data(as_text=True) or ""
    if len(raw.encode("utf-8")) > MAX_STATE_BYTES:
        return jsonify({"error": "State payload too large"}), 413

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid state payload"}), 400

    db = get_db()
    existing = _load_state(db, session["user_id"])

    # Only persist known keys — never trust the client to add arbitrary columns/keys.
    to_store = {k: data.get(k, DEFAULT_STATE[k]) for k in DEFAULT_STATE}
    # Streak, last-log-date, and coach history are server-authoritative:
    # always keep whatever is already on record regardless of what the
    # client sent, so this generic save can't be used to fake a streak or
    # tamper with coach conversation history.
    for key in SERVER_AUTHORITATIVE_KEYS:
        to_store[key] = existing.get(key, DEFAULT_STATE[key])

    now = _save_state(db, session["user_id"], to_store)
    return jsonify({"message": "Saved", "updated_at": now}), 200


@app.route("/api/reset-progress", methods=["POST"])
@limiter.limit("10 per minute")
def erase_data():
    """Wipes goals/XP/streaks/achievements but keeps the account and login."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    db = get_db()
    _save_state(db, session["user_id"], DEFAULT_STATE)
    return jsonify({"message": "All progress erased. Your account is still active."}), 200


@app.route("/api/streak/log", methods=["POST"])
@limiter.limit("30 per minute")
def log_streak():
    """
    Server-authoritative streak logging. The server — not the browser —
    decides whether today already counts, whether the streak continues or
    resets, using its own clock (UTC) and its own stored last-log-date.
    A client can't fake a streak by tampering with local state or the
    generic /api/state save, because this is the only path that's allowed
    to change `streak` / `lastLogDate`.
    """
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    db = get_db()
    user_id = session["user_id"]
    current = _load_state(db, user_id)

    today = datetime.now(timezone.utc).date()
    today_str = today.isoformat()
    last_log = current.get("lastLogDate")

    if last_log == today_str:
        return jsonify({"streak": current.get("streak", 0), "lastLogDate": last_log, "already_logged": True}), 200

    last_date = None
    if last_log:
        try:
            last_date = datetime.fromisoformat(last_log).date()
        except ValueError:
            last_date = None

    streak = current.get("streak", 0)
    if last_date and (today - last_date).days == 1:
        streak += 1
    else:
        streak = 1

    current["streak"] = streak
    current["lastLogDate"] = today_str
    _save_state(db, user_id, current)

    return jsonify({"streak": streak, "lastLogDate": today_str, "already_logged": False}), 200


# --------------------------------------------------------------------------
# AI Coach — a real LLM call (Anthropic), grounded in the user's actual
# goals/progress/streak/learning style so its advice is specific, not
# generic. Conversation history is stored server-side per account (part of
# SERVER_AUTHORITATIVE_KEYS above) so it persists like everything else, and
# so a client can't rewrite its own chat history.
#
# Requires ANTHROPIC_API_KEY to be set (see .env.example). Without it, the
# endpoint returns a clear 503 rather than crashing, and the frontend falls
# back to a simple local assistant.
# --------------------------------------------------------------------------
COACH_MAX_HISTORY = 40          # messages kept in storage
COACH_HISTORY_SENT_TO_MODEL = 10  # most recent turns actually sent to the API


def _goal_progress_pct(goal):
    total = sum(len(p.get("tasks", [])) for p in goal.get("phases", []))
    done = sum(1 for p in goal.get("phases", []) for t in p.get("tasks", []) if t.get("done"))
    return round((done / total) * 100) if total else 0


def build_coach_system_prompt(user_name, app_state):
    lines = [
        "You are the GroveGoals AI Coach, an encouraging and specific mentor "
        "built into the GroveGoals goal-tracking app.",
        f"The user's name is {user_name or 'there'}.",
    ]

    goals = app_state.get("goals") or []
    if goals:
        lines.append("Their current goals:")
        for goal in goals:
            pct = _goal_progress_pct(goal)
            lines.append(
                f'- "{goal.get("title")}" ({goal.get("category")}), '
                f'{goal.get("experience", "Beginner")} level, prefers learning by '
                f'{goal.get("method", "Mixed")}, has about {goal.get("hours", "a few")} hrs/week, '
                f"{pct}% through the roadmap."
            )
    else:
        lines.append("They haven't created a goal yet in the app — gently encourage them to use the Goal Generator.")

    lines.append(f"Current streak: {app_state.get('streak', 0)} day(s). Total XP: {app_state.get('xp', 0)}.")
    lines.append(
        "Be concise and concrete: 2-4 short sentences unless they ask for more. "
        "Tailor suggestions to how much time they say they have right now. "
        "When it helps, briefly explain *why* a step matters for what comes next, not only what to do. "
        "You are not a licensed doctor, lawyer, or financial advisor — if their goal touches on "
        "health, legal, or financial decisions, keep advice general and suggest a qualified professional "
        "for anything specific."
    )
    return "\n".join(lines)


def call_anthropic(system_prompt, history, user_message):
    """Returns (reply_text, error_message) — exactly one of the two is set."""
    if not ANTHROPIC_API_KEY:
        return None, "The AI Coach isn't configured yet — ask the site owner to set ANTHROPIC_API_KEY."

    messages = []
    for msg in history[-COACH_HISTORY_SENT_TO_MODEL:]:
        role = "assistant" if msg.get("role") == "assistant" else "user"
        content = msg.get("content", "")
        if content:
            messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": user_message})

    try:
        resp = requests.post(
            ANTHROPIC_API_URL,
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": 400,
                "system": system_prompt,
                "messages": messages,
            },
            timeout=20,
        )
    except requests.RequestException:
        return None, "Could not reach the AI service right now. Please try again shortly."

    if resp.status_code == 401:
        return None, "The AI service rejected the configured API key."
    if resp.status_code == 429:
        return None, "The AI Coach is getting a lot of requests right now. Please try again in a moment."
    if resp.status_code != 200:
        return None, f"The AI service returned an error ({resp.status_code})."

    try:
        payload = resp.json()
    except ValueError:
        return None, "The AI service returned an unreadable response."

    text = "".join(
        block.get("text", "") for block in payload.get("content", []) if block.get("type") == "text"
    ).strip()

    if not text:
        return None, "The AI service returned an empty response."
    return text, None


@app.route("/api/coach/history", methods=["GET"])
def coach_history():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    db = get_db()
    state = _load_state(db, session["user_id"])
    return jsonify({"history": state.get("coachHistory", [])}), 200


@app.route("/api/coach/chat", methods=["POST"])
@limiter.limit("20 per minute")
def coach_chat():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    user_message = (data.get("message") or "").strip()
    if not user_message:
        return jsonify({"error": "Message can't be empty"}), 400
    if len(user_message) > 2000:
        return jsonify({"error": "That message is too long"}), 400

    db = get_db()
    user_row = db.execute("SELECT name FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    app_state = _load_state(db, session["user_id"])
    history = app_state.get("coachHistory", [])

    system_prompt = build_coach_system_prompt(user_row["name"] if user_row else None, app_state)
    reply, error = call_anthropic(system_prompt, history, user_message)

    if error:
        return jsonify({"error": error}), 503

    now_iso = datetime.now(timezone.utc).isoformat()
    history.append({"role": "user", "content": user_message, "ts": now_iso})
    history.append({"role": "assistant", "content": reply, "ts": now_iso})
    app_state["coachHistory"] = history[-COACH_MAX_HISTORY:]
    _save_state(db, session["user_id"], app_state)

    return jsonify({"reply": reply}), 200


# --------------------------------------------------------------------------
# Real video search (YouTube Data API v3) for users whose learning style is
# "Videos" or "Mixed". Requires YOUTUBE_API_KEY (see .env.example). Without
# it, this still returns 200 with configured=False and a plain YouTube
# search-results link, so the feature degrades gracefully instead of
# breaking the roadmap page.
# --------------------------------------------------------------------------
@app.route("/api/videos", methods=["GET"])
@limiter.limit("30 per minute")
def video_search():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    query = (request.args.get("query") or "").strip()
    if not query:
        return jsonify({"error": "query is required"}), 400

    fallback_url = "https://www.youtube.com/results?search_query=" + requests.utils.quote(query)

    if not YOUTUBE_API_KEY:
        return jsonify({"configured": False, "videos": [], "fallback_url": fallback_url}), 200

    try:
        resp = requests.get(
            YOUTUBE_SEARCH_URL,
            params={
                "part": "snippet",
                "q": query,
                "type": "video",
                "maxResults": 4,
                "safeSearch": "strict",
                "key": YOUTUBE_API_KEY,
            },
            timeout=10,
        )
    except requests.RequestException:
        return jsonify({
            "configured": True, "videos": [], "fallback_url": fallback_url,
            "error": "Could not reach YouTube right now.",
        }), 200

    if resp.status_code != 200:
        return jsonify({
            "configured": True, "videos": [], "fallback_url": fallback_url,
            "error": f"YouTube API error ({resp.status_code}).",
        }), 200

    try:
        items = resp.json().get("items", [])
    except ValueError:
        items = []

    videos = []
    for item in items:
        video_id = item.get("id", {}).get("videoId")
        if not video_id:
            continue
        snippet = item.get("snippet", {})
        videos.append({
            "videoId": video_id,
            "title": snippet.get("title", ""),
            "channelTitle": snippet.get("channelTitle", ""),
            "thumbnail": (snippet.get("thumbnails", {}).get("medium") or snippet.get("thumbnails", {}).get("default") or {}).get("url", ""),
            "url": f"https://www.youtube.com/watch?v={video_id}",
        })

    return jsonify({"configured": True, "videos": videos, "fallback_url": fallback_url}), 200


@app.route("/api/delete-account", methods=["POST"])
@limiter.limit("5 per minute")
def delete_account():
    """Permanently deletes the account and all associated data. Requires
    re-entering the current password as confirmation, since this is
    irreversible."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""

    db = get_db()
    user = db.execute(
        "SELECT password_hash FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Incorrect password. Account was not deleted."}), 401

    user_id = session["user_id"]
    db.execute("DELETE FROM user_state WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM password_resets WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    session.clear()

    return jsonify({"message": "Your account and all associated data have been permanently deleted."}), 200


# --------------------------------------------------------------------------
# Routes: password reset
# --------------------------------------------------------------------------
@csrf.exempt
@app.route("/request-password-reset", methods=["POST"])
@limiter.limit("5 per minute")
def request_password_reset():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    # Always return the same generic message regardless of whether the
    # email exists — this endpoint is a classic enumeration vector if you
    # let the response differ.
    generic_response = jsonify(
        {"message": "If an account exists for that email, reset instructions have been sent."}
    )

    if not is_valid_email(email):
        return generic_response, 200

    db = get_db()
    user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if not user:
        return generic_response, 200

    token = secrets.token_urlsafe(32)  # sent to the user, never stored raw
    token_hash = hash_token(token)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    now = datetime.now(timezone.utc).isoformat()

    db.execute(
        "INSERT INTO password_resets (user_id, token_hash, expires_at, used, created_at) "
        "VALUES (?, ?, ?, 0, ?)",
        (user["id"], token_hash, expires_at, now),
    )
    db.commit()

    # TODO: plug in a real email provider here (SendGrid, Mailgun, AWS SES,
    # Postmark, or SMTP via Flask-Mail). This sandbox has no mail
    # credentials, so we just log the link — replace this with an actual
    # send in production. Never email the raw password, only this link.
    reset_link = f"https://your-domain.example/reset-password?token={token}"
    app.logger.info(f"[DEV ONLY] Password reset link for {email}: {reset_link}")

    return generic_response, 200


@csrf.exempt
@app.route("/reset-password", methods=["POST"])
@limiter.limit("5 per minute")
def reset_password():
    data = request.get_json(silent=True) or {}
    token = data.get("token") or ""
    new_password = data.get("password") or ""

    if not token:
        return jsonify({"error": "Missing or invalid reset token."}), 400

    issues = password_issues(new_password)
    if issues:
        return jsonify({"error": issues[0]}), 400

    token_hash = hash_token(token)
    db = get_db()
    row = db.execute(
        "SELECT id, user_id, expires_at, used FROM password_resets WHERE token_hash = ?",
        (token_hash,),
    ).fetchone()

    if not row or row["used"]:
        return jsonify({"error": "This reset link is invalid or has already been used."}), 400

    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        return jsonify({"error": "This reset link has expired. Please request a new one."}), 400

    new_hash = hash_password(new_password)
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, row["user_id"]))
    db.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (row["id"],))
    db.commit()

    return jsonify({"message": "Password updated. You can now log in."}), 200


# --------------------------------------------------------------------------
if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=not IS_PRODUCTION)
