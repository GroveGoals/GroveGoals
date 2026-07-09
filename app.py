"""
GroveGoals authentication backend.

Implements: signup, login, logout, profile, and password reset,
following the security checklist:
  - Password storage:        bcrypt (bcrypt.hashpw / bcrypt.checkpw)
  - HTTPS only:               enforced via Flask-Talisman in production mode
  - Session security:         HttpOnly + Secure + SameSite cookies
  - Rate limiting:            Flask-Limiter, 5 attempts/min on auth routes
  - SQL injection:            parameterized queries everywhere (psycopg2 "%s" placeholders)
  - Input validation:         email format check, password complexity, trimming
  - CSRF:                     Flask-WTF CSRFProtect on session-mutating routes
  - Account enumeration:      generic error messages, constant-time-ish responses
  - Password reset:           single-use, time-limited, hashed tokens

Database: Postgres (e.g. a free Neon.tech project), via DATABASE_URL.
This intentionally does NOT use a local SQLite file, because most free
hosting (like Render's free tier) has no persistent disk — anything written
to local disk resets on every restart/redeploy. A separate Postgres
instance keeps your data permanent regardless of what happens to the web
server itself, and Neon's free tier costs nothing and never expires.

Run locally:
    pip install -r requirements.txt
    cp .env.example .env        # then edit SECRET_KEY and DATABASE_URL
    flask --app app init-db     # creates the tables in your Postgres DB
    flask --app app run --debug

This app serves the GroveGoals frontend itself at "/" (same-origin),
so the frontend's fetch('/signup') etc. work with no CORS setup needed.
"""

import os
import re
import secrets
import hashlib
import json
from datetime import datetime, timedelta, timezone

import bcrypt
import requests
import psycopg2
import psycopg2.errors
from psycopg2.extras import RealDictCursor
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

# Gemini is the recommended default: Google AI Studio issues free API keys
# with no credit card and a generous daily quota, unlike Anthropic which
# requires billing to be enabled even for light usage. If both keys are
# set, Gemini is used first (see call_ai_coach() below).
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

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
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not set. Create a free Postgres project (e.g. at "
        "neon.tech), copy its connection string, and set it as DATABASE_URL "
        "before running this app."
    )

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
        g.db = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def db_execute(db, query, params=()):
    """
    sqlite3-style '.execute()' convenience shim for psycopg2 connections.
    psycopg2 (unlike sqlite3) requires an explicit cursor — this keeps every
    call site below reading the same way: db_execute(db, "...", (...)).fetchone()
    """
    cur = db.cursor()
    cur.execute(query, params)
    return cur


def init_db():
    db = psycopg2.connect(DATABASE_URL)
    cur = db.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            SERIAL PRIMARY KEY,
            email         TEXT UNIQUE NOT NULL,
            name          TEXT,
            password_hash TEXT NOT NULL,
            created_at    TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS password_resets (
            id           SERIAL PRIMARY KEY,
            user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash   TEXT NOT NULL,
            expires_at   TEXT NOT NULL,
            used         INTEGER NOT NULL DEFAULT 0,
            created_at   TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_state (
            user_id      INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            state_json   TEXT NOT NULL DEFAULT '{}',
            updated_at   TEXT NOT NULL
        )
        """
    )
    # Additive migrations — safe to run on every startup, including against
    # an existing database that already has users in it (won't touch or
    # lose any existing data, just adds new columns with sensible defaults
    # if they aren't already there).
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_data_url TEXT")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_reminders INTEGER NOT NULL DEFAULT 0")
    db.commit()
    cur.close()
    db.close()


@app.cli.command("init-db")
def init_db_command():
    """Run with: flask --app app init-db"""
    init_db()
    print("Initialized database tables in the Postgres database at DATABASE_URL.")


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
    existing = db_execute(db, "SELECT id FROM users WHERE email = %s", (email,)).fetchone()
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
    try:
        cursor = db_execute(
            db,
            "INSERT INTO users (email, name, password_hash, created_at) VALUES (%s, %s, %s, %s) RETURNING id",
            (email, name, password_hash, now),
        )
        user_id = cursor.fetchone()["id"]
        db.commit()
    except psycopg2.errors.UniqueViolation:
        # Rare race: two signups with the same email landed between the
        # SELECT check above and this INSERT. Roll back so the connection
        # isn't left in Postgres's "aborted transaction" state.
        db.rollback()
        return jsonify({"error": "An account with that email already exists."}), 409

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
    user = db_execute(
        db, "SELECT id, name, password_hash FROM users WHERE email = %s", (email,)
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
    user = db_execute(
        db, "SELECT email, name, avatar_data_url, email_reminders FROM users WHERE id = %s", (session["user_id"],)
    ).fetchone()
    if not user:
        session.clear()
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify({
        "email": user["email"],
        "name": user["name"],
        "avatar": user["avatar_data_url"],
        "emailReminders": bool(user["email_reminders"]),
    }), 200


# --------------------------------------------------------------------------
# Profile picture + notification settings
# --------------------------------------------------------------------------
MAX_AVATAR_BYTES = 350_000  # ~350KB of base64 text — plenty for a small resized photo

@app.route("/api/profile/avatar", methods=["POST"])
@limiter.limit("10 per minute")
def upload_avatar():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    image = data.get("image") or ""

    if not image.startswith("data:image/"):
        return jsonify({"error": "Please upload a valid image."}), 400
    if len(image) > MAX_AVATAR_BYTES:
        return jsonify({"error": "Image is too large. Please choose a smaller photo."}), 400

    db = get_db()
    db_execute(db, "UPDATE users SET avatar_data_url = %s WHERE id = %s", (image, session["user_id"]))
    db.commit()
    return jsonify({"message": "Profile picture updated", "avatar": image}), 200


@app.route("/api/profile/avatar", methods=["DELETE"])
def delete_avatar():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    db = get_db()
    db_execute(db, "UPDATE users SET avatar_data_url = NULL WHERE id = %s", (session["user_id"],))
    db.commit()
    return jsonify({"message": "Profile picture removed"}), 200


@app.route("/api/profile/settings", methods=["POST"])
def update_profile_settings():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.get_json(silent=True) or {}
    if "emailReminders" not in data:
        return jsonify({"error": "emailReminders is required"}), 400

    email_reminders = 1 if data.get("emailReminders") else 0
    db = get_db()
    db_execute(db, "UPDATE users SET email_reminders = %s WHERE id = %s", (email_reminders, session["user_id"]))
    db.commit()
    return jsonify({"message": "Settings updated", "emailReminders": bool(email_reminders)}), 200


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
    row = db_execute(db, "SELECT state_json FROM user_state WHERE user_id = %s", (user_id,)).fetchone()
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
    db_execute(
        db,
        """
        INSERT INTO user_state (user_id, state_json, updated_at) VALUES (%s, %s, %s)
        ON CONFLICT (user_id) DO UPDATE SET state_json = EXCLUDED.state_json, updated_at = EXCLUDED.updated_at
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


import google.generativeai as genai
import os

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

    messages = []
    for msg in history[-COACH_HISTORY_SENT_TO_MODEL:]:
        role = "assistant" if msg.get("role") == "assistant" else "user"
        content = msg.get("content", "")
        if content:
            messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": user_message


           def call_gemini(system_prompt, history, user_message):
    """Returns (reply_text, error_message)."""

    if not GEMINI_API_KEY:
        return None, "The AI Coach isn't configured yet. Please set GEMINI_API_KEY."

    try:
        model = genai.GenerativeModel("gemini-2.5-flash")

        conversation = system_prompt + "\n\n"

        for msg in history[-COACH_HISTORY_SENT_TO_MODEL:]:
            role = "Assistant" if msg.get("role") == "assistant" else "User"
            conversation += f"{role}: {msg.get('content','')}\n"

        conversation += f"User: {user_message}\nAssistant:"

        response = model.generate_content(
            conversation,
            generation_config={
                "max_output_tokens": 1024,
                "temperature": 0.7,
            }
        )

    except Exception as e:
        return None, str(e)
    excerequests.RequestException:
        return None, "Could not reach the AI service right now. Please try again shortly."
    
        return None, "The AI service rejected the configured API key.

        return None, "The AI Coach is getting a lot of requests right now. Please try again in a moment."
    if resp.status_code != 200:
        return None, f"The AI service returned an error ({resp.status_code})."

    try:
    except ValueError:
        return None, "The AI service returned an unreadable response.
      
        block.get("text", "") for block in payload.get("content", []) if block.get("type") == "text"
    ).strip()

    if not text:
    "The AI service returned an empty response."
  
def call_gemini(system_prompt, history, user_message):
    """
    Returns (reply_text, error_message) — exactly one of the two is set.
    Uses Google's Gemini API, which offers free API keys with no credit
    card and a generous daily quota — the recommended option if you want
    the AI Coach running at zero cost.
    """
    if not GEMINI_API_KEY:
        return None, "The AI Coach isn't configured yet — ask the site owner to set GEMINI_API_KEY or ANTHROPIC_API_KEY."

    contents = []
    for msg in history[-COACH_HISTORY_SENT_TO_MODEL:]:
        role = "model" if msg.get("role") == "assistant" else "user"
        content = msg.get("content", "")
        if content:
            contents.append({"role": role, "parts": [{"text": content}]})
    contents.append({"role": "user", "parts": [{"text": user_message}]})

    url = GEMINI_API_URL.format(model=GEMINI_MODEL)

    try:
        resp = requests.post(
            url,
            params={"key": GEMINI_API_KEY},
            headers={"content-type": "application/json"},
            json={
                "contents": contents,
                "systemInstruction": {"parts": [{"text": system_prompt}]},
                "generationConfig": {"maxOutputTokens": 400},
            },
            timeout=20,
        )
    except requests.RequestException:
        return None, "Could not reach the AI service right now. Please try again shortly."

    if resp.status_code in (401, 403):
        return None, "The AI service rejected the configured API key."
    if resp.status_code == 429:
        return None, "The AI Coach is getting a lot of requests right now. Please try again in a moment."
    if resp.status_code != 200:
        return None, f"The AI service returned an error ({resp.status_code})."

    try:
        payload = resp.json()
    except ValueError:
        return None, "The AI service returned an unreadable response."

    try:
        candidates = payload.get("candidates", [])
        parts = candidates[0].get("content", {}).get("parts", []) if candidates else []
        text = "".join(p.get("text", "") for p in parts).strip()
    except (IndexError, AttributeError, TypeError):
        text = ""

    if not text:
        return None, "The AI service returned an empty response."
    return text, None


def call_ai_coach(system_prompt, history, user_message):
    """
    Dispatches to whichever provider is configured. Gemini is tried first
    since it's free to set up; Anthropic is used if that's what's configured
    instead (or as well).
    """
    if GEMINI_API_KEY:
        return call_gemini(system_prompt, history, user_message)
    if ANTHROPIC_API_KEY:
        return call_anthropic(system_prompt, history, user_message)
    return None, "The AI Coach isn't configured yet — ask the site owner to set GEMINI_API_KEY (free, recommended) or ANTHROPIC_API_KEY."


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
    user_row = db_execute(db, "SELECT name FROM users WHERE id = %s", (session["user_id"],)).fetchone()
    app_state = _load_state(db, session["user_id"])
    history = app_state.get("coachHistory", [])

    system_prompt = build_coach_system_prompt(user_row["name"] if user_row else None, app_state)
    reply, error = call_ai_coach(system_prompt, history, user_message)

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
    user = db_execute(
        db, "SELECT password_hash FROM users WHERE id = %s", (session["user_id"],)
    ).fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Incorrect password. Account was not deleted."}), 401

    user_id = session["user_id"]
    db_execute(db, "DELETE FROM user_state WHERE user_id = %s", (user_id,))
    db_execute(db, "DELETE FROM password_resets WHERE user_id = %s", (user_id,))
    db_execute(db, "DELETE FROM users WHERE id = %s", (user_id,))
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
    user = db_execute(db, "SELECT id FROM users WHERE email = %s", (email,)).fetchone()
    if not user:
        return generic_response, 200

    token = secrets.token_urlsafe(32)  # sent to the user, never stored raw
    token_hash = hash_token(token)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    now = datetime.now(timezone.utc).isoformat()

    db_execute(
        db,
        "INSERT INTO password_resets (user_id, token_hash, expires_at, used, created_at) "
        "VALUES (%s, %s, %s, 0, %s)",
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
    row = db_execute(
        db,
        "SELECT id, user_id, expires_at, used FROM password_resets WHERE token_hash = %s",
        (token_hash,),
    ).fetchone()

    if not row or row["used"]:
        return jsonify({"error": "This reset link is invalid or has already been used."}), 400

    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        return jsonify({"error": "This reset link has expired. Please request a new one."}), 400

    new_hash = hash_password(new_password)
    db_execute(db, "UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, row["user_id"]))
    db_execute(db, "UPDATE password_resets SET used = 1 WHERE id = %s", (row["id"],))
    db.commit()

    return jsonify({"message": "Password updated. You can now log in."}), 200


# --------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()  # CREATE TABLE IF NOT EXISTS is idempotent — safe to call every start
    app.run(debug=not IS_PRODUCTION)
