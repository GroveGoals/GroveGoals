"""
GroveGoals backend — authentication, email, profile, security.
"""

import os
import re
import secrets
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

import bcrypt
import requests
import psycopg2
import psycopg2.errors
from psycopg2.extras import RealDictCursor
from flask import Flask, request, jsonify, session, g, redirect, send_from_directory
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# App configuration
# --------------------------------------------------------------------------
app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

IS_PRODUCTION = os.environ.get('FLASK_ENV', 'development') == 'production'

# Session security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    SESSION_COOKIE_SAMESITE='Lax',
)

# --------------------------------------------------------------------------
# Security headers middleware
# --------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    """Add security headers to every response."""
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self' https://api.github.com; "
        "frame-ancestors 'none'"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains' if IS_PRODUCTION else ''
    return response

# --------------------------------------------------------------------------
# HTTPS redirect
# --------------------------------------------------------------------------
@app.before_request
def enforce_https():
    if IS_PRODUCTION and not request.is_secure:
        return redirect(request.url.replace('http://', 'https://'), 301)

# --------------------------------------------------------------------------
# CSRF & Rate Limiting
# --------------------------------------------------------------------------
csrf = CSRFProtect(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)

# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------
DATABASE_URL = os.environ.get('DATABASE_URL')


def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None and exception is None:
        db.close()


def db_execute(db, query, params=None):
    cur = db.cursor()
    try:
        if params:
            cur.execute(query, params)
        else:
            cur.execute(query)
        return cur
    except Exception as e:
        db.rollback()
        logger.error(f"DB error: {e}")
        raise


# --------------------------------------------------------------------------
# Email configuration (SendGrid)
# --------------------------------------------------------------------------
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY', '')
FROM_EMAIL = os.environ.get('FROM_EMAIL', 'welcome@grovegoals.app')


def send_welcome_email(user_email: str, user_name: str) -> bool:
    """
    Sends a welcome email via SendGrid after successful signup.
    If the email fails, we log the error but DON'T block account creation.
    Returns True if sent successfully, False otherwise.
    """
    if not SENDGRID_API_KEY:
        logger.warning(f"No SENDGRID_API_KEY configured. Welcome email NOT sent to {user_email}.")
        logger.info(f"[DEV ONLY] Would send welcome email to {user_email} for {user_name}")
        return False

    try:
        resp = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            headers={
                "Authorization": f"Bearer {SENDGRID_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "personalizations": [{"to": [{"email": user_email}], "subject": "🎉 Welcome to GroveGoals!"}],
                "from": {"email": FROM_EMAIL, "name": "GroveGoals Team"},
                "content": [
                    {
                        "type": "text/html",
                        "value": f"""
                        <div style="font-family: 'Plus Jakarta Sans', sans-serif; max-width: 600px; margin: 0 auto; padding: 40px 20px; background: #F5F9F3; border-radius: 18px;">
                            <div style="text-align: center; font-size: 48px; margin-bottom: 20px;">🌳</div>
                            <h1 style="color: #0B3D2E; text-align: center; font-size: 28px; margin-bottom: 8px;">Welcome to GroveGoals, {user_name}!</h1>
                            <p style="color: #4A5D52; text-align: center; font-size: 16px; line-height: 1.6;">
                                Your journey starts today. Every goal you plant grows into something real.
                            </p>
                            <div style="background: white; border-radius: 16px; padding: 30px; margin: 30px 0;">
                                <p style="margin: 8px 0; font-size: 15px; color: #122018;">🌱 <strong>Create your first goal</strong> — the Goal Generator makes it easy</p>
                                <p style="margin: 8px 0; font-size: 15px; color: #122018;">📊 <strong>Track progress</strong> — XP, streaks, and achievements</p>
                                <p style="margin: 8px 0; font-size: 15px; color: #122018;">🤖 <strong>AI Coach</strong> — personalized guidance every step of the way</p>
                            </div>
                            <div style="text-align: center; margin-top: 30px;">
                                <a href="https://grovegoals.app" style="background: #1E5631; color: white; padding: 14px 40px; border-radius: 40px; text-decoration: none; font-weight: 600; display: inline-block;">Start Your Journey 🌱</a>
                            </div>
                            <p style="text-align: center; color: #8FA69A; font-size: 12px; margin-top: 40px;">
                                GroveGoals — Grow Your Goals Into Reality
                            </p>
                        </div>
                        """
                    }
                ],
            },
            timeout=15,
        )
        if resp.status_code in (200, 201, 202):
            logger.info(f"Welcome email sent to {user_email}")
            return True
        else:
            logger.error(f"SendGrid error ({resp.status_code}): {resp.text}")
            return False
    except Exception as e:
        logger.error(f"Failed to send welcome email to {user_email}: {e}")
        return False


# --------------------------------------------------------------------------
# Password utilities
# --------------------------------------------------------------------------
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8') if isinstance(hashed, str) else hashed)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def is_valid_email(email: str) -> bool:
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]{2,}$', email))


def password_issues(password: str) -> list:
    issues = []
    if len(password) < 8:
        issues.append("Password must be at least 8 characters.")
    if not re.search(r'[A-Z]', password):
        issues.append("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        issues.append("Password must contain at least one lowercase letter.")
    if not re.search(r'\d', password):
        issues.append("Password must contain at least one number.")
    return issues


# --------------------------------------------------------------------------
# Database initialization
# --------------------------------------------------------------------------
def init_db():
    db = psycopg2.connect(DATABASE_URL)
    cur = db.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            age INTEGER,
            country TEXT DEFAULT '',
            bio TEXT DEFAULT '',
            profile_pic TEXT DEFAULT '',
            online_status TEXT DEFAULT 'online',
            show_online_status BOOLEAN DEFAULT TRUE,
            account_public BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS user_state (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            xp INTEGER DEFAULT 0,
            streak INTEGER DEFAULT 0,
            last_log_date TEXT DEFAULT '',
            goals_data TEXT DEFAULT '[]',
            achievements TEXT DEFAULT '{}',
            preferences TEXT DEFAULT '{}',
            is_premium BOOLEAN DEFAULT FALSE
        );
        CREATE TABLE IF NOT EXISTS password_resets (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS communities (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            cover_photo TEXT DEFAULT '',
            is_public BOOLEAN DEFAULT TRUE,
            creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS community_members (
            id SERIAL PRIMARY KEY,
            community_id INTEGER REFERENCES communities(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            role TEXT DEFAULT 'member',
            joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            UNIQUE(community_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS community_messages (
            id SERIAL PRIMARY KEY,
            community_id INTEGER REFERENCES communities(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            message TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS friendships (
            id SERIAL PRIMARY KEY,
            requester_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            addressee_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            UNIQUE(requester_id, addressee_id)
        );
    """)
    db.commit()
    cur.close()
    db.close()


# --------------------------------------------------------------------------
# Routes: Auth
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory('.', 'grovegoals.html')


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory('.', path)


@app.route("/signup", methods=["POST"])
@limiter.limit("5 per minute")
def signup():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    # Validate
    if not name or not email or not password:
        return jsonify({"error": "Name, email, and password are required."}), 400

    if not is_valid_email(email):
        return jsonify({"error": "Please enter a valid email address."}), 400

    issues = password_issues(password)
    if issues:
        return jsonify({"error": issues[0]}), 400

    # Sanitize name (prevent XSS)
    name = re.sub(r'<[^>]*>', '', name)[:100]

    db = get_db()

    # Check existing user
    existing = db_execute(db, "SELECT id FROM users WHERE email = %s", (email,)).fetchone()
    if existing:
        return jsonify({"error": "An account with this email already exists."}), 409

    try:
        # Create user
        password_hash = hash_password(password)
        cur = db_execute(
            db,
            "INSERT INTO users (name, email, password_hash) VALUES (%s, %s, %s) RETURNING id, created_at",
            (name, email, password_hash),
        )
        user = cur.fetchone()
        user_id = user["id"]
        created_at = user["created_at"]

        # Create user state
        db_execute(
            db,
            "INSERT INTO user_state (user_id) VALUES (%s)",
            (user_id,),
        )
        db.commit()

        # Log the user in immediately
        session["user_id"] = user_id
        session["user_name"] = name
        session["user_email"] = email
        session.permanent = True

        # --- SEND WELCOME EMAIL (non-blocking) ---
        # If it fails, account is still created — we just log the error
        logger.info(f"New user created: {email} (ID: {user_id})")
        try:
            email_sent = send_welcome_email(email, name)
            if email_sent:
                logger.info(f"Welcome email sent to {email}")
            else:
                logger.warning(f"Welcome email failed to send to {email} — account still created")
        except Exception as e:
            logger.error(f"Welcome email error for {email}: {e}")

        return jsonify({
            "message": "Account created! Welcome to GroveGoals 🌱",
            "user": {
                "id": user_id,
                "name": name,
                "email": email,
                "created_at": created_at.isoformat() if hasattr(created_at, 'isoformat') else str(created_at),
                "xp": 0,
                "streak": 0,
                "level": "Seed",
                "bio": "",
                "profile_pic": "",
            }
        }), 201

    except Exception as e:
        db.rollback()
        logger.error(f"Signup error: {e}")
        return jsonify({"error": "Something went wrong. Please try again."}), 500


@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    db = get_db()
    user = db_execute(
        db,
        "SELECT u.*, s.xp, s.streak, s.last_log_date, s.goals_data, s.achievements, s.is_premium "
        "FROM users u LEFT JOIN user_state s ON u.id = s.user_id WHERE u.email = %s",
        (email,),
    ).fetchone()

    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid email or password."}), 401

    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session["user_email"] = user["email"]
    session.permanent = True

    return jsonify({
        "message": "Welcome back!",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "age": user.get("age"),
            "country": user.get("country", ""),
            "bio": user.get("bio", ""),
            "profile_pic": user.get("profile_pic", ""),
            "online_status": user.get("online_status", "online"),
            "show_online_status": user.get("show_online_status", True),
            "account_public": user.get("account_public", True),
            "created_at": user.get("created_at").isoformat() if hasattr(user.get("created_at"), 'isoformat') else str(user.get("created_at", "")),
            "xp": user.get("xp", 0),
            "streak": user.get("streak", 0),
            "is_premium": user.get("is_premium", False),
            "goals": json.loads(user.get("goals_data", "[]")),
            "achievements": json.loads(user.get("achievements", "{}")),
        }
    }), 200


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out."}), 200


@app.route("/api/profile", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def profile():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    db = get_db()

    if request.method == "GET":
        user = db_execute(
            db,
            "SELECT u.*, s.xp, s.streak, s.last_log_date, s.goals_data, s.achievements, s.is_premium "
            "FROM users u LEFT JOIN user_state s ON u.id = s.user_id WHERE u.id = %s",
            (session["user_id"],),
        ).fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404

        return jsonify({
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "age": user.get("age"),
                "country": user.get("country", ""),
                "bio": user.get("bio", ""),
                "profile_pic": user.get("profile_pic", ""),
                "online_status": user.get("online_status", "online"),
                "show_online_status": user.get("show_online_status", True),
                "account_public": user.get("account_public", True),
                "created_at": user.get("created_at").isoformat() if hasattr(user.get("created_at"), 'isoformat') else str(user.get("created_at", "")),
                "xp": user.get("xp", 0),
                "streak": user.get("streak", 0),
                "is_premium": user.get("is_premium", False),
                "goals": json.loads(user.get("goals_data", "[]")),
                "achievements": json.loads(user.get("achievements", "{}")),
            }
        }), 200

    # POST = update profile
    data = request.get_json(silent=True) or {}

    allowed_fields = ["name", "age", "country", "bio", "online_status", "show_online_status", "account_public"]
    updates = []
    params = []

    for field in allowed_fields:
        if field in data:
            value = data[field]
            if field == "name":
                value = re.sub(r'<[^>]*>', '', str(value))[:100]
            elif field == "bio":
                value = re.sub(r'<[^>]*>', '', str(value))[:500]
            elif field == "age":
                try:
                    value = int(value)
                    if value < 1 or value > 150:
                        continue
                except (ValueError, TypeError):
                    continue
            updates.append(f"{field} = %s")
            params.append(value)

    if updates:
        params.append(session["user_id"])
        db_execute(db, f"UPDATE users SET {', '.join(updates)} WHERE id = %s", params)
        db.commit()
        return jsonify({"message": "Profile updated."}), 200

    return jsonify({"message": "Nothing to update."}), 200


# --------------------------------------------------------------------------
# Routes: Profile picture upload
# --------------------------------------------------------------------------
import base64
import uuid

ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.webp'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB


@app.route("/api/upload-profile-pic", methods=["POST"])
@limiter.limit("10 per minute")
def upload_profile_pic():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    image_data = data.get("image", "")

    if not image_data:
        return jsonify({"error": "No image data provided."}), 400

    # Validate base64 image
    try:
        if "," in image_data:
            header, encoded = image_data.split(",", 1)
            ext = ".png"
            if "jpeg" in header or "jpg" in header:
                ext = ".jpg"
            elif "webp" in header:
                ext = ".webp"
            elif "png" in header:
                ext = ".png"
            else:
                return jsonify({"error": "Unsupported image format. Use JPEG, PNG, or WebP."}), 400
        else:
            return jsonify({"error": "Invalid image data."}), 400

        decoded = base64.b64decode(encoded)

        if len(decoded) > MAX_FILE_SIZE:
            return jsonify({"error": "Image too large. Max 5MB."}), 400

        # Save to local uploads directory (or cloud storage)
        filename = f"profile_{session['user_id']}_{uuid.uuid4().hex}{ext}"
        upload_dir = "uploads"
        os.makedirs(upload_dir, exist_ok=True)
        filepath = os.path.join(upload_dir, filename)

        with open(filepath, "wb") as f:
            f.write(decoded)

        db = get_db()
        db_execute(db, "UPDATE users SET profile_pic = %s WHERE id = %s", (f"/{filepath}", session["user_id"]))
        db.commit()

        return jsonify({"message": "Profile picture updated.", "profile_pic": f"/{filepath}"}), 200

    except Exception as e:
        logger.error(f"Profile pic upload error: {e}")
        return jsonify({"error": "Failed to upload image."}), 500


@app.route("/api/remove-profile-pic", methods=["POST"])
def remove_profile_pic():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    db = get_db()
    db_execute(db, "UPDATE users SET profile_pic = '' WHERE id = %s", (session["user_id"],))
    db.commit()
    return jsonify({"message": "Profile picture removed."}), 200


# --------------------------------------------------------------------------
# Routes: State save/load
# --------------------------------------------------------------------------
@app.route("/api/save-state", methods=["POST"])
@limiter.limit("30 per minute")
def save_state():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    db = get_db()

    allowed = ["xp", "streak", "last_log_date", "goals_data", "achievements", "preferences"]
    updates = []
    params = []

    for field in allowed:
        if field in data:
            value = data[field]
            if field in ("goals_data", "achievements", "preferences"):
                value = json.dumps(value)
            updates.append(f"{field} = %s")
            params.append(value)

    if updates:
        params.append(session["user_id"])
        db_execute(db, f"UPDATE user_state SET {', '.join(updates)} WHERE user_id = %s", params)
        db.commit()
        return jsonify({"message": "Saved."}), 200

    return jsonify({"message": "Nothing to save."}), 200


# --------------------------------------------------------------------------
# Routes: Password reset & delete account (from your original)
# --------------------------------------------------------------------------
# ... (keep your existing password reset routes as-is) ...

# --------------------------------------------------------------------------
# Routes: Communities API
# --------------------------------------------------------------------------
@app.route("/api/communities", methods=["GET"])
def list_communities():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    db = get_db()
    communities = db_execute(
        db,
        "SELECT c.*, u.name as creator_name, "
        "(SELECT COUNT(*) FROM community_members cm WHERE cm.community_id = c.id) as member_count "
        "FROM communities c JOIN users u ON c.creator_id = u.id "
        "WHERE c.is_public = TRUE OR c.creator_id = %s "
        "ORDER BY c.created_at DESC",
        (session["user_id"],),
    ).fetchall()
    return jsonify({"communities": [dict(c) for c in communities]}), 200


@app.route("/api/communities", methods=["POST"])
def create_community():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()[:100]
    description = (data.get("description") or "").strip()[:500]
    is_public = data.get("is_public", True)

    if not name:
        return jsonify({"error": "Community name is required."}), 400

    name = re.sub(r'<[^>]*>', '', name)
    description = re.sub(r'<[^>]*>', '', description)

    db = get_db()
    cur = db_execute(
        db,
        "INSERT INTO communities (name, description, is_public, creator_id) VALUES (%s, %s, %s, %s) RETURNING id",
        (name, description, is_public, session["user_id"]),
    )
    community_id = cur.fetchone()["id"]
    db_execute(
        db,
        "INSERT INTO community_members (community_id, user_id, role) VALUES (%s, %s, %s)",
        (community_id, session["user_id"], "creator"),
    )
    db.commit()
    return jsonify({"message": "Community created!", "community_id": community_id}), 201


@app.route("/api/communities/<int:community_id>/join", methods=["POST"])
def join_community(community_id):
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    db = get_db()
    try:
        db_execute(
            db,
            "INSERT INTO community_members (community_id, user_id) VALUES (%s, %s)",
            (community_id, session["user_id"]),
        )
        db.commit()
        return jsonify({"message": "Joined community!"}), 200
    except psycopg2.errors.UniqueViolation:
        db.rollback()
        return jsonify({"error": "Already a member."}), 409


@app.route("/api/communities/<int:community_id>/messages", methods=["GET"])
def get_community_messages(community_id):
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    db = get_db()
    messages = db_execute(
        db,
        "SELECT cm.*, u.name as user_name, u.profile_pic "
        "FROM community_messages cm JOIN users u ON cm.user_id = u.id "
        "WHERE cm.community_id = %s ORDER BY cm.created_at ASC LIMIT 100",
        (community_id,),
    ).fetchall()
    return jsonify({"messages": [dict(m) for m in messages]}), 200


@app.route("/api/communities/<int:community_id>/messages", methods=["POST"])
def send_community_message(community_id):
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()[:1000]
    if not message:
        return jsonify({"error": "Message cannot be empty."}), 400
    message = re.sub(r'<[^>]*>', '', message)

    db = get_db()
    db_execute(
        db,
        "INSERT INTO community_messages (community_id, user_id, message) VALUES (%s, %s, %s)",
        (community_id, session["user_id"], message),
    )
    db.commit()
    return jsonify({"message": "Sent!"}), 201


# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=not IS_PRODUCTION)
