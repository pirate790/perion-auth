import os
import base64
import io
import string
import secrets
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, make_response, g
import bcrypt
import qrcode
import requests as http_requests
from db import get_db, init_db, execute_query
from crypto_utils import (
    encrypt_secret, decrypt_secret, generate_secret,
    totp, verify_totp, generate_backup_codes, hash_backup_code
)

app = Flask(__name__)

# ============================================================
# CORS — allows other apps to call the public API
# ============================================================
@app.after_request
def add_cors_headers(response):
    if request.path.startswith("/api/v1/"):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.route("/api/v1/<path:path>", methods=["OPTIONS"])
def cors_preflight(path):
    return ("", 204)


# ============================================================
# CONFIG
# ============================================================
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
SESSION_HOURS = 24
SESSION_TIMEOUT_MINUTES = int(os.environ.get("SESSION_TIMEOUT_MINUTES", "30"))
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").strip().lower()
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "https://www.perionauth.ryzedns.org")
RESET_TOKEN_HOURS = 1


# ============================================================
# HELPERS
# ============================================================
def _now():
    return datetime.now()


def _iso(dt=None):
    return (dt or _now()).isoformat()


def _parse(dt):
    if not dt:
        return None
    if isinstance(dt, datetime):
        return dt
    return datetime.fromisoformat(str(dt))


def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def get_device_label():
    ua = request.headers.get("User-Agent", "")
    if "Android" in ua:
        return "Android device"
    if "iPhone" in ua or "iPad" in ua:
        return "iOS device"
    if "Windows" in ua:
        return "Windows PC"
    if "Mac" in ua:
        return "Mac"
    if "Linux" in ua:
        return "Linux"
    return "Unknown device"


def log_login_event(user_id, event):
    try:
        conn = get_db()
        c = conn.cursor()
        execute_query(c,
            "INSERT INTO login_history (user_id, event, device, ip) VALUES (%s, %s, %s, %s)",
            (user_id, event, get_device_label(), get_client_ip()))
        conn.commit()
        conn.close()
    except Exception:
        pass


def send_reset_email(to_email, reset_token):
    """Send a password reset email via Resend API."""
    if not RESEND_API_KEY:
        print(f"[DEV] RESEND_API_KEY not set. Reset link: {APP_BASE_URL}/reset-password?token={reset_token}")
        return False

    reset_link = f"{APP_BASE_URL}/reset-password?token={reset_token}"
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:24px;background:#f9f9f9;border-radius:12px;">
      <h2 style="color:#101828;">Reset your Perion Auth password</h2>
      <p style="color:#344054;">Someone requested a password reset for your account.</p>
      <p style="color:#344054;">Click the button below to choose a new password. This link expires in <strong>{RESET_TOKEN_HOURS} hour(s)</strong>.</p>
      <p style="text-align:center;margin:28px 0;">
        <a href="{reset_link}" style="display:inline-block;background:#25D366;color:#0f0f0f;padding:14px 32px;border-radius:999px;text-decoration:none;font-weight:600;">Reset Password</a>
      </p>
      <p style="color:#667085;font-size:13px;">Or copy this link into your browser:<br>{reset_link}</p>
      <hr style="border:none;border-top:1px solid #e4e7ec;margin:24px 0;">
      <p style="color:#98a2b3;font-size:12px;">If you didn't request this, you can safely ignore this email.</p>
    </div>
    """

    try:
        r = http_requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "from": "Perion Auth <onboarding@resend.dev>",
                "to": to_email,
                "subject": "Reset your Perion Auth password",
                "html": html
            },
            timeout=15
        )
        if r.status_code >= 400:
            print(f"Resend error {r.status_code}: {r.text}")
            return False
        return True
    except Exception as e:
        print(f"Email send failed: {e}")
        return False


# ============================================================
# SESSION HELPERS
# ============================================================
def create_session(user_id):
    token = secrets.token_urlsafe(32)
    expires = (_now() + timedelta(hours=SESSION_HOURS)).isoformat()
    conn = get_db()
    c = conn.cursor()
    execute_query(c,
        "INSERT INTO sessions (token, user_id, expires_at, last_active, device) VALUES (%s, %s, %s, %s, %s)",
        (token, user_id, expires, _iso(), get_device_label()))
    conn.commit()
    conn.close()
    return token


def get_session(token, touch=True):
    if not token:
        return None

    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT * FROM sessions WHERE token = %s", (token,))
    row = c.fetchone()

    if not row:
        conn.close()
        return None

    now = _now()
    expires_at = _parse(row["expires_at"])
    last_active = _parse(row["last_active"]) if row.get("last_active") else expires_at

    if expires_at and now > expires_at:
        execute_query(c, "DELETE FROM sessions WHERE token = %s", (token,))
        conn.commit()
        conn.close()
        return None

    if last_active and (now - last_active).total_seconds() > SESSION_TIMEOUT_MINUTES * 60:
        execute_query(c, "DELETE FROM sessions WHERE token = %s", (token,))
        conn.commit()
        conn.close()
        return None

    if touch:
        execute_query(c, "UPDATE sessions SET last_active = %s WHERE token = %s", (_iso(), token))
        conn.commit()

    session = dict(row)
    conn.close()
    return session


def get_session_token():
    return request.cookies.get("perion_session") or request.args.get("token")


def login_required_html(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        token = get_session_token()
        session = get_session(token)
        if not session:
            return redirect(url_for("index"))
        return view(session, *args, **kwargs)
    return wrapper


def is_admin_user(user_id):
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT email, is_admin FROM users WHERE id = %s", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    email = (row["email"] or "").lower()
    if ADMIN_EMAIL and email == ADMIN_EMAIL:
        return True
    return bool(row.get("is_admin"))


def login_required_api(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        token = get_session_token()
        session = get_session(token)
        if not session:
            return jsonify({"error": "Not authenticated", "code": "session_expired"}), 401
        return view(session, *args, **kwargs)
    return wrapper


def admin_required_api(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        token = get_session_token()
        session = get_session(token)
        if not session:
            return jsonify({"error": "Not authenticated"}), 401
        if not is_admin_user(session["user_id"]):
            return jsonify({"error": "Admin access required"}), 403
        return view(session, *args, **kwargs)
    return wrapper


def _user_owns_key(user_id, key_id):
    if is_admin_user(user_id):
        return True
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT owner_user_id FROM api_keys WHERE id = %s", (key_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    return row["owner_user_id"] == user_id


# ============================================================
# RATE LIMIT / REPLAY
# ============================================================
def is_rate_limited(user_id):
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT attempts, last_attempt FROM rate_limits WHERE user_id = %s", (user_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return False

    attempts = row["attempts"]
    last_attempt = row["last_attempt"]

    if last_attempt:
        last = _parse(last_attempt)
        if _now() - last > timedelta(minutes=LOCKOUT_MINUTES):
            reset_rate_limit(user_id)
            return False

    return attempts >= MAX_ATTEMPTS


def increment_rate_limit(user_id):
    conn = get_db()
    c = conn.cursor()
    now = _iso()
    execute_query(c, """
        INSERT INTO rate_limits (user_id, attempts, last_attempt)
        VALUES (%s, 1, %s)
        ON CONFLICT(user_id) DO UPDATE SET
            attempts = rate_limits.attempts + 1,
            last_attempt = %s
    """, (user_id, now, now))
    conn.commit()
    conn.close()


def reset_rate_limit(user_id):
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "DELETE FROM rate_limits WHERE user_id = %s", (user_id,))
    conn.commit()
    conn.close()


def is_code_used(user_id, code):
    conn = get_db()
    c = conn.cursor()
    execute_query(c, """
        SELECT used_at FROM used_codes
        WHERE user_id = %s AND code = %s
        ORDER BY used_at DESC LIMIT 1
    """, (user_id, code))
    row = c.fetchone()
    conn.close()

    if not row:
        return False

    used_at = _parse(row["used_at"])
    return _now() - used_at < timedelta(seconds=30)


def mark_code_used(user_id, code):
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "INSERT INTO used_codes (user_id, code) VALUES (%s, %s)", (user_id, code))
    execute_query(c, "DELETE FROM used_codes WHERE used_at < %s",
                  ((_now() - timedelta(minutes=2)).isoformat(),))
    conn.commit()
    conn.close()


# ============================================================
# QR
# ============================================================
def generate_qr_data_uri(secret, email, issuer="Perion Auth"):
    uri = f"otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}"
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    data_uri = "data:image/png;base64," + base64.b64encode(buf.read()).decode()
    return data_uri, uri


# ============================================================
# PAGES
# ============================================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/sw.js")
def service_worker():
    return app.send_static_file("sw.js")


@app.route("/profile")
@login_required_html
def profile_page(session):
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT * FROM users WHERE id = %s", (session["user_id"],))
    user = dict(c.fetchone())

    execute_query(c, "SELECT COUNT(*) AS n FROM backup_codes WHERE user_id = %s AND used = 0",
                  (session["user_id"],))
    remaining = c.fetchone()["n"]

    execute_query(c, "SELECT COUNT(*) AS n FROM sessions WHERE user_id = %s AND expires_at > %s",
                  (session["user_id"], _iso()))
    sessions_count = c.fetchone()["n"]
    conn.close()

    created = user.get("created_at")
    last_login = user.get("last_login")

    return render_template(
        "profile.html",
        email=user["email"],
        display_name=user.get("display_name") or user["email"].split("@")[0],
        created_at=str(created)[:10] if created else "—",
        last_login=str(last_login)[:19] if last_login else "—",
        twofa=bool(user.get("totp_enabled")),
        backup_remaining=remaining,
        sessions_count=sessions_count,
        is_admin=is_admin_user(session["user_id"]),
        token=session["token"],
    )


@app.route("/settings")
@login_required_html
def settings_page(session):
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT * FROM users WHERE id = %s", (session["user_id"],))
    user = dict(c.fetchone())

    execute_query(c, "SELECT COUNT(*) AS n FROM backup_codes WHERE user_id = %s AND used = 0",
                  (session["user_id"],))
    remaining = c.fetchone()["n"]

    execute_query(c, "SELECT * FROM login_history WHERE user_id = %s ORDER BY created_at DESC LIMIT 10",
                  (session["user_id"],))
    history = []
    for r in c.fetchall():
        r = dict(r)
        created = r.get("created_at")
        r["created_at_str"] = str(created)[:16] if created else "—"
        history.append(r)

    execute_query(c, "SELECT device, created_at, last_active FROM sessions WHERE user_id = %s ORDER BY last_active DESC LIMIT 5",
                  (session["user_id"],))
    devices = []
    for r in c.fetchall():
        r = dict(r)
        la = r.get("last_active")
        r["last_active_str"] = str(la)[:16] if la else "—"
        devices.append(r)
    conn.close()

    return render_template(
        "settings.html",
        email=user["email"],
        display_name=user.get("display_name") or user["email"].split("@")[0],
        twofa=bool(user.get("totp_enabled")),
        backup_remaining=remaining,
        recovery_email=user.get("recovery_email") or "",
        recovery_phone=user.get("recovery_phone") or "",
        session_length=user.get("session_length") or 30,
        timeout_minutes=SESSION_TIMEOUT_MINUTES,
        history=history,
        devices=devices,
        is_admin=is_admin_user(session["user_id"]),
        token=session["token"],
    )


@app.route("/reset-password")
def reset_password_page():
    """Serve the single-page app; JS will read ?token= from the URL."""
    return render_template("index.html")


# ============================================================
# API — ENROLL / LOGIN
# ============================================================
@app.route("/enroll", methods=["GET", "POST"])
def enroll():
    if request.method == "GET":
        return redirect(url_for("index"))

    data = request.get_json() if request.is_json else request.form
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    display_name = (data.get("name") or "").strip() or None

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT id FROM users WHERE email = %s", (email,))
    if c.fetchone():
        conn.close()
        return jsonify({"error": "Email already registered"}), 400

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    secret = generate_secret()
    encrypted = encrypt_secret(secret)

    if os.environ.get("DATABASE_URL"):
        execute_query(c, """
            INSERT INTO users (email, password_hash, display_name, totp_secret_encrypted, totp_enabled)
            VALUES (%s, %s, %s, %s, 1) RETURNING id
        """, (email, password_hash, display_name, encrypted))
        user_id = c.fetchone()["id"]
    else:
        execute_query(c, """
            INSERT INTO users (email, password_hash, display_name, totp_secret_encrypted, totp_enabled)
            VALUES (%s, %s, %s, %s, 1)
        """, (email, password_hash, display_name, encrypted))
        user_id = c.lastrowid

    codes, hashes = generate_backup_codes()
    for h in hashes:
        execute_query(c, "INSERT INTO backup_codes (user_id, code_hash) VALUES (%s, %s)", (user_id, h))

    conn.commit()
    conn.close()

    qr_data_uri, uri = generate_qr_data_uri(secret, email)

    return jsonify({
        "success": True,
        "user_id": user_id,
        "qr_code": qr_data_uri,
        "secret": secret,
        "uri": uri,
        "backup_codes": codes
    })


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return redirect(url_for("index"))

    data = request.get_json() if request.is_json else request.form
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    code = data.get("code", "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT id, password_hash, totp_secret_encrypted, totp_enabled FROM users WHERE email = %s", (email,))
    user = c.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    user_id = user["id"]
    password_hash = user["password_hash"]
    encrypted_secret = user["totp_secret_encrypted"]
    totp_enabled = user["totp_enabled"]

    if not bcrypt.checkpw(password.encode(), password_hash.encode()):
        log_login_event(user_id, "Failed — wrong password")
        return jsonify({"error": "Invalid credentials"}), 401

    if totp_enabled:
        if not code:
            return jsonify({"error": "TOTP code required", "totp_required": True}), 401

        if is_rate_limited(user_id):
            return jsonify({"error": "Too many attempts. Try again in 15 minutes."}), 429

        secret = decrypt_secret(encrypted_secret)

        if is_code_used(user_id, code):
            return jsonify({"error": "Code already used. Wait for the next one."}), 401

        if verify_totp(secret, code):
            mark_code_used(user_id, code)
            reset_rate_limit(user_id)
            token = create_session(user_id)
            conn = get_db()
            c = conn.cursor()
            execute_query(c, "UPDATE users SET last_login = %s WHERE id = %s", (_iso(), user_id))
            conn.commit()
            conn.close()
            log_login_event(user_id, "Successful sign-in")
            return _login_response(token)

        conn = get_db()
        c = conn.cursor()
        execute_query(c, "SELECT id, code_hash FROM backup_codes WHERE user_id = %s AND used = 0", (user_id,))
        rows = c.fetchall()
        conn.close()

        code_hash = hash_backup_code(code)
        for row in rows:
            if row["code_hash"] == code_hash:
                conn = get_db()
                c = conn.cursor()
                execute_query(c, "UPDATE backup_codes SET used = 1, used_at = %s WHERE id = %s",
                              (_iso(), row["id"]))
                conn.commit()
                conn.close()
                reset_rate_limit(user_id)
                token = create_session(user_id)
                log_login_event(user_id, "Successful sign-in (backup code)")
                return _login_response(token, used_backup_code=True)

        increment_rate_limit(user_id)
        log_login_event(user_id, "Failed — wrong 2FA code")
        return jsonify({"error": "Invalid code"}), 401

    token = create_session(user_id)
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "UPDATE users SET last_login = %s WHERE id = %s", (_iso(), user_id))
    conn.commit()
    conn.close()
    log_login_event(user_id, "Successful sign-in")
    return _login_response(token)


def _login_response(token, used_backup_code=False):
    body = {"success": True, "session_token": token}
    if used_backup_code:
        body["used_backup_code"] = True
    resp = make_response(jsonify(body))
    resp.set_cookie("perion_session", token, httponly=True, samesite="Lax",
                    max_age=SESSION_HOURS * 3600)
    return resp


# ============================================================
# PASSWORD RESET
# ============================================================
@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "Email required"}), 400

    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT id FROM users WHERE email = %s", (email,))
    user = c.fetchone()

    if user:
        token = secrets.token_urlsafe(32)
        expiry = (_now() + timedelta(hours=RESET_TOKEN_HOURS)).isoformat()
        execute_query(c,
            "UPDATE users SET reset_token = %s, reset_token_expiry = %s WHERE id = %s",
            (token, expiry, user["id"]))
        conn.commit()
        conn.close()
        send_reset_email(email, token)
    else:
        conn.close()

    # Always return success to prevent email enumeration
    return jsonify({
        "success": True,
        "message": "If that email is registered, a reset link has been sent."
    })


@app.route("/api/reset-password", methods=["POST"])
def api_reset_password():
    data = request.get_json() or {}
    token = (data.get("token") or "").strip()
    new_password = data.get("password") or ""
    confirm = data.get("confirm") or ""

    if not token:
        return jsonify({"error": "Reset token missing"}), 400
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if new_password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400

    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT id, reset_token_expiry FROM users WHERE reset_token = %s", (token,))
    user = c.fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "Invalid or expired reset link"}), 400

    expiry = _parse(user["reset_token_expiry"])
    if not expiry or _now() > expiry:
        conn.close()
        return jsonify({"error": "Reset link has expired. Request a new one."}), 400

    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    execute_query(c,
        "UPDATE users SET password_hash = %s, reset_token = NULL, reset_token_expiry = NULL WHERE id = %s",
        (new_hash, user["id"]))
    # Invalidate all existing sessions for security
    execute_query(c, "DELETE FROM sessions WHERE user_id = %s", (user["id"],))
    conn.commit()
    conn.close()

    log_login_event(user["id"], "Password reset via email link")
    return jsonify({"success": True, "message": "Password updated. You can now sign in."})


# ============================================================
# API — LOGOUT
# ============================================================
@app.route("/api/logout", methods=["POST"])
@login_required_api
def api_logout(session):
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "DELETE FROM sessions WHERE token = %s", (session["token"],))
    conn.commit()
    conn.close()
    resp = make_response(jsonify({"success": True}))
    resp.delete_cookie("perion_session")
    return resp


@app.route("/api/logout-all", methods=["POST"])
@login_required_api
def api_logout_all(session):
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "DELETE FROM sessions WHERE user_id = %s AND token != %s",
                  (session["user_id"], session["token"]))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ============================================================
# API — PROFILE / SETTINGS
# ============================================================
@app.route("/api/profile-data", methods=["GET"])
@login_required_api
def api_profile_data(session):
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT email, display_name, totp_enabled, created_at, last_login FROM users WHERE id = %s",
                  (session["user_id"],))
    user = dict(c.fetchone())
    execute_query(c, "SELECT COUNT(*) AS n FROM backup_codes WHERE user_id = %s AND used = 0",
                  (session["user_id"],))
    user["backup_remaining"] = c.fetchone()["n"]
    conn.close()
    user["created_at"] = str(user.get("created_at") or "")[:19]
    user["last_login"] = str(user.get("last_login") or "—")[:19]
    return jsonify(user)


@app.route("/api/update-profile", methods=["POST"])
@login_required_api
def api_update_profile(session):
    data = request.get_json() or {}
    display_name = (data.get("display_name") or "").strip()
    if len(display_name) > 60:
        return jsonify({"error": "Name too long"}), 400
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "UPDATE users SET display_name = %s WHERE id = %s",
                  (display_name or None, session["user_id"]))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/change-password", methods=["POST"])
@login_required_api
def api_change_password(session):
    data = request.get_json() or {}
    current = data.get("current", "")
    new = data.get("new", "")
    confirm = data.get("confirm", "")

    if not current or not new:
        return jsonify({"error": "All fields required"}), 400
    if len(new) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400
    if new != confirm:
        return jsonify({"error": "New passwords do not match"}), 400

    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT password_hash FROM users WHERE id = %s", (session["user_id"],))
    row = c.fetchone()
    if not bcrypt.checkpw(current.encode(), row["password_hash"].encode()):
        conn.close()
        return jsonify({"error": "Current password is incorrect"}), 401

    new_hash = bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode()
    execute_query(c, "UPDATE users SET password_hash = %s WHERE id = %s",
                  (new_hash, session["user_id"]))
    execute_query(c, "DELETE FROM sessions WHERE user_id = %s AND token != %s",
                  (session["user_id"], session["token"]))
    conn.commit()
    conn.close()
    log_login_event(session["user_id"], "Password changed")
    return jsonify({"success": True})


@app.route("/api/toggle-2fa", methods=["POST"])
@login_required_api
def api_toggle_2fa(session):
    data = request.get_json() or {}
    enable = bool(data.get("enable"))

    conn = get_db()
    c = conn.cursor()
    if enable:
        secret = generate_secret()
        encrypted = encrypt_secret(secret)
        execute_query(c, "UPDATE users SET totp_secret_encrypted = %s, totp_enabled = 1 WHERE id = %s",
                      (encrypted, session["user_id"]))
        conn.commit()
        execute_query(c, "SELECT email FROM users WHERE id = %s", (session["user_id"],))
        email = c.fetchone()["email"]
        conn.close()
        qr_data_uri, uri = generate_qr_data_uri(secret, email)
        return jsonify({"success": True, "qr_code": qr_data_uri, "secret": secret, "uri": uri})

    execute_query(c, "UPDATE users SET totp_enabled = 0 WHERE id = %s", (session["user_id"],))
    conn.commit()
    conn.close()
    log_login_event(session["user_id"], "2FA disabled")
    return jsonify({"success": True})


@app.route("/api/regenerate-backup-codes", methods=["POST"])
@login_required_api
def api_regenerate_backup_codes(session):
    codes, hashes = generate_backup_codes()
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "DELETE FROM backup_codes WHERE user_id = %s", (session["user_id"],))
    for h in hashes:
        execute_query(c, "INSERT INTO backup_codes (user_id, code_hash) VALUES (%s, %s)",
                      (session["user_id"], h))
    conn.commit()
    conn.close()
    log_login_event(session["user_id"], "Backup codes regenerated")
    return jsonify({"success": True, "backup_codes": codes})


@app.route("/api/update-recovery", methods=["POST"])
@login_required_api
def api_update_recovery(session):
    data = request.get_json() or {}
    conn = get_db()
    c = conn.cursor()
    if "recovery_email" in data:
        execute_query(c, "UPDATE users SET recovery_email = %s WHERE id = %s",
                      ((data["recovery_email"] or "").strip() or None, session["user_id"]))
    if "recovery_phone" in data:
        execute_query(c, "UPDATE users SET recovery_phone = %s WHERE id = %s",
                      ((data["recovery_phone"] or "").strip() or None, session["user_id"]))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/update-session-length", methods=["POST"])
@login_required_api
def api_update_session_length(session):
    data = request.get_json() or {}
    days = int(data.get("days") or 30)
    if days not in (1, 7, 30, 90):
        return jsonify({"error": "Invalid choice"}), 400
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "UPDATE users SET session_length = %s WHERE id = %s", (days, session["user_id"]))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/login-history", methods=["GET"])
@login_required_api
def api_login_history(session):
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT event, device, ip, created_at FROM login_history WHERE user_id = %s ORDER BY created_at DESC LIMIT 20",
                  (session["user_id"],))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for r in rows:
        r["created_at"] = str(r.get("created_at"))[:19]
    return jsonify({"history": rows})


@app.route("/api/heartbeat", methods=["POST"])
@login_required_api
def api_heartbeat(session):
    return jsonify({"success": True, "timeout_minutes": SESSION_TIMEOUT_MINUTES})


# ============================================================
# API KEY MANAGEMENT (self-serve)
# ============================================================
def generate_api_key():
    prefix = "per_live_"
    body = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(32))
    return prefix + body


@app.route("/developers")
@login_required_html
def developers_page(session):
    admin = is_admin_user(session["user_id"])
    conn = get_db()
    c = conn.cursor()
    if admin:
        execute_query(c, """
            SELECT k.id, k.key, k.name, k.owner_email, k.created_at, k.is_active,
                   k.last_used, k.request_count, k.owner_user_id, u.email AS owner_user_email
            FROM api_keys k
            LEFT JOIN users u ON u.id = k.owner_user_id
            ORDER BY k.created_at DESC
        """)
    else:
        execute_query(c, """
            SELECT id, key, name, owner_email, created_at, is_active,
                   last_used, request_count, owner_user_id, NULL AS owner_user_email
            FROM api_keys
            WHERE owner_user_id = %s
            ORDER BY created_at DESC
        """, (session["user_id"],))
    keys = [dict(r) for r in c.fetchall()]
    conn.close()
    for k in keys:
        k["created_str"] = str(k.get("created_at") or "")[:16]
        k["last_used_str"] = str(k.get("last_used") or "Never")[:16]
    return render_template("developers.html", keys=keys, is_admin=admin, token=session["token"])


@app.route("/api/admin/keys", methods=["POST"])
@login_required_api
def api_admin_create_key(session):
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Name is required"}), 400

    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT email FROM users WHERE id = %s", (session["user_id"],))
    row = c.fetchone()
    owner_email = row["email"] if row else None

    new_key = generate_api_key()
    execute_query(c, """
        INSERT INTO api_keys (key, name, owner_email, owner_user_id)
        VALUES (%s, %s, %s, %s)
    """, (new_key, name, owner_email, session["user_id"]))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "key": new_key, "name": name})


@app.route("/api/admin/keys/<int:key_id>/revoke", methods=["POST"])
@login_required_api
def api_admin_revoke_key(session, key_id):
    if not _user_owns_key(session["user_id"], key_id):
        return jsonify({"error": "Not your key"}), 403
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "UPDATE api_keys SET is_active = 0 WHERE id = %s", (key_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/admin/keys/<int:key_id>/activate", methods=["POST"])
@login_required_api
def api_admin_activate_key(session, key_id):
    if not _user_owns_key(session["user_id"], key_id):
        return jsonify({"error": "Not your key"}), 403
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "UPDATE api_keys SET is_active = 1 WHERE id = %s", (key_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/admin/keys/<int:key_id>", methods=["DELETE"])
@login_required_api
def api_admin_delete_key(session, key_id):
    if not _user_owns_key(session["user_id"], key_id):
        return jsonify({"error": "Not your key"}), 403
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "DELETE FROM api_keys WHERE id = %s", (key_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ============================================================
# PUBLIC API v1
# ============================================================
def require_api_key(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        key = request.headers.get("X-API-Key", "").strip()
        if not key:
            return jsonify({"error": "Missing X-API-Key header"}), 401
        conn = get_db()
        c = conn.cursor()
        execute_query(c, "SELECT id, is_active FROM api_keys WHERE key = %s", (key,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Invalid API key"}), 401
        if not row["is_active"]:
            conn.close()
            return jsonify({"error": "API key revoked"}), 403
        execute_query(c, "UPDATE api_keys SET last_used = %s, request_count = request_count + 1 WHERE id = %s",
                      (_iso(), row["id"]))
        conn.commit()
        conn.close()
        g.api_key_id = row["id"]
        return view(*args, **kwargs)
    return wrapper


@app.route("/api/v1/health", methods=["GET"])
def api_v1_health():
    return jsonify({"status": "ok", "service": "Perion Auth", "version": "1.0"})


@app.route("/api/v1/signup", methods=["POST"])
@require_api_key
def api_v1_signup():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    name = (data.get("name") or "").strip() or None

    if not email or not password:
        return jsonify({"error": "email and password required"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT id FROM users WHERE email = %s", (email,))
    if c.fetchone():
        conn.close()
        return jsonify({"error": "Email already registered"}), 409

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    secret = generate_secret()
    encrypted = encrypt_secret(secret)

    if os.environ.get("DATABASE_URL"):
        execute_query(c, """
            INSERT INTO users (email, password_hash, display_name, totp_secret_encrypted, totp_enabled)
            VALUES (%s, %s, %s, %s, 1) RETURNING id
        """, (email, password_hash, name, encrypted))
        user_id = c.fetchone()["id"]
    else:
        execute_query(c, """
            INSERT INTO users (email, password_hash, display_name, totp_secret_encrypted, totp_enabled)
            VALUES (%s, %s, %s, %s, 1)
        """, (email, password_hash, name, encrypted))
        user_id = c.lastrowid

    codes, hashes = generate_backup_codes()
    for h in hashes:
        execute_query(c, "INSERT INTO backup_codes (user_id, code_hash) VALUES (%s, %s)", (user_id, h))
    conn.commit()
    conn.close()

    qr_data_uri, uri = generate_qr_data_uri(secret, email)
    return jsonify({
        "success": True,
        "user_id": user_id,
        "email": email,
        "qr_code": qr_data_uri,
        "uri": uri,
        "secret": secret,
        "backup_codes": codes
    }), 201


@app.route("/api/v1/login", methods=["POST"])
@require_api_key
def api_v1_login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "email and password required"}), 400

    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT id, password_hash, totp_enabled FROM users WHERE email = %s", (email,))
    user = c.fetchone()
    conn.close()
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        log_login_event(user["id"], "Failed — wrong password (API)")
        return jsonify({"error": "Invalid credentials"}), 401

    if user["totp_enabled"]:
        return jsonify({
            "success": True,
            "totp_required": True,
            "user_id": user["id"],
            "message": "Call /api/v1/verify with the 6-digit code"
        })

    token = create_session(user["id"])
    log_login_event(user["id"], "Successful sign-in (API)")
    return jsonify({"success": True, "session_token": token, "user_id": user["id"]})


@app.route("/api/v1/verify", methods=["POST"])
@require_api_key
def api_v1_verify():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    code = (data.get("code") or "").strip()

    if not email or not code:
        return jsonify({"error": "email and code required"}), 400

    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT id, totp_secret_encrypted FROM users WHERE email = %s", (email,))
    user = c.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    if is_rate_limited(user["id"]):
        conn.close()
        return jsonify({"error": "Too many attempts. Try again later."}), 429

    secret = decrypt_secret(user["totp_secret_encrypted"])
    if is_code_used(user["id"], code):
        conn.close()
        return jsonify({"error": "Code already used"}), 401

    if verify_totp(secret, code):
        mark_code_used(user["id"], code)
        reset_rate_limit(user["id"])
        execute_query(c, "UPDATE users SET last_login = %s WHERE id = %s", (_iso(), user["id"]))
        conn.commit()
        conn.close()
        token = create_session(user["id"])
        log_login_event(user["id"], "Successful sign-in (API 2FA)")
        return jsonify({"success": True, "session_token": token, "user_id": user["id"]})

    execute_query(c, "SELECT id, code_hash FROM backup_codes WHERE user_id = %s AND used = 0", (user["id"],))
    rows = c.fetchall()
    code_hash = hash_backup_code(code)
    for row in rows:
        if row["code_hash"] == code_hash:
            execute_query(c, "UPDATE backup_codes SET used = 1, used_at = %s WHERE id = %s",
                          (_iso(), row["id"]))
            conn.commit()
            conn.close()
            reset_rate_limit(user["id"])
            token = create_session(user["id"])
            return jsonify({"success": True, "session_token": token, "user_id": user["id"], "used_backup_code": True})

    increment_rate_limit(user["id"])
    conn.commit()
    conn.close()
    log_login_event(user["id"], "Failed — wrong 2FA code (API)")
    return jsonify({"error": "Invalid code"}), 401


@app.route("/api/v1/me", methods=["GET"])
@require_api_key
def api_v1_me():
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if not token:
        return jsonify({"error": "Missing Authorization: Bearer <token>"}), 401
    session = get_session(token)
    if not session:
        return jsonify({"error": "Invalid or expired session"}), 401
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT id, email, display_name, totp_enabled, created_at, last_login FROM users WHERE id = %s",
                  (session["user_id"],))
    user = dict(c.fetchone())
    conn.close()
    user["created_at"] = str(user.get("created_at") or "")
    user["last_login"] = str(user.get("last_login") or "")
    return jsonify({"success": True, "user": user})


@app.route("/api/v1/logout", methods=["POST"])
@require_api_key
def api_v1_logout():
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if not token:
        return jsonify({"error": "Missing token"}), 401
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "DELETE FROM sessions WHERE token = %s", (token,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ============================================================
# PUBLIC DOCS PAGE
# ============================================================
@app.route("/docs")
def docs_page():
    return render_template("docs.html")


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)
else:
    init_db()
