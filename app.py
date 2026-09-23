import os
import base64
import io
import secrets
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, make_response
import bcrypt
import qrcode
from db import get_db, init_db, execute_query
from crypto_utils import (
    encrypt_secret, decrypt_secret, generate_secret,
    totp, verify_totp, generate_backup_codes, hash_backup_code
)

app = Flask(__name__)

# ============================================================
# CONFIG
# ============================================================
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
SESSION_HOURS = 24
SESSION_TIMEOUT_MINUTES = int(os.environ.get("SESSION_TIMEOUT_MINUTES", "30"))


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
    """Return session dict if valid and not timed out, else None."""
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

    # Absolute expiry
    if expires_at and now > expires_at:
        execute_query(c, "DELETE FROM sessions WHERE token = %s", (token,))
        conn.commit()
        conn.close()
        return None

    # Idle timeout
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
    """Decorator for HTML pages — redirects to / if not logged in."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        token = get_session_token()
        session = get_session(token)
        if not session:
            return redirect(url_for("index"))
        return view(session, *args, **kwargs)
    return wrapper


def login_required_api(view):
    """Decorator for JSON APIs — returns 401 if not logged in."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        token = get_session_token()
        session = get_session(token)
        if not session:
            return jsonify({"error": "Not authenticated", "code": "session_expired"}), 401
        return view(session, *args, **kwargs)
    return wrapper


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

    # backup codes remaining
    execute_query(c, "SELECT COUNT(*) AS n FROM backup_codes WHERE user_id = %s AND used = 0",
                  (session["user_id"],))
    remaining = c.fetchone()["n"]

    # active sessions
    execute_query(c, "SELECT COUNT(*) AS n FROM sessions WHERE user_id = %s AND expires_at > %s",
                  (session["user_id"], _iso()))
    sessions_count = c.fetchone()["n"]
    conn.close()

    # Safe date formatting
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
        token=session["token"],
    )


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

        # Backup code
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

    # No 2FA
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
# MAIN
# ============================================================
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)
else:
    init_db()
