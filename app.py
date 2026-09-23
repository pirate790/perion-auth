import os
import base64
import io
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for
import bcrypt
import qrcode
from db import get_db, init_db, execute_query
from crypto_utils import (
    encrypt_secret, decrypt_secret, generate_secret,
    totp, verify_totp, generate_backup_codes, hash_backup_code
)

app = Flask(__name__)

# ============================================================
# SERVICE WORKER ROUTE (PWA)
# ============================================================
@app.route("/sw.js")
def service_worker():
    return app.send_static_file("sw.js")

# ============================================================
# HELPERS
# ============================================================
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
SESSION_HOURS = 24

def is_rate_limited(user_id):
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT attempts, last_attempt FROM rate_limits WHERE user_id = %s", (user_id,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return False
    
    attempts = row['attempts']
    last_attempt = row['last_attempt']
    
    if last_attempt:
        last = datetime.fromisoformat(str(last_attempt))
        if datetime.now() - last > timedelta(minutes=LOCKOUT_MINUTES):
            reset_rate_limit(user_id)
            return False
    
    return attempts >= MAX_ATTEMPTS

def increment_rate_limit(user_id):
    conn = get_db()
    c = conn.cursor()
    now = datetime.now().isoformat()
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
    
    used_at = datetime.fromisoformat(str(row['used_at']))
    return datetime.now() - used_at < timedelta(seconds=30)

def mark_code_used(user_id, code):
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "INSERT INTO used_codes (user_id, code) VALUES (%s, %s)", (user_id, code))
    execute_query(c, "DELETE FROM used_codes WHERE used_at < %s", 
              ((datetime.now() - timedelta(minutes=2)).isoformat(),))
    conn.commit()
    conn.close()

def create_session(user_id):
    token = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(hours=SESSION_HOURS)).isoformat()
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "INSERT INTO sessions (token, user_id, expires_at) VALUES (%s, %s, %s)",
              (token, user_id, expires))
    conn.commit()
    conn.close()
    return token

def get_session_user(token):
    conn = get_db()
    c = conn.cursor()
    execute_query(c, """
        SELECT user_id FROM sessions 
        WHERE token = %s AND expires_at > %s
    """, (token, datetime.now().isoformat()))
    row = c.fetchone()
    conn.close()
    return row['user_id'] if row else None

def generate_qr_data_uri(secret, email, issuer="Perion Auth"):
    uri = f"otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}"
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    data_uri = "data:image/png;base64," + base64.b64encode(buf.read()).decode()
    return data_uri, uri

# ============================================================
# ROUTES — PAGES
# ============================================================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/enroll", methods=["GET", "POST"])
def enroll():
    if request.method == "GET":
        return render_template("enroll.html")
    
    data = request.get_json() if request.is_json else request.form
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    
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
            INSERT INTO users (email, password_hash, totp_secret_encrypted, totp_enabled)
            VALUES (%s, %s, %s, 1) RETURNING id
        """, (email, password_hash, encrypted))
        user_id = c.fetchone()['id']
    else:
        execute_query(c, """
            INSERT INTO users (email, password_hash, totp_secret_encrypted, totp_enabled)
            VALUES (%s, %s, %s, 1)
        """, (email, password_hash, encrypted))
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
        return render_template("login.html")
    
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
    
    user_id = user['id']
    password_hash = user['password_hash']
    encrypted_secret = user['totp_secret_encrypted']
    totp_enabled = user['totp_enabled']
    
    if not bcrypt.checkpw(password.encode(), password_hash.encode()):
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
            return jsonify({"success": True, "session_token": token})
        
        conn = get_db()
        c = conn.cursor()
        execute_query(c, "SELECT id, code_hash FROM backup_codes WHERE user_id = %s AND used = 0", (user_id,))
        rows = c.fetchall()
        conn.close()
        
        code_hash = hash_backup_code(code)
        for row in rows:
            if row['code_hash'] == code_hash:
                conn = get_db()
                c = conn.cursor()
                execute_query(c, "UPDATE backup_codes SET used = 1, used_at = %s WHERE id = %s",
                          (datetime.now().isoformat(), row['id']))
                conn.commit()
                conn.close()
                reset_rate_limit(user_id)
                token = create_session(user_id)
                return jsonify({"success": True, "session_token": token, "used_backup_code": True})
        
        increment_rate_limit(user_id)
        return jsonify({"error": "Invalid code"}), 401
    
    token = create_session(user_id)
    return jsonify({"success": True, "session_token": token})

@app.route("/dashboard")
def dashboard():
    token = request.args.get("token") or request.cookies.get("session_token")
    if not token:
        return redirect(url_for("login"))
    
    user_id = get_session_user(token)
    if not user_id:
        return redirect(url_for("login"))
    
    conn = get_db()
    c = conn.cursor()
    execute_query(c, "SELECT email FROM users WHERE id = %s", (user_id,))
    user = c.fetchone()
    conn.close()
    
    return render_template("dashboard.html", email=user['email'], token=token)

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)
else:
    init_db()
