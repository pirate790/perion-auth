import os
import base64
import io
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for
import bcrypt
import qrcode
from db import get_db, init_db
from crypto_utils import (
    encrypt_secret, decrypt_secret, generate_secret,
    totp, verify_totp, generate_backup_codes, hash_backup_code
)

app = Flask(__name__)

# ============================================================
# HELPERS
# ============================================================
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
SESSION_HOURS = 24

def is_rate_limited(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT attempts, last_attempt FROM rate_limits WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return False
    
    attempts, last_attempt = row
    if last_attempt:
        last = datetime.fromisoformat(last_attempt)
        if datetime.now() - last > timedelta(minutes=LOCKOUT_MINUTES):
            reset_rate_limit(user_id)
            return False
    
    return attempts >= MAX_ATTEMPTS

def increment_rate_limit(user_id):
    conn = get_db()
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute("""
        INSERT INTO rate_limits (user_id, attempts, last_attempt)
        VALUES (?, 1, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            attempts = attempts + 1,
            last_attempt = ?
    """, (user_id, now, now))
    conn.commit()
    conn.close()

def reset_rate_limit(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM rate_limits WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

def is_code_used(user_id, code):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT used_at FROM used_codes 
        WHERE user_id = ? AND code = ?
        ORDER BY used_at DESC LIMIT 1
    """, (user_id, code))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return False
    
    used_at = datetime.fromisoformat(row[0])
    return datetime.now() - used_at < timedelta(seconds=30)

def mark_code_used(user_id, code):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO used_codes (user_id, code) VALUES (?, ?)", (user_id, code))
    c.execute("DELETE FROM used_codes WHERE used_at < ?", 
              ((datetime.now() - timedelta(minutes=2)).isoformat(),))
    conn.commit()
    conn.close()

def create_session(user_id):
    token = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(hours=SESSION_HOURS)).isoformat()
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
              (token, user_id, expires))
    conn.commit()
    conn.close()
    return token

def get_session_user(token):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT user_id FROM sessions 
        WHERE token = ? AND expires_at > ?
    """, (token, datetime.now().isoformat()))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def generate_qr_data_uri(secret, email, issuer="Perion Auth"):
    encoded_issuer = issuer.replace(" ", "%20")
    uri = f"otpauth://totp/{encoded_issuer}:{email}?secret={secret}&issuer={encoded_issuer}"
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
    c.execute("SELECT id FROM users WHERE email = ?", (email,))
    if c.fetchone():
        conn.close()
        return jsonify({"error": "Email already registered"}), 400
    
    # Hash password
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    # Generate TOTP secret
    secret = generate_secret()
    encrypted = encrypt_secret(secret)
    
    # Insert user
    c.execute("""
        INSERT INTO users (email, password_hash, totp_secret_encrypted, totp_enabled)
        VALUES (?, ?, ?, 1)
    """, (email, password_hash, encrypted))
    user_id = c.lastrowid
    
    # Generate backup codes
    codes, hashes = generate_backup_codes()
    for h in hashes:
        c.execute("INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)", (user_id, h))
    
    conn.commit()
    conn.close()
    
    # Generate QR
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
    c.execute("SELECT id, password_hash, totp_secret_encrypted, totp_enabled FROM users WHERE email = ?", (email,))
    user = c.fetchone()
    conn.close()
    
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    
    user_id, password_hash, encrypted_secret, totp_enabled = user
    
    # Verify password
    if not bcrypt.checkpw(password.encode(), password_hash.encode()):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # If TOTP is enabled, require code
    if totp_enabled:
        if not code:
            return jsonify({"error": "TOTP code required", "totp_required": True}), 401
        
        # Rate limit check
        if is_rate_limited(user_id):
            return jsonify({"error": "Too many attempts. Try again in 15 minutes."}), 429
        
        # Decrypt secret
        secret = decrypt_secret(encrypted_secret)
        
        # Check replay
        if is_code_used(user_id, code):
            return jsonify({"error": "Code already used. Wait for the next one."}), 401
        
        # Verify TOTP
        if verify_totp(secret, code):
            mark_code_used(user_id, code)
            reset_rate_limit(user_id)
            token = create_session(user_id)
            return jsonify({"success": True, "session_token": token})
        
        # Try backup codes
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, code_hash FROM backup_codes WHERE user_id = ? AND used = 0", (user_id,))
        rows = c.fetchall()
        conn.close()
        
        code_hash = hash_backup_code(code)
        for row in rows:
            if row[1] == code_hash:
                conn = get_db()
                c = conn.cursor()
                c.execute("UPDATE backup_codes SET used = 1, used_at = ? WHERE id = ?",
                          (datetime.now().isoformat(), row[0]))
                conn.commit()
                conn.close()
                reset_rate_limit(user_id)
                token = create_session(user_id)
                return jsonify({"success": True, "session_token": token, "used_backup_code": True})
        
        increment_rate_limit(user_id)
        return jsonify({"error": "Invalid code"}), 401
    
    # No TOTP — just login
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
    c.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    
    return render_template("dashboard.html", email=user[0], token=token)

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
