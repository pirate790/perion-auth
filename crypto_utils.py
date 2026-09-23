import os
import base64
import hashlib
import hmac
import struct
import time
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ============================================================
# MASTER KEY — LOAD OR GENERATE (FIXED)
# ============================================================
KEY_FILE = os.path.join(os.path.dirname(__file__), ".master_key")

def load_or_create_master_key():
    """
    Load the master key from (in order of priority):
    1. Environment variable TOTP_MASTER_KEY
    2. The .master_key file
    3. Generate a new one and save it
    """
    # 1. Check environment variable first
    env_key = os.environ.get("TOTP_MASTER_KEY")
    if env_key:
        print("Loaded master key from environment variable.")
        return env_key.strip()
    
    # 2. Check if key file exists — LOAD IT, don't regenerate
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "r") as f:
            key = f.read().strip()
        if key:
            print(f"Loaded master key from {KEY_FILE}")
            return key
    
    # 3. Generate new key and save it (only happens once)
    key = AESGCM.generate_key(bit_length=256)
    key_b64 = base64.b64encode(key).decode()
    with open(KEY_FILE, "w") as f:
        f.write(key_b64)
    # Restrict file permissions (owner read/write only)
    try:
        os.chmod(KEY_FILE, 0o600)
    except Exception:
        pass
    print("=" * 60)
    print("FIRST RUN: GENERATED NEW MASTER KEY")
    print(f"Saved to: {KEY_FILE}")
    print(f"MASTER_KEY={key_b64}")
    print("=" * 60)
    print("BACK THIS UP. If you lose it, all TOTP secrets become unrecoverable.")
    print("=" * 60)
    return key_b64

MASTER_KEY = load_or_create_master_key()


# ============================================================
# ENCRYPTION (AES-256-GCM)
# ============================================================
def encrypt_secret(plaintext_secret):
    """Encrypt a TOTP secret before storing in DB."""
    key = base64.b64decode(MASTER_KEY)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce, unique per encryption
    ciphertext = aesgcm.encrypt(nonce, plaintext_secret.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_secret(encrypted_blob):
    """Decrypt a stored TOTP secret for verification."""
    key = base64.b64decode(MASTER_KEY)
    aesgcm = AESGCM(key)
    data = base64.b64decode(encrypted_blob)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


# ============================================================
# TOTP (from scratch, RFC 6238)
# ============================================================
def generate_secret():
    """Generate a random 20-byte secret, returned as Base32 string."""
    random_bytes = os.urandom(20)
    return base64.b32encode(random_bytes).decode('utf-8')


def hotp(secret_base32, counter):
    """HMAC-based One-Time Password (RFC 4226)."""
    key = base64.b32decode(secret_base32)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    binary = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(binary % 1000000).zfill(6)


def totp(secret_base32, time_step=30):
    """Time-based One-Time Password (RFC 6238)."""
    counter = int(time.time() // time_step)
    return hotp(secret_base32, counter)


def verify_totp(secret_base32, code, window=1, time_step=30):
    """Verify a code with a +/- window for clock drift."""
    current_counter = int(time.time() // time_step)
    for i in range(-window, window + 1):
        if hotp(secret_base32, current_counter + i) == code:
            return True
    return False


# ============================================================
# BACKUP CODES
# ============================================================
def generate_backup_codes(count=10):
    """Generate backup codes and their SHA-256 hashes."""
    codes = []
    hashes = []
    for _ in range(count):
        code = ''.join(secrets.choice('0123456789') for _ in range(8))
        codes.append(code)
        hashes.append(hashlib.sha256(code.encode()).hexdigest())
    return codes, hashes


def hash_backup_code(code):
    """Hash a single backup code for comparison."""
    return hashlib.sha256(code.encode()).hexdigest()
