from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import sqlite3
import json
import time
import os
from pathlib import Path

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent

DATABASE = BASE_DIR / "licenses.db"
PRIVATE_KEY_FILE = BASE_DIR / "private.pem"
PUBLIC_KEY_EXPORT_FILE = REPO_ROOT / "public.pem"
LICENSE_EXPIRY_SECONDS = 7 * 24 * 60 * 60
STARTUP_BANNER = r"""
         _____          _____  ______ __  __ _____  _____  __  __         _____ _____  _____     _____ ______ _______      ________ _____
     /\   / ____|   /\   |  __ \|  ____|  \/  |  __ \|  __ \|  \/  |       / ____|  __ \|  __ \   / ____|  ____|  __ \ \    / /  ____|  __ \
    /  \ | |       /  \  | |  | | |__  | \  / | |  | | |__) | \  / |______| |    | |__) | |__) | | (___ | |__  | |__) \ \  / /| |__  | |__) |
   / /\ \| |      / /\ \ | |  | |  __| | |\/| | |  | |  _  /| |\/| |______| |    |  ___/|  ___/   \___ \|  __| |  _  / \ \/ / |  __| |  _  /
  / ____ \ |____ / ____ \| |__| | |____| |  | | |__| | | \ \| |  | |      | |____| |    | |       ____) | |____| | \ \  \  /  | |____| | \ \
 /_/    \_\_____/_/    \_\_____/|______|_|  |_|_____/|_|  \_\_|  |_|       \_____|_|    |_|      |_____/|______|_|  \_\  \/   |______|_|  \_\
"""

def load_or_create_private_key():
    if not PRIVATE_KEY_FILE.exists():
        generated_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        pem = generated_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(PRIVATE_KEY_FILE, "wb") as key_file:
            key_file.write(pem)
        print(f"[setup] Generated new private key: {PRIVATE_KEY_FILE}")

    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def export_public_key(private_key):
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(PUBLIC_KEY_EXPORT_FILE, "wb") as key_file:
        key_file.write(public_pem)

    print(f"[setup] Exported public key: {PUBLIC_KEY_EXPORT_FILE}")

private_key = load_or_create_private_key()
export_public_key(private_key)

def init_db():
    if not DATABASE.exists():
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE licenses (
                license_key TEXT PRIMARY KEY,
                hardware_id TEXT,
                expires INTEGER,
                active INTEGER
            )
        """)

        c.execute("INSERT INTO licenses (license_key, hardware_id, expires, active) VALUES (?, ?, ?, ?)",
                  ("TEST-1234-ABCD", "", int(time.time()) + LICENSE_EXPIRY_SECONDS, 1))
        conn.commit()
        conn.close()
        print(f"[setup] Created new database: {DATABASE} (seeded TEST-1234-ABCD)")

init_db()

def get_license(license_key):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT license_key, hardware_id, expires, active FROM licenses WHERE license_key = ?", (license_key,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"license_key": row[0], "hardware_id": row[1], "expires": row[2], "active": row[3]}
    return None

def bind_hardware(license_key, hardware_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("UPDATE licenses SET hardware_id = ? WHERE license_key = ?", (hardware_id, license_key))
    conn.commit()
    conn.close()

def sign_payload(payload: dict) -> str:
    message = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature.hex()

@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "AcademDRM license server"})

@app.route("/validate", methods=["POST"])
def validate():
    data = request.get_json()

    license_key = data.get("license_key", "")
    hardware_id = data.get("hardware_id", "")
    nonce = data.get("nonce", "")
    timestamp = data.get("timestamp", 0)

    if not license_key or not hardware_id or not nonce or not timestamp:
        return jsonify({"error": "Missing fields"}), 400

    now = int(time.time())
    if abs(now - timestamp) > 300:
        return jsonify({"error": "Timestamp invalid"}), 400

    license_entry = get_license(license_key)
    if not license_entry or not license_entry["active"]:
        return jsonify({"status": "invalid", "reason": "License not found or inactive"}), 403

    if license_entry["expires"] < now:
        return jsonify({"status": "invalid", "reason": "License expired"}), 403

    if license_entry["hardware_id"] == "":
        bind_hardware(license_key, hardware_id)
    elif license_entry["hardware_id"] != hardware_id:
        return jsonify({"status": "invalid", "reason": "Hardware mismatch"}), 403

    response_payload = {
        "status": "valid",
        "expires": license_entry["expires"],
        "nonce": nonce
    }

    signature = sign_payload(response_payload)

    return jsonify({
        "data": response_payload,
        "signature": signature
    })

if __name__ == "__main__":
    print(STARTUP_BANNER)
    app.run(host="127.0.0.1", port=5000)