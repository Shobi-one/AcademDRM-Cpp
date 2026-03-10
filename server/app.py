from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import sqlite3
import json
import time
import os

app = Flask(__name__)

DATABASE = "licenses.db"
PRIVATE_KEY_FILE = "private.pem"
LICENSE_EXPIRY_SECONDS = 7 * 24 * 60 * 60

with open(PRIVATE_KEY_FILE, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

def init_db():
    if not os.path.exists(DATABASE):
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
    message = json.dumps(payload, sort_keys=True).encode()
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature.hex()

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
    app.run(host="0.0.0.0", port=5000)