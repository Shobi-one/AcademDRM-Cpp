# AcademDRM-Cpp

AcademDRM-Cpp is an educational DRM and anti-tamper prototype built with:
- A native C++ client that performs license verification, anti-debug checks, integrity checks, and protected feature unlocking
- A Python Flask license server that signs license responses and enforces hardware-bound activation

The project is intentionally designed as a learning artifact for software protection concepts.

## Disclaimer

This project is for academic and defensive research use only.
It is not production DRM and should not be used as a sole protection layer for commercial software.

## Highlights

- End-to-end license flow: challenge request, signed response, local signature verification
- Hardware binding: first successful activation binds a key to a hardware fingerprint
- Startup protections:
	- Anti-debug checks
	- In-memory .text integrity validation against on-disk image
- Virtualized execution pipeline:
	- Small DSL/compiler
	- Bytecode encoding
	- Bytecode encryption/decryption
	- Host-callback VM execution
- Protected feature gating (ASCII donut animation)
- Interactive diagnostics console to demonstrate each stage independently

## High-Level Architecture

```text
+-------------------------+         HTTP POST /validate         +-------------------------+
| C++ Client              | ----------------------------------> | Flask License Server    |
| - HWID collection       |                                     | - SQLite license store  |
| - Nonce + timestamp     | <---------------------------------- | - Signature generation  |
| - Signature verify      |      JSON {data, signature}         | - HWID bind + expiry    |
| - Startup protections   |                                     |                         |
| - VM protected payload  |                                     +-------------------------+
+-------------------------+
```

## Repository Layout

```text
client/
	include/drm/
		security/                 # anti-debug and integrity checks
		vm/                       # VM, bytecode codec, encryption
		crypto_verify.hpp         # signed payload verification API
		hardware_id.hpp           # HWID API
		license_client.hpp        # license validation API
		protected_logic.hpp       # protected feature entrypoint
	src/
		main.cpp                  # interactive console and DRM journey
		license_client.cpp        # server call + local verification logic
		crypto_verify.cpp         # OpenSSL signature verification
		hardware_id.cpp           # Windows HWID collection
	protected/
		donut_animation.cpp       # gated protected feature

server/
	app.py                      # Flask app, key management, license endpoint
	data/                       # SQLite db
	keys/                       # server private key

vcpkg/                        # vendored dependency manager checkout
vcpkg.json                    # dependency manifest
```

## DRM Flow

1. Client computes hardware fingerprint.
2. Client generates nonce and timestamp.
3. Client sends `{license_key, hardware_id, nonce, timestamp}` to `/validate`.
4. Server checks:
	 - required fields
	 - timestamp freshness
	 - license active/expiry
	 - hardware binding rules
5. Server signs canonical JSON payload and returns `{data, signature}`.
6. Client verifies signature with `public.pem`.
7. Client validates payload status + nonce match.
8. Client unlocks protected logic only on successful checks.

## Requirements

### Client (Windows)

- Visual Studio C++ toolchain (`cl`)
- PowerShell
- vcpkg dependencies (installed via manifest):
	- `curl`
	- `openssl`
	- `nlohmann-json`

### Server

- Python 3.10+
- `flask`
- `cryptography`

## Setup

## 1) Install C++ dependencies with vcpkg

From repository root:

```powershell
.\vcpkg\bootstrap-vcpkg.bat
.\vcpkg\vcpkg.exe install --triplet x64-windows
```

## 2) Install Python dependencies

```powershell
python -m pip install flask cryptography
```

## 3) Start the license server

```powershell
python .\server\app.py
```

On first run the server will:
- Create `server/keys/private.pem` if missing
- Export `public.pem` to repository root
- Create `server/data/licenses.db` with a seeded test key

Seeded demo key:

```text
TEST-1234-ABCD
```

## Build and Run Client (CMake)

This repository now uses CMake for client builds.

### Option A: Use presets (recommended)

```powershell
cmake --preset windows-release
cmake --build --preset build-release
```

Run:

```powershell
.\build\Release\AcademDRMClient.exe
```

### Option B: Explicit configure/build commands

```powershell
cmake -S . -B .\build -DCMAKE_TOOLCHAIN_FILE=.\vcpkg\scripts\buildsystems\vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build .\build --config Release
```

Run:

```powershell
.\build\Release\AcademDRMClient.exe
```

`CMakeLists.txt` copies required runtime DLLs next to the executable after build:
- `libcurl.dll`
- `libcrypto-3-x64.dll`
- `libssl-3-x64.dll`
- `zlib1.dll`

## Demo Walkthrough

1. Start server: `python .\server\app.py`
2. Build/run client.
3. In client menu, run:
	 - `7` startup diagnostics
	 - `8` VM diagnostics
	 - `10` full DRM journey
4. Validate with default key (`TEST-1234-ABCD`) or custom entries in SQLite.

## API

### `GET /`

Health endpoint.

Response example:

```json
{"status":"ok","service":"AcademDRM license server"}
```

### `POST /validate`

Request JSON:

```json
{
	"license_key": "TEST-1234-ABCD",
	"hardware_id": "123456789",
	"nonce": "a1b2c3d4e5f60789",
	"timestamp": 1760000000
}
```

Success response:

```json
{
	"data": {
		"status": "valid",
		"expires": 1760604800,
		"nonce": "a1b2c3d4e5f60789"
	},
	"signature": "<hex-signature>"
}
```

Failure response examples:
- `{"error":"Missing fields"}`
- `{"error":"Timestamp invalid"}`
- `{"status":"invalid","reason":"License expired"}`
- `{"status":"invalid","reason":"Hardware mismatch"}`

## Security Notes

What this project demonstrates well:
- Signed server payloads with local verification
- Nonce/timestamp anti-replay basics
- Process-environment checks at startup
- Code-section integrity validation concept
- VM-based indirection for protected logic

Known limitations:
- Prototype-level anti-debug and anti-tamper only
- HWID strategy is simplified and Windows-specific
- Local attacker with sufficient capability can still bypass controls
- Some crypto/verification implementation choices are educational rather than hardened
- No formal threat model document or penetration test report yet

## Troubleshooting

- Signature verification fails:
	- Ensure `public.pem` exists in repository root and matches server private key
- HTTP request fails:
	- Confirm server is running on `127.0.0.1:5000`
- Hardware mismatch:
	- License was already bound to another hardware fingerprint
- Build fails with missing libraries:
	- Re-run vcpkg install and verify include/lib paths
