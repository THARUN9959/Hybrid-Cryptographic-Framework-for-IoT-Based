# Secure CCTV: Hybrid Cryptographic IoT Surveillance Pipeline

This project simulates a secure smart-surveillance pipeline with three containerized stages:

1. Camera service (encrypt + sign + key rotation)
2. Gateway service (policy enforcement + signature verification)
3. Cloud service (decrypt + replay protection + optional LLM analysis)

It also includes host-side tools for:

1. YOLO-based object detection and event generation
2. Displaying decrypted output
3. Natural-language querying of recent events
4. Attack simulation and performance evaluation

## What Is Happening In This Project

The system classifies outgoing data into security contexts and applies different crypto policies:

1. `LOW_LATENCY_ALERT`: AES-128-GCM + Ed25519 + key class K1
2. `HIGH_VALUE_IMAGE`: AES-256-GCM + Ed25519 + key class K2
3. `CRITICAL_EVENT`: AES-256-GCM + RSA-PSS + key class K3

Core behavior:

1. Host detector writes events/frames to shared folders.
2. Camera container reads raw data, classifies context, encrypts, signs, and forwards to Gateway.
3. Gateway validates anti-downgrade policy and signatures, then forwards verified packets to Cloud.
4. Cloud rejects replays, decrypts payloads, writes artifacts, and can run LLM analysis (Ollama).
5. Cloud can publish adaptive policy hints (`/shared/control/encryption_policy.json`) that Camera applies (for dynamic key-rotation interval).

## Project Structure

Main workspace folder:

`secure-cctv/`

Important files and folders:

1. `docker-compose.yml`
   1. Starts `camera`, `gateway`, `cloud` containers
   2. Mounts `./keys` and `./shared` into containers
2. `run_simulation.ps1`
   1. End-to-end launcher for full local demo
   2. Starts Docker services, host detector, viewer, and query console
3. `generate_keys.py`
   1. Generates camera/cloud key pairs in `keys/`
4. `detect_and_send.py`
   1. Host YOLO detection (webcam)
   2. Writes event files to `shared/metadata/`
5. `display_host.py`
   1. Displays decrypted image frames from `shared/decrypted/`
6. `query_events.py`
   1. Natural-language query over recent decrypted event text files
   2. Uses Ollama if available, else keyword fallback
7. `attack_simulation.py`
   1. Simulates tampering, replay, forged-signature attacks
8. `performance_eval.py`
   1. Benchmarks crypto overhead and throughput

Service code:

1. `camera/camera.py`
   1. Context classification, policy-bound crypto, key lifecycle management, packet build/sign/send
2. `gateway/gateway.py`
   1. Policy checks + signature verification + forwarding to Cloud
3. `cloud/cloud.py`
   1. Replay checks, decryption, archive recovery, optional LLM analysis, adaptive policy publishing
4. `cloud/llm_module.py`
   1. Calls Ollama endpoint with structured prompt/history context

Shared data folders (host + containers):

1. `shared/raw/`: host-captured raw frames (`.jpg`) + motion metadata (`.meta`)
2. `shared/frames/`: encrypted frame payloads (camera output)
3. `shared/metadata/`: host-detected event text files
4. `shared/decrypted/`: cloud-decrypted outputs (images/events)
5. `shared/control/`: adaptive crypto policy file from cloud to camera

Other data:

1. `data/key_archive/`: archived key lifecycle snapshots
2. `data/metadata/`, `data/recordings/`: dataset and generated assets

## End-to-End Flow

```text
Webcam/YOLO Host
  -> shared/raw + shared/metadata
  -> Camera service
       - classify context
       - select policy (AES/signature/key class)
       - encrypt + wrap key + sign canonical payload
  -> Gateway service
       - enforce anti-downgrade policy
       - verify signature (Ed25519 or RSA-PSS)
  -> Cloud service
       - replay protection (timestamp + composite message id)
       - unwrap key + AES-GCM decrypt
       - write decrypted outputs
       - optional LLM analysis (Ollama)
       - publish adaptive rotation interval policy
```

## Prerequisites

Before running, install and verify:

1. Docker Desktop (running)
2. Python 3.10+ on host
3. PowerShell (Windows)
4. Webcam access (for host detector)
5. Ollama (optional, but recommended for LLM features)
   1. Install Ollama
   2. Pull model: `ollama pull mistral`
6. Host Python packages for local scripts:
   1. `ultralytics`
   2. `opencv-python`
   3. `requests`
   4. `cryptography`

The Docker images install container-side dependencies automatically.

## One-Time Setup

From `secure-cctv/`:

```powershell
python -m pip install --upgrade pip
python -m pip install ultralytics opencv-python requests cryptography
python generate_keys.py
```

Generated key files in `keys/` include:

1. `camera_private.pem` and `camera_public.pem` (RSA-PSS path)
2. `camera_ed_private.pem` and `camera_ed_public.pem` (Ed25519 path)
3. `cloud_private.pem` and `cloud_public.pem` (RSA-OAEP unwrap/wrap)

## Quick Start (Recommended)

Run full pipeline:

```powershell
.\run_simulation.ps1
```

This script will:

1. Clean old shared artifacts
2. Build and start Docker services (`camera`, `gateway`, `cloud`)
3. Start Ollama model session (`mistral`) in a new terminal
4. Start YOLO host detector
5. Start decrypted stream viewer
6. Open query console
7. Attach current terminal to `docker-compose logs -f`

To open only the query console mode:

```powershell
.\run_simulation.ps1 -QueryConsole
```

## Manual Run (Alternative)

If you want to start each part manually:

1. Generate keys:

```powershell
python generate_keys.py
```

2. Start containers:

```powershell
docker-compose up --build -d
```

3. Start Ollama on host (optional but recommended):

```powershell
ollama run mistral
```

4. Start host detector:

```powershell
python detect_and_send.py
```

5. Start decrypted frame viewer:

```powershell
python display_host.py
```

6. Query events from another terminal:

```powershell
python query_events.py "show suspicious events from last 10 minutes" --minutes 10
```

## Runtime Outputs You Should Expect

1. Camera logs:
   1. context-selected encryption/signing lines
   2. key rotation and archive send messages
2. Gateway logs:
   1. verified packets
   2. policy rejection or invalid signature drops
3. Cloud logs:
   1. decrypted alerts/events/images
   2. replay rejection when duplicate/stale
   3. LLM analysis status for text events
4. Host windows:
   1. YOLO annotated feed
   2. decrypted image viewer
   3. query prompt console

## Security and Evaluation Utilities

Attack simulation:

```powershell
python attack_simulation.py
```

Expected outcome: gateway/cloud should reject tampered, replayed, or forged packets.

Performance evaluation:

```powershell
python performance_eval.py
```

Reports:

1. AES-GCM encrypt/decrypt overhead
2. RSA wrap/sign/verify overhead
3. communication overhead ratio
4. estimated throughput
5. risk window based on key rotation config

## Configuration Notes

Container environment (from `docker-compose.yml`):

1. `OLLAMA_URL` default: `http://host.docker.internal:11434/api/generate`
2. `OLLAMA_MODEL` default: `mistral`
3. `OLLAMA_TIMEOUT_SECONDS` default: `120`
4. `OLLAMA_RETRIES` default: `2`

If Ollama is not available:

1. `query_events.py` falls back to keyword matching
2. Cloud text-event analysis may fail gracefully depending on host state

## Stop and Cleanup

Stop Docker services:

```powershell
docker-compose down
```

Follow logs anytime:

```powershell
docker-compose logs -f
```

Clear shared artifacts (manual):

```powershell
Remove-Item shared\raw\* -ErrorAction SilentlyContinue
Remove-Item shared\frames\* -ErrorAction SilentlyContinue
Remove-Item shared\decrypted\* -ErrorAction SilentlyContinue
Remove-Item shared\metadata\* -ErrorAction SilentlyContinue
```

## Troubleshooting

1. Webcam not opening
   1. Close other apps using camera
   2. Check Windows camera permissions
2. `ollama` command not found
   1. Install Ollama and reopen terminal
   2. Pull model: `ollama pull mistral`
3. No decrypted output
   1. Confirm detector is producing events/frames
   2. Check gateway/cloud logs for policy or signature rejection
   3. Verify keys exist in `keys/` and match expected names
4. Container cannot reach host Ollama
   1. Ensure Docker Desktop is running
   2. Verify endpoint `host.docker.internal:11434`
5. Slow inference
   1. Increase `OLLAMA_TIMEOUT_SECONDS`
   2. Use a lighter local model if needed

## Typical Development Workflow

1. Update crypto/policy logic in `camera/camera.py` and `gateway/gateway.py`
2. Rebuild containers with `docker-compose up --build -d`
3. Run full simulation and monitor logs
4. Validate resilience with `attack_simulation.py`
5. Measure impact with `performance_eval.py`
