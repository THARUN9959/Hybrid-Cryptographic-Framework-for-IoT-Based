"""
Cloud Service — Context-Aware Decryption with Replay Protection
and Encrypted Key Archive Recovery

Replay ID: composite key_id-nonce-timestamp
Key Archive: Hybrid AES+RSA encrypted, decrypted and stored
"""
import socket, json, os, time, threading, hashlib
from collections import deque
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from llm_module import analyze_event

cloud_private = serialization.load_pem_private_key(
    open("/keys/cloud_private.pem", "rb").read(),
    password=None
)

os.makedirs("storage", exist_ok=True)
os.makedirs("key_archive", exist_ok=True)
os.makedirs("/shared/decrypted", exist_ok=True)
os.makedirs("/shared/control", exist_ok=True)
os.makedirs("/data/key_archive", exist_ok=True)
os.makedirs("/data/metadata", exist_ok=True)
os.makedirs("/data/recordings", exist_ok=True)

# === Replay Protection ===
seen_messages = set()
MAX_CLOCK_DRIFT = 30

# === Per-Context Stats ===
context_stats = {
    "LOW_LATENCY_ALERT": {"count": 0, "total_ms": 0},
    "HIGH_VALUE_IMAGE":  {"count": 0, "total_ms": 0},
    "CRITICAL_EVENT":    {"count": 0, "total_ms": 0}
}

# Temporal context for sequence-aware LLM reasoning.
event_history = deque(maxlen=20)
event_history_lock = threading.Lock()
control_lock = threading.Lock()

RISK_INTERVAL_SECONDS = {
    "LOW": 60,
    "MEDIUM": 30,
    "HIGH": 15,
    "CRITICAL": 10,
}


def extract_risk_level(analysis_text):
    for line in analysis_text.splitlines():
        if line.lower().startswith("risk:"):
            return line.split(":", 1)[1].strip().upper()
    return "MEDIUM"


def publish_adaptive_policy(event_text, analysis_text):
    risk = extract_risk_level(analysis_text)
    interval = RISK_INTERVAL_SECONDS.get(risk, 30)

    policy = {
        "updated_at": time.time(),
        "source": "cloud_llm",
        "risk": risk,
        "recommended_rotation_interval": interval,
        "event": event_text,
    }

    control_path = "/shared/control/encryption_policy.json"
    with control_lock:
        with open(control_path, "w", encoding="utf-8") as f:
            json.dump(policy, f, indent=2)

    print(f"🔐 Adaptive policy → risk:{risk} interval:{interval}s")


def analyze_and_store(event_text, save_path):
    with event_history_lock:
        stamped_event = f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {event_text}"
        event_history.append(stamped_event)
        history_snapshot = list(event_history)

    analysis = analyze_event(event_text, history_snapshot)
    print(f"🤖 LLM Analysis: {analysis}")
    publish_adaptive_policy(event_text, analysis)

    with open(save_path, "w", encoding="utf-8") as f:
        f.write(event_text + "\n")
        f.write(f"LLM Analysis: {analysis}\n")


def recv_all(conn):
    chunks = []
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def check_replay(header):
    """Composite replay ID: key_id + nonce + timestamp"""
    msg_id = f"{header['key_id']}-{header['nonce']}-{header['timestamp']}"

    if msg_id in seen_messages:
        raise Exception("Replay: duplicate message")

    drift = abs(time.time() - header["timestamp"])
    if drift > MAX_CLOCK_DRIFT:
        raise Exception(f"Replay: stale message ({drift:.1f}s drift)")

    seen_messages.add(msg_id)

    # Overflow protection
    if len(seen_messages) > 10000:
        seen_messages.clear()


def packet_server():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 5001))
    server.listen(5)

    print("Cloud packet server listening on port 5001...")

    while True:
        conn, _ = server.accept()
        try:
            data = recv_all(conn)
            if not data:
                continue

            message = json.loads(data.decode())
            header = message["header"]

            context = header.get("context", "UNKNOWN")
            filename = header.get("filename", "?")
            key_id = header.get("key_id", "?")
            pid = header.get("packet_id", "?")[:8]

            # === Replay Check ===
            try:
                check_replay(header)
            except Exception as e:
                print(f"⛔ REJECTED | {filename} | {e}")
                continue

            # === Decrypt ===
            encrypted_key = bytes.fromhex(message["encrypted_key"])
            ciphertext = bytes.fromhex(message["ciphertext"])
            nonce = bytes.fromhex(header["nonce"])

            start_dec = time.time()

            # Unwrap AES key (RSA-OAEP)
            aes_key = cloud_private.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # AES-GCM decrypt (auto-detects 128/256 from key length)
            aes = AESGCM(aes_key)
            decrypted = aes.decrypt(nonce, ciphertext, None)

            end_dec = time.time()
            dec_time = (end_dec - start_dec) * 1000

            # Determine AES variant
            aes_variant = f"AES-{len(aes_key)*8}-GCM"

            # Track stats
            if context in context_stats:
                context_stats[context]["count"] += 1
                context_stats[context]["total_ms"] += dec_time

            # Process based on type
            if filename.endswith(".alert"):
                alert = json.loads(decrypted.decode())
                print(f"🟡 Alert: {alert.get('type','?')} | {dec_time:.2f}ms | {aes_variant} | key:{key_id} | pid:{pid}...")
            elif filename.endswith(".txt"):
                event_text = decrypted.decode(errors="ignore").strip()
                print(f"🔵 Event: {event_text} | {dec_time:.2f}ms | {aes_variant} | key:{key_id} | pid:{pid}...")

                save_path = f"/shared/decrypted/{filename}"
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(event_text + "\n")
                    f.write("LLM Analysis: processing\n")

                data_meta_path = f"/data/metadata/{filename}"
                with open(data_meta_path, "w", encoding="utf-8") as f:
                    f.write(event_text + "\n")
                    f.write("LLM Analysis: processing\n")

                # Avoid blocking packet intake on slow LLM inference.
                threading.Thread(
                    target=analyze_and_store,
                    args=(event_text, save_path),
                    daemon=True,
                ).start()
            else:
                save_path = f"/shared/decrypted/{filename}"
                with open(save_path, "wb") as f:
                    f.write(decrypted)

                data_recording_path = f"/data/recordings/{filename}"
                with open(data_recording_path, "wb") as f:
                    f.write(decrypted)

                ctx_icon = "🔴" if context == "CRITICAL_EVENT" else "🟢"
                print(f"{ctx_icon} Decrypted: {filename} | {dec_time:.2f}ms | {aes_variant} | key:{key_id} | {len(ciphertext)}B→{len(decrypted)}B | pid:{pid}...")

        except Exception as e:
            print(f"Packet error: {e}")
        finally:
            conn.close()


def archive_server():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 6000))
    server.listen(5)

    print("Cloud archive server listening on port 6000...")
    archive_count = 0

    while True:
        conn, _ = server.accept()
        try:
            data = recv_all(conn)
            if not data:
                continue

            packet = json.loads(data.decode())
            wrapped_key = bytes.fromhex(packet["wrapped_key"])
            nonce = bytes.fromhex(packet["nonce"])
            encrypted_data = bytes.fromhex(packet["encrypted_data"])
            rotation_id = packet.get("rotation_id", "?")

            # Unwrap temp AES key
            temp_key = cloud_private.decrypt(
                wrapped_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Decrypt archive
            temp_aes = AESGCM(temp_key)
            archive_data = temp_aes.decrypt(nonce, encrypted_data, None)
            archive_json = json.loads(archive_data.decode())

            # Count keys recovered
            total_keys = sum(len(v) for v in archive_json.get("key_classes", {}).values())

            archive_count += 1
            archive_path = f"key_archive/archive_{archive_count}.json"
            with open(archive_path, "w") as f:
                json.dump(archive_json, f, indent=2)

            data_archive_path = f"/data/key_archive/archive_{archive_count}.json"
            with open(data_archive_path, "w", encoding="utf-8") as f:
                json.dump(archive_json, f, indent=2)

            print(f"🔑 Archive #{rotation_id} recovered: {total_keys} keys (K1/K2/K3) → {archive_path}")

        except Exception as e:
            print(f"Archive error: {e}")
        finally:
            conn.close()


def stats_reporter():
    """Periodic per-context performance report."""
    while True:
        time.sleep(120)
        total = sum(s["count"] for s in context_stats.values())
        if total > 0:
            print(f"\n📊 Performance Report ({total} packets)")
            for ctx, s in context_stats.items():
                if s["count"] > 0:
                    avg = s["total_ms"] / s["count"]
                    print(f"  {ctx}: {s['count']} pkts, avg {avg:.2f}ms")
            print()


print("=" * 60)
print("Cloud — Context-Aware Decryption Engine v2")
print(f"Replay: composite key_id-nonce-timestamp ({MAX_CLOCK_DRIFT}s drift)")
print(f"Archive: Hybrid AES+RSA recovery")
print("=" * 60)

threading.Thread(target=packet_server, daemon=True).start()
threading.Thread(target=archive_server, daemon=True).start()
threading.Thread(target=stats_reporter, daemon=True).start()

while True:
    time.sleep(60)
