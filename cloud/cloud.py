"""
Cloud Service — Context-Aware Decryption with Replay Protection
and Encrypted Key Archive Recovery

Replay ID: composite key_id-nonce-timestamp
Key Archive: Hybrid AES+RSA encrypted, decrypted and stored
"""
import socket, json, os, time, threading, hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

cloud_private = serialization.load_pem_private_key(
    open("/keys/cloud_private.pem", "rb").read(),
    password=None
)

os.makedirs("storage", exist_ok=True)
os.makedirs("key_archive", exist_ok=True)
os.makedirs("/shared/decrypted", exist_ok=True)

# === Replay Protection ===
seen_messages = set()
MAX_CLOCK_DRIFT = 30

# === Per-Context Stats ===
context_stats = {
    "LOW_LATENCY_ALERT": {"count": 0, "total_ms": 0},
    "HIGH_VALUE_IMAGE":  {"count": 0, "total_ms": 0},
    "CRITICAL_EVENT":    {"count": 0, "total_ms": 0}
}


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
            else:
                save_path = f"/shared/decrypted/{filename}"
                with open(save_path, "wb") as f:
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
