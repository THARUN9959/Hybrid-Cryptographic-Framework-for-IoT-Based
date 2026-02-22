"""
Gateway Service — Policy Enforcement Engine
with Anti-Downgrade Protection and Context-Bound Verification

Flow: enforce_policy → build_signed_payload → verify_signature → forward
"""
import socket, json, time, hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Load Camera verification keys
camera_rsa_public = serialization.load_pem_public_key(
    open("/keys/camera_public.pem", "rb").read()
)
camera_ed_public = serialization.load_pem_public_key(
    open("/keys/camera_ed_public.pem", "rb").read()
)


# ============================================================
# POLICY TABLE — Must match Camera's table exactly
# ============================================================
CRYPTO_POLICY = {
    "LOW_LATENCY_ALERT": {
        "encryption": "AES-128-GCM",
        "signature": "Ed25519",
        "key_class": "K1",
        "min_key_bits": 128,
        "policy_version": 2
    },
    "HIGH_VALUE_IMAGE": {
        "encryption": "AES-256-GCM",
        "signature": "Ed25519",
        "key_class": "K2",
        "min_key_bits": 256,
        "policy_version": 2
    },
    "CRITICAL_EVENT": {
        "encryption": "AES-256-GCM",
        "signature": "RSA-PSS",
        "key_class": "K3",
        "min_key_bits": 256,
        "policy_version": 2
    }
}


# ============================================================
# STEP 1: ANTI-DOWNGRADE ENFORCEMENT
# ============================================================
def enforce_policy(header):
    """Validate header fields against registered policy table.
    Rejects: unknown context, encryption downgrade, signature downgrade,
    wrong key class, wrong policy version."""
    context = header.get("context")
    policy = CRYPTO_POLICY.get(context)

    if not policy:
        raise Exception(f"Unknown context: {context}")

    if header.get("algorithm") != policy["encryption"]:
        raise Exception(f"Encryption downgrade: expected {policy['encryption']}, got {header.get('algorithm')}")

    if header.get("signature_scheme") != policy["signature"]:
        raise Exception(f"Signature downgrade: expected {policy['signature']}, got {header.get('signature_scheme')}")

    if header.get("key_class") != policy["key_class"]:
        raise Exception(f"Key class mismatch: expected {policy['key_class']}, got {header.get('key_class')}")

    if header.get("policy_version") != policy["policy_version"]:
        raise Exception(f"Policy version mismatch: expected {policy['policy_version']}, got {header.get('policy_version')}")

    return True


# ============================================================
# STEP 2: REBUILD SIGNED PAYLOAD (Canonicalized JSON)
# ============================================================
def build_signed_payload(header, ciphertext):
    """Reconstruct the exact canonicalized payload the Camera signed."""
    signed_blob = {
        "context": header["context"],
        "policy_version": header["policy_version"],
        "algorithm": header["algorithm"],
        "signature_scheme": header["signature_scheme"],
        "key_id": header["key_id"],
        "timestamp": header["timestamp"],
        "nonce": header["nonce"],
        "ciphertext_hash": hashlib.sha256(ciphertext).hexdigest()
    }
    return json.dumps(signed_blob, sort_keys=True).encode()


# ============================================================
# STEP 3: VERIFY SIGNATURE
# ============================================================
def verify_signature(header, payload, signature):
    """Verify using context-appropriate scheme."""
    scheme = header.get("signature_scheme", "Ed25519")

    if scheme == "Ed25519":
        camera_ed_public.verify(signature, payload)
    else:  # RSA-PSS
        camera_rsa_public.verify(
            signature,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )


# ============================================================
# NETWORK
# ============================================================
def recv_all(conn):
    chunks = []
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def forward_data(data):
    for attempt in range(3):
        try:
            s = socket.socket()
            s.settimeout(10)
            s.connect(("cloud", 5001))
            s.sendall(data)
            s.close()
            return True
        except Exception as e:
            print(f"  Forward retry {attempt+1}: {e}")
            time.sleep(1)
    return False


# ============================================================
# MAIN — Gateway Enforcement Engine
# ============================================================
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 5000))
server.listen(5)

print("=" * 60)
print("Gateway — Policy Enforcement Engine v2")
print(f"Registered policies: {list(CRYPTO_POLICY.keys())}")
print(f"Verification: Ed25519 (alerts/images) + RSA-PSS (critical)")
print(f"Anti-downgrade: encryption + signature + key_class + version")
print("=" * 60)

while True:
    conn, addr = server.accept()
    try:
        data = recv_all(conn)
        if not data:
            continue

        message = json.loads(data.decode())
        header = message["header"]
        ciphertext = bytes.fromhex(message["ciphertext"])
        signature = bytes.fromhex(message["signature"])

        context = header.get("context", "?")
        filename = header.get("filename", "?")
        pid = header.get("packet_id", "?")[:8]
        key_id = header.get("key_id", "?")

        # === STEP 1: Anti-Downgrade Enforcement ===
        try:
            enforce_policy(header)
        except Exception as e:
            print(f"⛔ POLICY REJECTED | {filename} | {e}")
            continue

        # === STEP 2: Rebuild Signed Payload ===
        payload = build_signed_payload(header, ciphertext)

        # === STEP 3: Verify Signature ===
        start_verify = time.time()
        try:
            verify_signature(header, payload, signature)
            end_verify = time.time()
            verify_time = (end_verify - start_verify) * 1000

            ctx_icon = {"LOW_LATENCY_ALERT": "🟡", "HIGH_VALUE_IMAGE": "🟢", "CRITICAL_EVENT": "🔴"}.get(context, "⚪")
            scheme = header.get("signature_scheme", "?")
            print(f"{ctx_icon} VERIFIED ({verify_time:.2f}ms) | {filename} | {scheme} | key:{key_id} | pid:{pid}...")

            # === STEP 4: Forward to Cloud ===
            if forward_data(data):
                print(f"  → Forwarded to cloud")
            else:
                print(f"  ✗ Forward failed")

        except Exception as e:
            end_verify = time.time()
            verify_time = (end_verify - start_verify) * 1000
            print(f"⛔ INVALID SIGNATURE ({verify_time:.2f}ms) | {filename} | DROPPED")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
