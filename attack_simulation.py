"""
Attack Simulation Script -- Secure CCTV System

Simulates 3 attack types:
  1. Packet Tampering (modified encrypted data)
  2. Replay Attack (resend a captured packet)
  3. Forged Signature (sign with wrong key)
"""

import os
import sys
import json
import time
import base64
import requests
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:5001/event")
KEYS_DIR    = os.getenv("KEYS_DIR",    "./keys")

def load_cloud_pub():
    with open(os.path.join(KEYS_DIR, "cloud_public.pem"), "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_camera_priv():
    with open(os.path.join(KEYS_DIR, "camera_private.pem"), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def build_legitimate_packet(camera_priv, cloud_pub):
    """Build a valid packet (to use as baseline for attacks)."""
    aes_key = AESGCM.generate_key(bit_length=128)
    aesgcm  = AESGCM(aes_key)
    nonce   = os.urandom(12)

    recording_id = str(uuid.uuid4())
    metadata = json.dumps({
        "recording_id": recording_id,
        "camera_id": "CAM-ATTACKER",
        "timestamp": time.time(),
        "key_set_id": 99,
        "key_index": 0,
    }).encode()

    frame = b"ATTACK_TEST_FRAME_DATA" + os.urandom(32)
    encrypted_data = aesgcm.encrypt(nonce, frame, metadata)

    encrypted_key = cloud_pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    signature = camera_priv.sign(
        encrypted_key + encrypted_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    return {
        "recording_id": recording_id,
        "camera_id": "CAM-ATTACKER",
        "timestamp": time.time(),
        "key_set_id": 99,
        "key_index": 0,
        "nonce": base64.b64encode(nonce).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "encrypted_data": base64.b64encode(encrypted_data).decode(),
        "signature": base64.b64encode(signature).decode(),
        "metadata_aad": base64.b64encode(metadata).decode(),
    }

def divider(title):
    print(f"\n{'='*60}")
    print(f"  ATTACK: {title}")
    print(f"{'='*60}")

# ---- Attack 1 ----
def attack_tamper():
    """Tamper with encrypted data after signing -> should be rejected."""
    divider("PACKET TAMPERING")
    camera_priv = load_camera_priv()
    cloud_pub   = load_cloud_pub()
    pkt = build_legitimate_packet(camera_priv, cloud_pub)

    # Tamper: flip bytes in encrypted_data
    raw = base64.b64decode(pkt["encrypted_data"])
    tampered = bytes([b ^ 0xFF for b in raw[:16]]) + raw[16:]
    pkt["encrypted_data"] = base64.b64encode(tampered).decode()

    print("  Sending tampered packet...")
    try:
        r = requests.post(GATEWAY_URL, json=pkt, timeout=5)
        if r.status_code == 401:
            print(f"  [OK] DEFENSE WORKS -- Gateway rejected (HTTP {r.status_code})")
            print(f"    Response: {r.json()}")
        else:
            print(f"  [FAIL] DEFENSE FAILED -- Got HTTP {r.status_code}")
    except Exception as e:
        print(f"  [WARN] Connection error: {e}")

# ---- Attack 2 ----
def attack_replay():
    """Send same packet twice -> second should be rejected by cloud."""
    divider("REPLAY ATTACK")
    camera_priv = load_camera_priv()
    cloud_pub   = load_cloud_pub()
    pkt = build_legitimate_packet(camera_priv, cloud_pub)

    print("  Sending first (legitimate) packet...")
    try:
        r1 = requests.post(GATEWAY_URL, json=pkt, timeout=5)
        print(f"  First:  HTTP {r1.status_code} -- {r1.json()}")
    except Exception as e:
        print(f"  [WARN] First send error: {e}")
        return

    time.sleep(1)

    print("  Replaying same packet...")
    try:
        r2 = requests.post(GATEWAY_URL, json=pkt, timeout=5)
        if r2.status_code == 409 or r2.status_code != 200:
            print(f"  [OK] DEFENSE WORKS -- Replay rejected (HTTP {r2.status_code})")
            print(f"    Response: {r2.json()}")
        else:
            print(f"  [FAIL] DEFENSE FAILED -- Got HTTP {r2.status_code}")
    except Exception as e:
        print(f"  [WARN] Replay send error: {e}")

# ---- Attack 3 ----
def attack_forged_signature():
    """Sign with a rogue key (not Camera's real private key) -> should be rejected."""
    divider("FORGED SIGNATURE (Rogue Device)")
    cloud_pub = load_cloud_pub()

    # Generate a ROGUE key pair
    rogue_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    pkt = build_legitimate_packet(rogue_priv, cloud_pub)

    print("  Sending packet signed with rogue key...")
    try:
        r = requests.post(GATEWAY_URL, json=pkt, timeout=5)
        if r.status_code == 401:
            print(f"  [OK] DEFENSE WORKS -- Gateway rejected forged signature (HTTP {r.status_code})")
            print(f"    Response: {r.json()}")
        else:
            print(f"  [FAIL] DEFENSE FAILED -- Got HTTP {r.status_code}")
    except Exception as e:
        print(f"  [WARN] Connection error: {e}")

# ---- Main ----
if __name__ == "__main__":
    print("+" + "=" * 58 + "+")
    print("|         ATTACK SIMULATION -- Secure CCTV System         |")
    print("+" + "=" * 58 + "+")

    attack_tamper()
    attack_replay()
    attack_forged_signature()

    print("\n" + "=" * 60)
    print("  ATTACK SIMULATION COMPLETE")
    print("=" * 60)
