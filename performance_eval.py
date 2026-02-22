"""
Performance Measurement Script -- Secure CCTV System

Measures:
  1. AES-GCM Encryption Overhead
  2. RSA Key Wrapping Overhead
  3. RSA Signing Overhead
  4. Communication Overhead (plaintext vs encrypted packet size)
  5. Throughput (events/sec)
  6. Risk Window calculation
"""

import os
import sys
import time
import json
import base64
import statistics

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

KEYS_DIR   = os.getenv("KEYS_DIR", "./keys")
ITERATIONS = 100
N_KEYS     = 5
ROTATION_INTERVAL = 60

def load_keys():
    with open(os.path.join(KEYS_DIR, "cloud_public.pem"), "rb") as f:
        cloud_pub = serialization.load_pem_public_key(f.read())
    with open(os.path.join(KEYS_DIR, "camera_private.pem"), "rb") as f:
        camera_priv = serialization.load_pem_private_key(f.read(), password=None)
    return camera_priv, cloud_pub

def measure(name, func, iterations=ITERATIONS):
    times = []
    result = None
    for _ in range(iterations):
        start = time.perf_counter()
        result = func()
        elapsed = (time.perf_counter() - start) * 1000  # ms
        times.append(elapsed)
    avg = statistics.mean(times)
    std = statistics.stdev(times) if len(times) > 1 else 0
    mn  = min(times)
    mx  = max(times)
    print(f"  {name:<35} avg={avg:.3f}ms  std={std:.3f}ms  min={mn:.3f}ms  max={mx:.3f}ms")
    return result, avg

def main():
    print("+" + "=" * 58 + "+")
    print("|       PERFORMANCE EVALUATION -- Secure CCTV System      |")
    print("+" + "=" * 58 + "+")
    print(f"  Iterations per test: {ITERATIONS}\n")

    camera_priv, cloud_pub = load_keys()

    # Sample data simulating a frame
    plaintext     = b"CCTV_FRAME_DATA_" + os.urandom(1024)  # 1KB frame
    metadata_aad  = json.dumps({"camera_id": "CAM-01", "ts": time.time()}).encode()
    aes_key       = AESGCM.generate_key(bit_length=128)
    nonce         = os.urandom(12)

    # --- 1. AES-GCM Encryption ---
    print("--- 1. AES-GCM Encryption Overhead ---")
    def do_aes_enc():
        aesgcm = AESGCM(aes_key)
        n = os.urandom(12)
        return aesgcm.encrypt(n, plaintext, metadata_aad)
    encrypted_data, aes_enc_time = measure("AES-GCM Encrypt (1KB)", do_aes_enc)

    # --- 2. AES-GCM Decryption ---
    print("\n--- 2. AES-GCM Decryption Overhead ---")
    aesgcm_dec = AESGCM(aes_key)
    ct_for_dec = aesgcm_dec.encrypt(nonce, plaintext, metadata_aad)
    def do_aes_dec():
        a = AESGCM(aes_key)
        return a.decrypt(nonce, ct_for_dec, metadata_aad)
    _, aes_dec_time = measure("AES-GCM Decrypt (1KB)", do_aes_dec)

    # --- 3. RSA Key Wrapping ---
    print("\n--- 3. RSA Key Wrapping Overhead ---")
    def do_rsa_wrap():
        return cloud_pub.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    encrypted_key, rsa_wrap_time = measure("RSA-OAEP Wrap (16B key)", do_rsa_wrap)

    # --- 4. RSA Signing ---
    print("\n--- 4. RSA Digital Signing Overhead ---")
    sign_payload = encrypted_key + encrypted_data
    def do_rsa_sign():
        return camera_priv.sign(
            sign_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    signature, rsa_sign_time = measure("RSA-PSS Sign", do_rsa_sign)

    # --- 5. RSA Verification ---
    print("\n--- 5. RSA Signature Verification Overhead ---")
    cam_pub_path = os.path.join(KEYS_DIR, "camera_public.pem")
    with open(cam_pub_path, "rb") as f:
        camera_pub = serialization.load_pem_public_key(f.read())
    def do_rsa_verify():
        camera_pub.verify(
            signature,
            sign_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    _, rsa_verify_time = measure("RSA-PSS Verify", do_rsa_verify)

    # --- 6. Communication Overhead ---
    print("\n--- 6. Communication Overhead ---")
    plaintext_size = len(plaintext) + len(metadata_aad)
    packet = {
        "encrypted_key":  base64.b64encode(encrypted_key).decode(),
        "encrypted_data": base64.b64encode(encrypted_data).decode(),
        "signature":      base64.b64encode(signature).decode(),
        "nonce":          base64.b64encode(nonce).decode(),
        "metadata_aad":   base64.b64encode(metadata_aad).decode(),
    }
    packet_size = len(json.dumps(packet).encode())
    overhead_ratio = packet_size / plaintext_size
    print(f"  Plaintext size        : {plaintext_size} bytes")
    print(f"  Encrypted packet size : {packet_size} bytes")
    print(f"  Overhead ratio        : {overhead_ratio:.2f}x")
    print(f"  Overhead increase     : {((overhead_ratio - 1) * 100):.1f}%")

    # --- 7. End-to-End Throughput ---
    print("\n--- 7. End-to-End Throughput ---")
    total_time_per_event = aes_enc_time + rsa_wrap_time + rsa_sign_time  # ms
    events_per_sec = 1000.0 / total_time_per_event if total_time_per_event > 0 else 0
    print(f"  Total crypto time/event : {total_time_per_event:.3f} ms")
    print(f"  Theoretical throughput  : {events_per_sec:.1f} events/sec")

    # --- 8. Risk Window ---
    print("\n--- 8. Risk Window Analysis ---")
    risk_window = ROTATION_INTERVAL / N_KEYS
    print(f"  Rotation Interval     : {ROTATION_INTERVAL}s")
    print(f"  Keys per Set          : {N_KEYS}")
    print(f"  Risk Window per Key   : {risk_window:.1f}s")

    # --- Summary Table ---
    print("\n" + "=" * 60)
    print("  SUMMARY TABLE (for paper)")
    print("=" * 60)
    print(f"  {'Metric':<35} {'Value':>15}")
    print(f"  {'-'*35} {'-'*15}")
    print(f"  {'AES-GCM Encrypt (1KB)':<35} {aes_enc_time:>12.3f} ms")
    print(f"  {'AES-GCM Decrypt (1KB)':<35} {aes_dec_time:>12.3f} ms")
    print(f"  {'RSA-OAEP Key Wrap':<35} {rsa_wrap_time:>12.3f} ms")
    print(f"  {'RSA-PSS Sign':<35} {rsa_sign_time:>12.3f} ms")
    print(f"  {'RSA-PSS Verify':<35} {rsa_verify_time:>12.3f} ms")
    print(f"  {'Communication Overhead':<35} {overhead_ratio:>11.2f}x")
    print(f"  {'Throughput':<35} {events_per_sec:>8.1f} evt/s")
    print(f"  {'Risk Window':<35} {risk_window:>10.1f} s")
    print("=" * 60)

if __name__ == "__main__":
    main()
