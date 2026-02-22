from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization
import os

os.makedirs("keys", exist_ok=True)

# === RSA-2048: Camera (signing CRITICAL_EVENT) ===
print("Generating Camera RSA-2048 keys...")
cam_rsa = rsa.generate_private_key(65537, 2048)
with open("keys/camera_private.pem", "wb") as f:
    f.write(cam_rsa.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))
with open("keys/camera_public.pem", "wb") as f:
    f.write(cam_rsa.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# === Ed25519: Camera (signing ALERT + IMAGE) ===
print("Generating Camera Ed25519 keys...")
cam_ed = ed25519.Ed25519PrivateKey.generate()
with open("keys/camera_ed_private.pem", "wb") as f:
    f.write(cam_ed.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))
with open("keys/camera_ed_public.pem", "wb") as f:
    f.write(cam_ed.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# === RSA-2048: Cloud (decryption + key unwrapping) ===
print("Generating Cloud RSA-2048 keys...")
cloud_rsa = rsa.generate_private_key(65537, 2048)
with open("keys/cloud_private.pem", "wb") as f:
    f.write(cloud_rsa.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))
with open("keys/cloud_public.pem", "wb") as f:
    f.write(cloud_rsa.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("\nKeys generated:")
for f in sorted(os.listdir("keys")):
    print(f"  keys/{f}")
print("\nKey purposes:")
print("  camera_private.pem   → RSA-PSS signing (CRITICAL_EVENT)")
print("  camera_public.pem    → RSA-PSS verification (Gateway)")
print("  camera_ed_private.pem → Ed25519 signing (ALERT + IMAGE)")
print("  camera_ed_public.pem  → Ed25519 verification (Gateway)")
print("  cloud_private.pem    → RSA-OAEP decryption (Cloud)")
print("  cloud_public.pem     → RSA-OAEP encryption (Camera)")
