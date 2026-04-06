"""
Camera Service — Policy-Enforced Context-Bound Cryptographic Specialization
with Deterministic N-Key Lifecycle Management

Structural Components:
  1. ManagedKey — Key with lifecycle metadata (key_id, created_at, expires_at)
  2. KeyManager — Multi-class N-key lifecycle (Active → Grace → Revoked)
  3. CRYPTO_POLICY — Formal policy manifest binding context to crypto
  4. build_signed_payload — Canonicalized JSON with ciphertext_hash
  5. Context Classifier — Derives security context from sensor data
"""
import os, time, json, uuid, socket, hashlib
import shutil
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# === Load Keys ===
camera_rsa_private = serialization.load_pem_private_key(
    open("/keys/camera_private.pem", "rb").read(), password=None
)
camera_ed_private = serialization.load_pem_private_key(
    open("/keys/camera_ed_private.pem", "rb").read(), password=None
)
cloud_rsa_public = serialization.load_pem_public_key(
    open("/keys/cloud_public.pem", "rb").read()
)


# ============================================================
# CRYPTO POLICY MANIFEST
# Formally binds context → encryption + signature + key class
# Shared between Camera and Gateway (deterministic, not random)
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
# MANAGED KEY — Key with lifecycle metadata
# ============================================================
class ManagedKey:
    def __init__(self, key_id, key, key_class, created_at, expires_at):
        self.key_id = key_id
        self.key = key
        self.key_class = key_class
        self.created_at = created_at
        self.expires_at = expires_at

    @property
    def is_active(self):
        return time.time() < self.expires_at

    def is_valid_for_decryption(self, grace_period=300):
        return time.time() < (self.expires_at + grace_period)


# ============================================================
# KEY MANAGER — Multi-Class N-Key Lifecycle
# Stages: Active → Grace → Revoked
# K1: 5x AES-128 (alerts)
# K2: 5x AES-256 (images)
# K3: 5x AES-256 (critical)
# ============================================================
class KeyManager:
    KEY_SIZES = {"K1": 16, "K2": 32, "K3": 32}

    def __init__(self, n=5, interval=60):
        self.N = n
        self.interval = interval
        self.rotation_id = 0
        self.key_sets = {"K1": [], "K2": [], "K3": []}
        self.indices = {"K1": 0, "K2": 0, "K3": 0}
        self._generate_key_set()

    def _generate_key_set(self):
        now = time.time()
        expires = now + self.interval

        for kc in self.key_sets:
            self.key_sets[kc] = []
            for i in range(self.N):
                key_id = f"{kc}_R{self.rotation_id}_I{i}"
                key = os.urandom(self.KEY_SIZES[kc])
                self.key_sets[kc].append(
                    ManagedKey(key_id, key, kc, now, expires)
                )
            self.indices[kc] = 0

    def get_key(self, key_class):
        keys = self.key_sets[key_class]
        idx = self.indices[key_class]
        managed_key = keys[idx]
        self.indices[key_class] = (idx + 1) % self.N
        return managed_key

    def rotate_if_needed(self):
        sample = self.key_sets["K1"][0]
        if time.time() > sample.expires_at:
            old_sets = {kc: list(keys) for kc, keys in self.key_sets.items()}
            self.rotation_id += 1
            self._generate_key_set()
            return old_sets
        return None

    def update_interval(self, new_interval, force_rotate=False):
        """Update key rotation interval and optionally force immediate rotation."""
        if new_interval <= 0:
            return False

        changed = new_interval != self.interval
        self.interval = new_interval

        if force_rotate:
            for keys in self.key_sets.values():
                for mk in keys:
                    mk.expires_at = time.time() - 1
            return changed

        # Apply tighter interval bound to currently active key windows.
        now = time.time()
        max_exp = now + self.interval
        for keys in self.key_sets.values():
            for mk in keys:
                if mk.expires_at > max_exp:
                    mk.expires_at = max_exp
        return changed

    def cleanup_expired(self):
        """Remove keys past grace period (called by archive flow)."""
        pass  # Old keys are archived then discarded


# ============================================================
# CONTEXT CLASSIFIER
# Derives context from motion sensor data
# ============================================================
def classify_context(motion_score=0):
    if motion_score > 3000000:
        return "CRITICAL_EVENT"
    else:
        return "HIGH_VALUE_IMAGE"


# ============================================================
# CANONICALIZED SIGNATURE PAYLOAD
# Signs structured JSON with ciphertext_hash (not raw bytes)
# Provides: deterministic verification + anti-downgrade
# ============================================================
def build_signed_payload(header, ciphertext):
    """Build canonicalized JSON payload for signing/verification."""
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


def sign_payload(policy, payload):
    """Sign using context-appropriate scheme."""
    if policy["signature"] == "Ed25519":
        return camera_ed_private.sign(payload)
    else:  # RSA-PSS
        return camera_rsa_private.sign(
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
def send_packet(host, port, data, retries=5):
    for attempt in range(retries):
        try:
            s = socket.socket()
            s.settimeout(10)
            s.connect((host, port))
            s.sendall(data)
            s.close()
            return True
        except Exception as e:
            print(f"  Retry {attempt+1}/{retries}: {e}")
            time.sleep(2)
    return False


def archive_keys(old_sets, rotation_id):
    """Encrypt and archive old key sets using hybrid AES+RSA."""
    try:
        archive_data = {
            "rotation_id": rotation_id,
            "archived_at": time.time(),
            "key_classes": {}
        }
        for kc, keys in old_sets.items():
            archive_data["key_classes"][kc] = [
                {
                    "key_id": mk.key_id,
                    "key": mk.key.hex(),
                    "created_at": mk.created_at,
                    "expires_at": mk.expires_at
                } for mk in keys
            ]

        raw = json.dumps(archive_data).encode()

        # Hybrid encrypt: AES-GCM for data, RSA-OAEP for key
        temp_key = os.urandom(32)
        temp_aes = AESGCM(temp_key)
        temp_nonce = os.urandom(12)
        encrypted = temp_aes.encrypt(temp_nonce, raw, None)

        wrapped = cloud_rsa_public.encrypt(
            temp_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        packet = json.dumps({
            "type": "key_archive",
            "rotation_id": rotation_id,
            "wrapped_key": wrapped.hex(),
            "nonce": temp_nonce.hex(),
            "encrypted_data": encrypted.hex()
        }).encode()

        send_packet("cloud", 6000, packet, retries=2)
        print(f"  Archive #{rotation_id} encrypted & sent (K1/K2/K3 lifecycle data)")
    except Exception as e:
        print(f"  Archive error: {e}")


# ============================================================
# MAIN — Camera Service
# ============================================================
print("Camera Service Starting - Waiting for Gateway...")
time.sleep(5)

os.makedirs("/shared/raw", exist_ok=True)
os.makedirs("/shared/frames", exist_ok=True)
os.makedirs("/shared/metadata", exist_ok=True)
os.makedirs("/shared/control", exist_ok=True)
os.makedirs("/shared/raw/processed", exist_ok=True)
os.makedirs("/shared/metadata/processed", exist_ok=True)

key_mgr = KeyManager(n=5, interval=60)
last_heartbeat = time.time()
policy_path = "/shared/control/encryption_policy.json"
last_policy_mtime = 0.0


def apply_adaptive_policy():
    global last_policy_mtime

    if not os.path.exists(policy_path):
        return

    try:
        mtime = os.path.getmtime(policy_path)
        if mtime <= last_policy_mtime:
            return

        with open(policy_path, "r", encoding="utf-8") as f:
            policy = json.load(f)

        recommended = int(policy.get("recommended_rotation_interval", key_mgr.interval))
        # Keep interval inside safe system bounds.
        recommended = max(10, min(60, recommended))
        risk = str(policy.get("risk", "MEDIUM")).upper()

        old_interval = key_mgr.interval
        force_rotate = recommended < old_interval
        changed = key_mgr.update_interval(recommended, force_rotate=force_rotate)

        if changed:
            print(
                f"🔐 Adaptive encryption policy applied | risk:{risk} "
                f"interval:{old_interval}s→{recommended}s"
            )

        last_policy_mtime = mtime
    except Exception as e:
        print(f"Adaptive policy read error: {e}")

print("=" * 60)
print("Policy-Enforced Context-Bound Crypto Engine v2")
print(f"Contexts: {list(CRYPTO_POLICY.keys())}")
print(f"Key lifecycle: Active({key_mgr.interval}s) → Grace(300s) → Revoked")
print(f"N-keys: {key_mgr.N}/class | Classes: K1(128b), K2(256b), K3(256b)")
print(f"Policy version: {CRYPTO_POLICY['LOW_LATENCY_ALERT']['policy_version']}")
print("=" * 60)

while True:
    apply_adaptive_policy()

    # === Key Lifecycle Check ===
    old_sets = key_mgr.rotate_if_needed()
    if old_sets:
        print(f"\n🔄 Rotation #{key_mgr.rotation_id} — All key classes refreshed")
        archive_keys(old_sets, key_mgr.rotation_id - 1)

    # === Process Frames ===
    try:
        raw_files = sorted([f for f in os.listdir("/shared/raw") if f.endswith(".jpg")])
    except FileNotFoundError:
        raw_files = []

    for file in raw_files:
        raw_path = f"/shared/raw/{file}"
        meta_path = raw_path.replace(".jpg", ".meta")

        try:
            with open(raw_path, "rb") as f:
                data = f.read()
            if len(data) == 0:
                continue
        except (PermissionError, FileNotFoundError):
            continue

        # Read motion metadata
        motion_score = 0
        if os.path.exists(meta_path):
            try:
                with open(meta_path) as f:
                    meta = json.load(f)
                motion_score = meta.get("motion_score", 0)
            except:
                pass

        # === Context Classification ===
        context = classify_context(motion_score)
        policy = CRYPTO_POLICY[context]

        # === Crypto Orchestration ===
        managed_key = key_mgr.get_key(policy["key_class"])

        start_enc = time.time()

        # Encrypt
        aes = AESGCM(managed_key.key)
        nonce = os.urandom(12)
        ciphertext = aes.encrypt(nonce, data, None)

        # Wrap AES key
        encrypted_key = cloud_rsa_public.encrypt(
            managed_key.key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        timestamp = time.time()

        # Build structured header
        header = {
            "packet_id": str(uuid.uuid4()),
            "context": context,
            "policy_version": policy["policy_version"],
            "algorithm": policy["encryption"],
            "signature_scheme": policy["signature"],
            "key_id": managed_key.key_id,
            "key_class": policy["key_class"],
            "rotation_id": key_mgr.rotation_id,
            "timestamp": timestamp,
            "nonce": nonce.hex(),
            "filename": file
        }

        # Sign canonicalized payload (includes ciphertext_hash)
        payload = build_signed_payload(header, ciphertext)
        signature = sign_payload(policy, payload)

        end_enc = time.time()
        enc_time = (end_enc - start_enc) * 1000

        ctx_icon = "🔴" if context == "CRITICAL_EVENT" else "🟢"
        print(f"[{ctx_icon} {context}] {enc_time:.2f}ms | {file} | {policy['encryption']}+{policy['signature']} | key:{managed_key.key_id} | {len(data)}B→{len(ciphertext)}B")

        # Save encrypted file
        enc_filename = file.replace(".jpg", ".jpg.enc")
        with open(f"/shared/frames/{enc_filename}", "wb") as ef:
            ef.write(ciphertext)

        # Build structured packet
        packet = {
            "header": header,
            "encrypted_key": encrypted_key.hex(),
            "ciphertext": ciphertext.hex(),
            "signature": signature.hex()
        }

        msg = json.dumps(packet).encode()
        if send_packet("gateway", 5000, msg):
            print(f"  → Sent (pid:{header['packet_id'][:8]}...)")
            try:
                shutil.move(raw_path, f"/shared/raw/processed/{file}")
                if os.path.exists(meta_path):
                    meta_file = os.path.basename(meta_path)
                    shutil.move(meta_path, f"/shared/raw/processed/{meta_file}")
            except FileNotFoundError:
                pass
        else:
            print(f"  ✗ FAILED: {file}")

    # === Process Metadata Events ===
    try:
        metadata_files = sorted([f for f in os.listdir("/shared/metadata") if f.endswith(".txt")])
    except FileNotFoundError:
        metadata_files = []

    for file in metadata_files:
        meta_path = f"/shared/metadata/{file}"

        try:
            with open(meta_path, "rb") as f:
                data = f.read()
            if len(data) == 0:
                continue
        except (PermissionError, FileNotFoundError):
            continue

        context = "HIGH_VALUE_IMAGE"
        policy = CRYPTO_POLICY[context]
        managed_key = key_mgr.get_key(policy["key_class"])

        start_enc = time.time()

        aes = AESGCM(managed_key.key)
        nonce = os.urandom(12)
        ciphertext = aes.encrypt(nonce, data, None)

        encrypted_key = cloud_rsa_public.encrypt(
            managed_key.key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        timestamp = time.time()
        header = {
            "packet_id": str(uuid.uuid4()),
            "context": context,
            "policy_version": policy["policy_version"],
            "algorithm": policy["encryption"],
            "signature_scheme": policy["signature"],
            "key_id": managed_key.key_id,
            "key_class": policy["key_class"],
            "rotation_id": key_mgr.rotation_id,
            "timestamp": timestamp,
            "nonce": nonce.hex(),
            "filename": file
        }

        payload = build_signed_payload(header, ciphertext)
        signature = sign_payload(policy, payload)

        end_enc = time.time()
        enc_time = (end_enc - start_enc) * 1000

        print(f"[🔵 EVENT] {enc_time:.2f}ms | {file} | {policy['encryption']}+{policy['signature']} | key:{managed_key.key_id} | {len(data)}B→{len(ciphertext)}B")

        packet = {
            "header": header,
            "encrypted_key": encrypted_key.hex(),
            "ciphertext": ciphertext.hex(),
            "signature": signature.hex()
        }

        msg = json.dumps(packet).encode()
        if send_packet("gateway", 5000, msg):
            print(f"  → Event sent (pid:{header['packet_id'][:8]}...)")
            try:
                shutil.move(meta_path, f"/shared/metadata/processed/{file}")
            except FileNotFoundError:
                pass
        else:
            print(f"  ✗ FAILED EVENT: {file}")

    # === Periodic Heartbeat (LOW_LATENCY_ALERT) ===
    if time.time() - last_heartbeat > 15:
        context = "LOW_LATENCY_ALERT"
        policy = CRYPTO_POLICY[context]

        alert_data = json.dumps({
            "type": "heartbeat",
            "sensor_id": "CAM-001",
            "status": "online",
            "rotation_id": key_mgr.rotation_id,
            "timestamp": time.time()
        }).encode()

        managed_key = key_mgr.get_key(policy["key_class"])

        start_enc = time.time()
        aes = AESGCM(managed_key.key)
        nonce = os.urandom(12)
        ciphertext = aes.encrypt(nonce, alert_data, None)

        encrypted_key = cloud_rsa_public.encrypt(
            managed_key.key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        timestamp = time.time()
        header = {
            "packet_id": str(uuid.uuid4()),
            "context": context,
            "policy_version": policy["policy_version"],
            "algorithm": policy["encryption"],
            "signature_scheme": policy["signature"],
            "key_id": managed_key.key_id,
            "key_class": policy["key_class"],
            "rotation_id": key_mgr.rotation_id,
            "timestamp": timestamp,
            "nonce": nonce.hex(),
            "filename": "heartbeat.alert"
        }

        payload = build_signed_payload(header, ciphertext)
        signature = sign_payload(policy, payload)
        end_enc = time.time()
        enc_time = (end_enc - start_enc) * 1000

        print(f"[🟡 ALERT] {enc_time:.2f}ms | heartbeat | {policy['encryption']}+{policy['signature']} | key:{managed_key.key_id} | {len(alert_data)}B→{len(ciphertext)}B")

        packet = {
            "header": header,
            "encrypted_key": encrypted_key.hex(),
            "ciphertext": ciphertext.hex(),
            "signature": signature.hex()
        }

        msg = json.dumps(packet).encode()
        if send_packet("gateway", 5000, msg):
            print(f"  → Heartbeat sent (pid:{header['packet_id'][:8]}...)")

        last_heartbeat = time.time()

    time.sleep(1)
