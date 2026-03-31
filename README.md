Secure Smart Surveillance: A Context-Derived Cryptographic Specialization Framework with N-Key Rotation for IoT-Based CCTV Systems
---
Abstract
The proliferation of Internet of Things (IoT)-based surveillance systems has introduced critical security challenges, including unauthorized data access, replay attacks, and key compromise. This paper presents a context-derived cryptographic specialization framework for securing CCTV data transmission across an IoT pipeline. Unlike traditional approaches that apply uniform encryption, the proposed system classifies each event into one of three security contexts — LOW_LATENCY_ALERT, HIGH_VALUE_IMAGE, or CRITICAL_EVENT — and selects the optimal combination of encryption algorithm, signing method, and key class accordingly. The architecture employs a three-tier model — Camera (IoT device), Gateway (Edge verifier), and Cloud (Central server) — deployed as Docker containers to simulate real-world IoT constraints. The framework integrates AES-127/256-GCM for symmetric encryption, RSA-2048-OAEP for asymmetric key exchange, Ed25519 for lightweight digital signatures, RSA-PSS for high-assurance signatures, and a novel multi-class N-Key rotation mechanism (K1/K2/K3) with per-context key isolation. Experimental evaluation demonstrates an average encryption latency of 2.15 ms per frame (~76 KB) with only 16 bytes of ciphertext overhead, confirming suitability for real-time surveillance. Security analysis confirms resilience against eavesdropping, tampering, replay, impersonation, and cryptographic downgrade attacks.
Keywords: Context-Aware Cryptography, IoT Security, CCTV Encryption, N-Key Rotation, AES-GCM, RSA-OAEP, Ed25519, RSA-PSS, Cryptographic Specialization, Docker, Edge Computing
---
1. Introduction
1.1 Background
Smart surveillance systems have become integral to urban security infrastructure, with an estimated 1 billion CCTV cameras deployed globally. The convergence of IoT and cloud computing enables remote monitoring, but introduces significant attack surfaces. Traditional CCTV systems transmit data in plaintext or apply uniform encryption, ignoring the varying sensitivity of different event types.
1.2 Problem Statement
Existing IoT surveillance solutions face four fundamental challenges:
One-size-fits-all encryption: Applying identical cryptographic treatment to low-priority alerts and high-value forensic images wastes resources and fails to optimize security.
Data Confidentiality: Video streams transmitted between cameras and cloud servers are vulnerable to interception and unauthorized viewing.
Data Integrity: Without cryptographic authentication, adversaries can inject, modify, or replay surveillance data.
Key Management: Static encryption keys create a single point of failure; if compromised, all historical and future data is exposed.
1.3 Core Innovation: Context-Derived Cryptographic Specialization
Instead of applying uniform cryptographic treatment, our system implements formal policy-bound contextual crypto specialization:
Context	Encryption	Signing	Key Class	Use Case
LOW_LATENCY_ALERT	AES-128-GCM	Ed25519	K1	Heartbeats, status alerts
HIGH_VALUE_IMAGE	AES-256-GCM	Ed25519	K2	Normal surveillance frames
CRITICAL_EVENT	AES-256-GCM	RSA-PSS	K3	High-motion critical events
This is not random algorithm switching (which would be insecure). Each context maps to a formally defined, immutable crypto policy. Context-bound signatures prevent downgrade attacks.
1.4 Contributions
Context-Derived Crypto Policy: A formal policy table mapping event contexts to specific encryption algorithms, signing methods, and key classes.
Multi-Class N-Key Rotation: A key manager maintaining three isolated key classes (K1/K2/K3) with 5 keys each, rotated every 60 seconds, providing per-context key isolation.
Dual Signature Architecture: Ed25519 for lightweight alert/image authentication; RSA-PSS for high-assurance critical event signing.
Context-Bound Signatures: Signatures cover `context + policy_id + nonce + ciphertext + timestamp`, providing anti-downgrade and context-tampering protection.
Zero-Knowledge Gateway: An edge verification architecture where the Gateway authenticates packets without accessing plaintext data.
Replay Protection: Packet-level protection using UUID identifiers and ±30-second timestamp validation.
Encrypted Key Archives: Old key sets encrypted using hybrid AES+RSA before archival.
Practical Evaluation: Docker-based IoT simulation with real webcam input, demonstrating sub-3ms latency.
1.5 Paper Organization
Section 2 reviews related work. Section 3 describes the system architecture. Section 4 details the cryptographic design. Section 5 presents the threat model. Section 6 provides experimental evaluation. Section 7 discusses security analysis. Section 8 addresses limitations and future work. Section 9 concludes the paper.
---
2. Related Work
2.1 IoT Security Frameworks
Sicari et al. (2015) surveyed IoT security challenges, identifying confidentiality, authentication, and access control as primary concerns. Their work highlighted the computational constraints of IoT devices, which limit the applicability of heavyweight cryptographic protocols.
2.2 Symmetric Encryption for Surveillance
AES has been widely adopted for video encryption due to its efficiency. Sallam and Beheshti (2018) proposed selective AES encryption of video I-frames. However, their approach applies uniform encryption without considering event sensitivity.
2.3 Hybrid Cryptographic Approaches
Singh and Supriya (2013) proposed hybrid RSA-AES encryption for cloud data. Our work extends this by adding contextual crypto policy selection, dual signature schemes, and multi-class key management.
2.4 Key Rotation in IoT
Porambage et al. (2016) studied key management for resource-constrained IoT devices. Our multi-class N-Key rotation scheme advances this by maintaining three isolated key classes with context-specific rotation, providing finer-grained key compromise containment.
2.5 Context-Aware Security
Covington et al. (2002) pioneered context-aware security policies for pervasive computing. Our framework applies this concept to cryptographic algorithm selection, formalizing the mapping between sensor context and crypto policy.
2.6 Edge Computing Security
Shi et al. (2016) introduced edge computing for IoT. Our Gateway adopts this paradigm by performing context-aware signature verification at the edge without decryption.
2.7 Research Gap
No prior work combines context-derived cryptographic specialization, multi-class N-key rotation, dual signature schemes (Ed25519 + RSA-PSS), and anti-downgrade protection into a unified, practical framework for CCTV surveillance.
---
3. System Architecture
3.1 Overview
```
                        CONTEXT CLASSIFICATION
                               │
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
    LOW_LATENCY_ALERT   HIGH_VALUE_IMAGE    CRITICAL_EVENT
    AES-128-GCM         AES-256-GCM        AES-256-GCM
    Ed25519              Ed25519            RSA-PSS
    Key Class K1         Key Class K2       Key Class K3
            │                  │                  │
            └──────────────────┼──────────────────┘
                               ▼
                      CRYPTO ORCHESTRATOR
                               │
                               ▼
┌─────────┐    ┌─────────┐    ┌──────────┐
│ Camera  │───▶│ Gateway │───▶│  Cloud   │
│ Service │    │ Service │    │  Server  │
│         │    │         │    │          │
│ Encrypt │    │ Verify  │    │ Decrypt  │
│ Sign    │    │ Forward │    │ Store    │
└────┬────┘    └─────────┘    └────┬─────┘
     │                              │
shared/frames/               shared/decrypted/
(.jpg.enc files)             (.jpg files)
```
3.2 Component Descriptions
Camera Service (IoT Device Simulation):
Implements the Context Classifier, Crypto Orchestrator, and multi-class Key Manager.
Monitors shared volume for raw frames and their motion metadata.
Sends periodic heartbeat alerts (LOW_LATENCY_ALERT) every 15 seconds.
Classifies events: motion_score > 3M → CRITICAL_EVENT, else → HIGH_VALUE_IMAGE.
Gateway Service (Edge Verifier):
Zero-knowledge intermediary with dual signature verification.
Uses Ed25519 for alert/image verification, RSA-PSS for critical events.
Performs anti-downgrade validation against registered policy table.
Drops packets with invalid signatures or mismatched policies.
Cloud Service (Central Server):
Context-aware decryption: auto-detects AES-128/256 from key length.
Replay protection: duplicate packet_id rejection + 30s timestamp drift.
Decrypts and stores archived key sets for forensic recovery.
Reports per-context performance statistics.
3.3 Packet Structure
Field	Type	Purpose
`packet_id`	UUID v4	Unique identifier for replay detection
`timestamp`	float	Unix timestamp for freshness validation
`context`	string	Security context (LOW_LATENCY_ALERT / HIGH_VALUE_IMAGE / CRITICAL_EVENT)
`policy_id`	string	`encryption|signing|key_class|version` for anti-downgrade
`filename`	string	Original frame identifier
`rotation_id`	int	Current key rotation set identifier
`key_index`	int	Key index within the active set
`nonce`	hex	12-byte IV for AES-GCM (unique per packet)
`encrypted_key`	hex	AES key encrypted with RSA-OAEP
`encrypted_data`	hex	Frame data encrypted with AES-GCM
`signature`	hex	Context-bound signature (Ed25519 or RSA-PSS)
---
4. Cryptographic Design
4.1 Context-Derived Crypto Policy Table
The policy table formally maps each security context to specific cryptographic parameters:
```python
CRYPTO_POLICY = {
    "LOW_LATENCY_ALERT": {
        "encryption": "AES-128-GCM",
        "signing":    "Ed25519",
        "key_class":  "K1",
        "policy_version": "1.0"
    },
    "HIGH_VALUE_IMAGE": {
        "encryption": "AES-256-GCM",
        "signing":    "Ed25519",
        "key_class":  "K2",
        "policy_version": "1.0"
    },
    "CRITICAL_EVENT": {
        "encryption": "AES-256-GCM",
        "signing":    "RSA-PSS",
        "key_class":  "K3",
        "policy_version": "1.0"
    }
}
```
Why this is NOT random algorithm switching:
Each context has a deterministic, immutable mapping to a specific crypto configuration.
The policy is signed into every packet, preventing substitution.
The Gateway validates the policy against a registered table, rejecting mismatches.
4.2 Multi-Class N-Key Rotation
```
Key Manager
├── K1: [k1_0, k1_1, k1_2, k1_3, k1_4]  ← AES-128 (alerts)
├── K2: [k2_0, k2_1, k2_2, k2_3, k2_4]  ← AES-256 (images)
└── K3: [k3_0, k3_1, k3_2, k3_3, k3_4]  ← AES-256 (critical)

Rotation: All classes rotate simultaneously every 60 seconds.
Selection: Round-robin within each class.
Archive: Old keys encrypted with AES+RSA hybrid before storage.
```
Key Isolation Property: Compromise of K1 keys does not affect K2 or K3. An attacker who compromises the alert key class cannot decrypt images or critical events.
4.3 AES-GCM Authenticated Encryption
Both AES-128-GCM and AES-256-GCM provide authenticated encryption:
Confidentiality: Counter-mode encryption.
Integrity: 16-byte Galois authentication tag.
IV Safety: `os.urandom(12)` generates a cryptographically secure 12-byte nonce for every operation — never reused.
4.4 RSA-2048-OAEP Key Wrapping
The AES session key (16 or 32 bytes) is encrypted using the Cloud's RSA-2048 public key with OAEP padding:
Only the Cloud (private key holder) can extract the AES key.
The Gateway cannot decrypt despite having network access.
4.5 Dual Signature Architecture
Ed25519 (Alerts + Images):
64-byte signatures.
~50μs signing time.
Optimal for high-throughput frame authentication.
RSA-PSS (Critical Events):
256-byte signatures.
~150μs signing time.
Maximum assurance, non-repudiation, legal admissibility.
4.6 Context-Bound Signatures
The signature covers a concatenation of context metadata and cryptographic material:
```
message = context ‖ policy_id ‖ nonce ‖ ciphertext ‖ timestamp
signature = Sign(message, signing_key)
```
Where `policy_id = "encryption|signing|key_class|version"`.
Security Properties:
Anti-downgrade: Changing the encryption algorithm invalidates the signature.
Context binding: Changing the context (e.g., CRITICAL → ALERT) invalidates the signature.
Freshness: Timestamp is signed, preventing replay with modified timestamps.
Cipher binding: Changing the ciphertext invalidates the signature.
4.7 Replay Protection
The Cloud validates every incoming packet against two criteria:
Duplicate Detection: UUID v4 `packet_id` checked against a `seen_packets` set.
Timestamp Validation: Packets with >30 second clock drift are rejected.
4.8 Encrypted Key Archive
When keys rotate, the old key set (K1/K2/K3) is archived using hybrid encryption:
A temporary AES-256 key is generated.
The key archive is encrypted with AES-GCM.
The temporary key is wrapped with RSA-OAEP.
Both are sent to the Cloud for forensic storage.
---
5. Threat Model
5.1 Adversary Capabilities
We consider an adversary who can:
Passively eavesdrop on all network traffic.
Actively inject, modify, or replay captured packets.
Compromise the Gateway (read-only access).
Attempt cryptographic downgrade attacks.
Attempt denial-of-service against any component.
5.2 Security Goals
Goal	Mechanism
Confidentiality	AES-128/256-GCM; only Cloud can decrypt
Integrity	AES-GCM auth tag + context-bound signature
Authentication	Ed25519/RSA-PSS signatures verify Camera identity
Freshness	Replay protection via packet_id + timestamp
Key Isolation	Per-context key classes (K1/K2/K3)
Anti-Downgrade	Policy_id signed into every packet
Archive Security	AES+RSA hybrid encrypted key archives
5.3 Attacks Addressed
Attack	Defense
Eavesdropping	AES-GCM renders intercepted data unintelligible
Man-in-the-Middle	Context-bound signature detects any modification
Replay Attack	Duplicate packet_id + timestamp drift rejection
Impersonation	Without Camera's Ed25519/RSA private key, valid signatures cannot be forged
Gateway Compromise	Zero-knowledge — Gateway has no decryption keys
Downgrade Attack	Policy_id validated against registered table at Gateway
Context Substitution	Context string is signed; changing it invalidates signature
Key Theft (current)	N-key rotation + per-class isolation limits exposure
---
6. Experimental Evaluation
6.1 Experimental Setup
Parameter	Value
Host OS	Windows 11
Container Runtime	Docker Desktop
Python Version	3.10 (slim)
Cryptography Library	Python `cryptography`
Camera Resolution	640×480 (VGA)
Frame Format	JPEG
Average Frame Size	~76 KB
RSA Key Size	2048 bits
AES Key Sizes	128 bits (K1), 256 bits (K2/K3)
Ed25519 Key Size	256 bits
N-Keys per Class	5
Key Classes	K1, K2, K3
Rotation Interval	60 seconds
6.2 Performance Results
Table 1: Per-Context Encryption Latency
Context	AES Variant	Signing	Mean (ms)	Min (ms)	Max (ms)
LOW_LATENCY_ALERT	AES-128-GCM	Ed25519	~0.35	0.25	0.50
HIGH_VALUE_IMAGE	AES-256-GCM	Ed25519	~2.15	1.57	3.67
CRITICAL_EVENT	AES-256-GCM	RSA-PSS	~2.45	1.80	4.26
Table 2: Cryptographic Operation Breakdown
Operation	Mean (ms)
AES-128-GCM Encrypt (~200B alert)	~0.05
AES-256-GCM Encrypt (~76KB image)	~1.72
RSA-OAEP Key Wrapping	~0.28
Ed25519 Signing	~0.05
RSA-PSS Signing	~0.15
Ed25519 Verification (Gateway)	~0.08
RSA-PSS Verification (Gateway)	~1.40
AES-GCM Decryption (Cloud)	~0.55
Table 3: Packet Size Analysis
Metric	Value
Average Raw Frame Size	76,382 bytes
Average Encrypted Frame Size	76,398 bytes
AES-GCM Overhead	16 bytes (0.02%)
RSA-Wrapped Key Size	256 bytes (fixed)
Ed25519 Signature Size	64 bytes
RSA-PSS Signature Size	256 bytes
Heartbeat Alert Size	~200 bytes
Table 4: Key Rotation Overhead
Metric	Value
Key Generation (3 classes × 5 keys)	< 1 ms
Archive Encryption (AES+RSA hybrid)	~0.6 ms
Archive Transmission	~2 ms
Total Rotation Overhead	~3.6 ms (one-time per 60s)
6.3 Context Distribution Analysis
In a typical 10-minute session:
LOW_LATENCY_ALERT: ~40 packets (heartbeats every 15s)
HIGH_VALUE_IMAGE: ~200-800 packets (motion-dependent)
CRITICAL_EVENT: ~5-20 packets (high-motion events only)
The context distribution validates the design: lightweight Ed25519 handles the majority of traffic (alerts + images), while heavyweight RSA-PSS is reserved for rare critical events.
6.4 Key Findings
Context-appropriate performance: Ed25519 signing (0.05ms) is 3× faster than RSA-PSS (0.15ms), validating the dual-signature design.
Negligible overhead: AES-GCM adds only 16 bytes per frame (0.02%).
Real-time feasible: Even CRITICAL_EVENT encryption (2.45ms) fits within the 33ms budget of 30 FPS video.
Key isolation verified: K1/K2/K3 classes operate independently; compromise of one does not affect others.
---
7. Security Analysis
7.1 Confidentiality
All data is encrypted with AES-GCM before leaving the Camera. LOW_LATENCY_ALERT uses AES-128 (2^128 keyspace) for lightweight alerts. HIGH_VALUE_IMAGE and CRITICAL_EVENT use AES-256 (2^256 keyspace) for maximum protection. Fresh 12-byte IVs ensure unique ciphertexts for identical plaintexts.
7.2 Integrity and Authentication
The dual-integrity mechanism (AES-GCM tag + context-bound signature) ensures:
Bit-level modification detection via GCM authentication tag.
Independent edge verification via Ed25519 or RSA-PSS.
Signature verification at the Gateway without decryption.
7.3 Anti-Downgrade Protection
The `policy_id` field (`encryption|signing|key_class|version`) is included in the signed message. An attacker attempting to downgrade from AES-256-GCM to AES-128-GCM, or from RSA-PSS to Ed25519, would invalidate the signature. The Gateway additionally validates the policy_id against a registered table of valid policies per context.
7.4 Context Binding
The context string is part of the signed message. An attacker who intercepts a CRITICAL_EVENT packet cannot re-label it as LOW_LATENCY_ALERT to bypass higher-assurance processing at the Cloud.
7.5 Replay Resistance
Validated experimentally: 93+ packets processed with unique UUID v4 identifiers. Resending a captured packet results in `REPLAY REJECTED (duplicate)`. The 30-second clock drift tolerance prevents stale packet injection.
7.6 Key Isolation
K1, K2, and K3 are cryptographically independent key classes. Compromise of K1 (alert keys) provides zero information about K2 or K3 keys. This property is maintained across rotation intervals.
---
8. Limitations and Future Work
8.1 Current Limitations
8.1.1 No Perfect Forward Secrecy (PFS)
RSA-based key wrapping does not provide true PFS. Compromise of the Cloud's long-term RSA private key exposes all historically wrapped AES keys.
Mitigation: Implement Ephemeral ECDH (ECDHE) for per-session key derivation.
8.1.2 Physical Camera Compromise
Physical access to the Camera during an active interval could expose current keys in memory.
Mitigation: Hardware Security Modules (HSM) or Trusted Platform Modules (TPM).
8.1.3 Static Context Policy
The context policy table is statically defined, not adaptive.
Future Work: Machine learning-based dynamic context classification.
8.1.4 Single Gateway Failure
A compromised Gateway can silently drop legitimate packets.
Mitigation: Redundant Gateways with Cloud-side heartbeat monitoring.
8.1.5 Metadata Leakage
Packet metadata (timestamps, context labels) is transmitted in plaintext.
Mitigation: Encrypted metadata fields and traffic padding.
8.2 Future Work
ECDHE Key Exchange: Per-session ephemeral keys for true Perfect Forward Secrecy.
Formal Verification: Dolev-Yao model-based security proofs.
Multi-Camera Scalability: Centralized key management for camera arrays.
Hardware Deployment: Raspberry Pi / ESP32-CAM resource measurements.
Blockchain Audit Trail: Tamper-evident immutable logging.
Adaptive Context ML: Neural network-based context classification.
TLS 1.3 Migration: Transport-layer security in addition to application-layer.
---
9. Conclusion
This paper presented a context-derived cryptographic specialization framework for securing IoT-based CCTV systems. The proposed system advances beyond uniform encryption by formally mapping event contexts to optimal cryptographic configurations — using AES-128-GCM with Ed25519 for lightweight alerts, AES-256-GCM with Ed25519 for standard images, and AES-256-GCM with RSA-PSS for critical events.
The multi-class N-key rotation mechanism (K1/K2/K3) provides per-context key isolation, ensuring that compromise of alert keys does not affect image or critical event keys. Context-bound signatures with anti-downgrade protection prevent adversaries from manipulating the applied cryptographic policy.
Experimental evaluation on a Docker-based IoT simulation with real webcam input confirmed sub-3ms encryption latency with negligible overhead, validating practical real-time feasibility. The zero-knowledge Gateway design and dual-signature architecture (Ed25519 + RSA-PSS) establish a robust, defense-in-depth security posture.
The framework demonstrates that context-aware cryptographic specialization under N-key rotation is not only theoretically sound but practically implementable, offering a strong foundation for next-generation secure surveillance systems.
---
References
Sicari, S., Rizzardi, A., Grieco, L. A., & Coen-Porisini, A. (2015). Security, privacy and trust in Internet of Things: The road ahead. Computer Networks, 76, 146-164.
Sallam, A. I., & Beheshti, E. (2018). Selective encryption of MPEG video streams in real-time using AES. Journal of Information Security, 9(3), 201-215.
Singh, S., & Supriya, M. (2013). A study of encryption algorithms (RSA, DES, 3DES and AES) for information security. International Journal of Computer Applications, 67(19), 33-38.
Porambage, P., et al. (2016). Two-phase authentication protocol for wireless sensor networks. IEEE Wireless Communications, 23(2), 24-30.
Covington, M. J., Long, W., Srinivasan, S., Dev, A. K., Ahamad, M., & Abowd, G. D. (2002). Securing context-aware applications using environment roles. ACM SACMAT.
Shi, W., Cao, J., Zhang, Q., Li, Y., & Xu, L. (2016). Edge computing: Vision and challenges. IEEE Internet of Things Journal, 3(5), 637-646.
Dworkin, M. J. (2007). Recommendation for block cipher modes of operation: GCM and GMAC. NIST SP 800-38D.
Bernstein, D. J., et al. (2012). High-speed high-security signatures. Journal of Cryptographic Engineering, 2(2), 77-89.
Barker, E. & Roginsky, A. (2019). Transitioning the use of cryptographic algorithms and key lengths. NIST SP 800-131A Rev. 2.
---
Appendix A: Project File Structure
```
secure-cctv/
├── docker-compose.yml          # Docker orchestration
├── generate_keys.py            # RSA + Ed25519 key pair generator
├── capture_host.py             # Host webcam + motion detection + .meta
├── display_host.py             # Decrypted stream viewer
├── run_simulation.ps1          # One-click launcher
├── camera/
│   ├── Dockerfile
│   └── camera.py               # Context classifier + crypto orchestrator
├── gateway/
│   ├── Dockerfile
│   └── gateway.py              # Dual Ed25519/RSA-PSS verification
├── cloud/
│   ├── Dockerfile
│   └── cloud.py                # Context-aware decryption + replay protection
├── keys/
│   ├── camera_private.pem      # RSA-2048 (CRITICAL signing)
│   ├── camera_public.pem       # RSA-2048 verification
│   ├── camera_ed_private.pem   # Ed25519 (ALERT/IMAGE signing)
│   ├── camera_ed_public.pem    # Ed25519 verification
│   ├── cloud_private.pem       # RSA-2048 (decryption)
│   └── cloud_public.pem        # RSA-2048 (key wrapping)
└── shared/
    ├── raw/                    # Raw webcam frames (temporary)
    ├── frames/                 # Encrypted frames (.jpg.enc)
    └── decrypted/              # Decrypted frames (.jpg)
```
Appendix B: Sample Execution Logs
```
camera-1  | Context-Aware Crypto Engine Active
camera-1  | Contexts: ['LOW_LATENCY_ALERT', 'HIGH_VALUE_IMAGE', 'CRITICAL_EVENT']
camera-1  | Key classes: K1(AES-128), K2(AES-256), K3(AES-256)
camera-1  |
camera-1  | [🟢 IMAGE] 2.13ms | frame_2.jpg | AES-256-GCM+Ed25519 | 76209B→76225B
camera-1  |   → Sent (pid:a3b8d1b6...)
gateway-1 | 🟢 VALID (0.08ms) | frame_2.jpg | Ed25519 | pid:a3b8d1b6...
gateway-1 |   → Forwarded to cloud
cloud-1   | 🟢 Decrypted: frame_2.jpg | 0.85ms | AES-256-GCM | 76225B→76209B
camera-1  |
camera-1  | [🟡 ALERT] 0.35ms | heartbeat | AES-128-GCM+Ed25519 | 142B→158B
gateway-1 | 🟡 VALID (0.06ms) | heartbeat.alert | Ed25519 | pid:f14eac78...
cloud-1   | 🟡 Alert: heartbeat | 0.12ms | AES-128-GCM
camera-1  |
camera-1  | [🔴 CRITICAL] 2.45ms | frame_83.jpg | AES-256-GCM+RSA-PSS | 76537B→76553B
gateway-1 | 🔴 VALID (1.38ms) | frame_83.jpg | RSA-PSS | pid:d7e2918c...
cloud-1   | 🔴 Decrypted: frame_83.jpg | 0.90ms | AES-256-GCM | 76553B→76537B
camera-1  |
camera-1  | 🔄 Keys rotated → Set #1 (K1/K2/K3 refreshed)
cloud-1   | 🔑 Key archive #0 decrypted & stored → key_archive/archive_1.json
```
