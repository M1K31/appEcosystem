# Privacy Policy

**Product**: appEcosystem (Unified Security & AI Control Plane)  
**Maintainer**: Smart Industries LLC (Mikel Smart)  
**Effective Date**: November 2026  

---

## 1. Core Architecture: Local-First & Zero-Telemetry

`appEcosystem` is engineered from the ground up on a **local-first, privacy-by-design** architecture. It acts as the local service registry, event bus, capability coordinator, and security policy control plane for home and enterprise security appliances.

- **Zero Phone-Home / Zero Phoning Beacons**: `appEcosystem` contains no external tracking, usage analytics, advertising beacons, or telemetry collectors.
- **Local Storage by Default**: All registry state, device enrollments, capability manifests, security policies, and audit logs are persisted exclusively on local storage within your filesystem (`~/.local/share/ecosystem/` or `/var/lib/ecosystem/`).
- **Encrypted Local Credentials**: HMAC shared secrets, device private keys, and TOTP seeds are stored with restrictive filesystem permissions (`0600` / `0700`) accessible only by the service owner.

---

## 2. Forensic Scan Data & Endpoint Sweeps

Forensic endpoint auditing and spyware scanning (powered by the Zero Breach Toolkit integration) adhere to strict privacy safeguards:

1. **Encrypted Full Reports at Rest**: Detailed scan artifacts (`full.json`) containing private filesystem paths, installed packages, process trees, or system configuration metadata are immediately encrypted using AES-256-GCM prior to being written to storage. Encryption keys are generated locally with POSIX `0600` permissions (`~/.local/share/ecosystem/keystore/scan_enc.key`). Plaintext temporary scan files are securely purged.
2. **Redacted Event Bus Summaries**: Only high-level, sanitized metadata (`share.json`) is published to the local ecosystem event bus (`scan.completed`). Sanitized summaries contain only high-level risk categories, finding counts, and detection timestamps—**zero** private system paths, file names, or indicator details are exposed across the local mesh.
3. **Cryptographic Consent Binding**: Scanning requires explicit owner consent via an Acceptable Use Policy (AUP) acknowledgment. Consent is bound cryptographically to the device's public key fingerprint (Ed25519). A dynamic IP reallocation (DHCP churn) can **never** transfer scanning consent to another device.
4. **Step-Up Authorization for Raw Detections**: Viewing or exporting the full unredacted scan report requires administrative step-up authentication (time-based one-time password / TOTP).

---

## 3. Voice Processing & Microphone Audio

The local voice subsystem (`ecosystem-voice`):

1. **Local-Only Transcriptions**: Speech-to-text inference runs strictly on-device utilizing optimized local models (`whisper.cpp` / `faster-whisper`). Raw audio is never transmitted to cloud transcription APIs.
2. **Zero Audio Retention Invariant**: Raw PCM audio buffers are transcribed directly in volatile system memory and immediately scrubbed/zeroed out upon completion. No audio recordings, temporary wave files, or audio buffers are ever persisted to disk.
3. **Privilege Boundary**: Voice recognition operates under a strict principle of least privilege. Voice commands may trigger emergency containment (`ecosystem.freeze` kill-switch) or request authorized automated scans, but voice intents can **never** approve security checkpoints, lower policy restrictions, or resume normal operations from a freeze state.

---

## 4. Notifications & Alert Routing

The `NotificationRouter`:

1. **Local Mesh Routing**: By default, notifications are routed directly over the local network via WebSockets, Server-Sent Events, or native platform IPC (macOS Notification Center / Linux Desktop notifications).
2. **External Mobile Delivery (Optional)**: If configured with an external push service (e.g. self-hosted `ntfy` server, Apple Push Notification service, or Firebase Cloud Messaging), notification payloads are limited to event titles, severity levels, and coarse category tags. Credential tokens, detailed threat payloads, and raw data are never sent in notification pushes.
3. **Local Deduplication & Rate Limiting**: Event deduplication keys and cooldown trackers are maintained in local memory to prevent spam while protecting event history privacy.

---

## 5. Cloud Compute & AI Processing

The multi-provider Compute Broker (`ecosystem-compute`):

1. **Cloud Disabled by Default**: All cloud compute providers (RunPod, SkyPilot, OpenAI-compatible APIs) are explicitly disabled out of the box (`enabled: false`). Local hardware (Apple Metal, NVIDIA CUDA, Intel/AMD ROCm) and LAN peer nodes are prioritized.
2. **Sensitive Data Egress Gate**: Jobs containing data tagged as `classification: sensitive` are blocked from cloud execution at the policy level. Dispatching sensitive workloads to cloud providers requires an explicit, cryptographically signed `data_release` policy grant.
3. **Hard Budget Enforcement**: The broker enforces hard spend limits (`monthly_usd` and `per_job_usd`). When cloud spend caps are reached, execution automatically fails closed or degrades to local CPU/GPU fallback rather than incurring unplanned cloud billing.

---

## 6. Data Subject Rights & Deletion (GDPR / CCPA)

You retain absolute ownership of all ecosystem records:

- **Reviewing Stored Data**: Inspect enrolled devices, policy audit logs, and scan history via the `ecosystem` CLI or the HIG Control Plane dashboard.
- **Purging Data**: To permanently delete all stored ecosystem data, keys, scan logs, and policy state:
  ```bash
  ecosystem stop-all
  rm -rf ~/.local/share/ecosystem/
  rm -rf ~/.config/ecosystem/
  ```

---

## 7. Disclosures & Inquiries

For security advisories, vulnerability disclosures, or privacy questions regarding `appEcosystem`, contact:

**Smart Industries LLC**  
Mikel Smart  
Website / GitHub: [github.com/M1K31](https://github.com/M1K31)

