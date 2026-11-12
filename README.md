# Unified Security & AI Ecosystem (appEcosystem)

A robust, **local-first, privacy-by-design** ecosystem combining AI, computer vision surveillance, intrusion detection, automated forensic scanning, and ambient smart displays into a resilient unified mesh.

`appEcosystem` provides the **control plane**: a service registry, event bus, cryptographic policy engine, capability coordinator, hardware-adaptive compute broker, and shared Apple Human Interface Guidelines (HIG) web components—while ensuring every app continues to operate **independently** when disconnected.

---

## 1. System Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    HIG Control Plane UI & Web Components                    │
│      @appecosystem/ui-controls (Policy Toggle, Approvals, Freeze, Status)   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                     appEcosystem Control Plane Registry                     │
│  • Service Discovery & mDNS        • Canonical Event Bus (Draft 2020-12)    │
│  • PolicyEngine & Step-Up Auth     • CapabilityRegistry & NotificationRouter│
│  • ScanRunner & Scheduler (ZBT)    • ComputeBroker & GPU Doctor             │
└───────┬──────────────┬───────────────┬────────────────┬──────────────┬──────┘
        │              │               │                │              │
        ▼              ▼               ▼                ▼              ▼
┌──────────────┐┌──────────────┐┌──────────────┐┌──────────────┐┌──────────────┐
│   AegisSIEM  ││ cyber-agents ││AI-for-Surv.  ││   OpenEye    ││ MagicMirror³ │
│ Router Syslog││Autonomous SOC││Offline LLM & ││ComputerVision││ Ambient Wall │
│  & Threat C2 ││Triage & Resp.││ RAG Assistant││ Surveillance ││   Display    │
└──────────────┘└──────────────┘└──────────────┘└──────────────┘└──────────────┘
```

### Connected Projects & Repositories

| Repository | Primary Role | License | Fail-Closed Standalone Behavior |
| :--- | :--- | :--- | :--- |
| **`appEcosystem`** | Control plane, registry, policy engine, compute broker | MIT | Independent local daemon; zero cloud dependencies |
| **`AegisSIEM`** | Network perimeter defense, router syslog & threat intelligence | MIT | Full local logging, Sigma rules & router SSH defense |
| **`cyber-agents`** | Autonomous security analyst daemon & response pipeline | MIT | Local rule engine & provisional containment |
| **`AI-for-Survival`** | Offline knowledge base, survival assistant & local RAG | MIT | Local SQLite RAG & native Ollama inference |
| **`OpenEye-OpenCV_Home_Security`** | Video surveillance, face recognition & smart home rules | MIT | Local RTSP streams, OpenCV processing & alerts |
| **`MagicMirror-Custom`** | Ambient wall display & smart home status dashboard | MIT | Ambient metrics; emergency freeze trigger only |
| **`Zero-Breach-Toolkit`** | Endpoint forensic auditor & spyware detection engine | Apache-2.0 | Full local CLI scan; reports encrypted at rest |
| **`Heritic`** | AI representation engineering & model steering | AGPL-3.0 | Non-interactive training; isolated subprocess |
| **`model-forge`** | Hardware tier model distillation & GGUF packaging | AGPL-3.0 | Standalone CLI; signs Ed25519 model manifests |
| **`openeye-packaging`** | Multi-profile distribution & CycloneDX SBOM packager | Private | Standalone, embedded, hub, and edge profiles |

---

## 2. Shared Packages

All shared ecosystem modules are modular, path-installed, and decoupled:

- **`ecosystem-policy`** (`packages/ecosystem-policy`): Cryptographic Ed25519-signed policy state with four action classes (`observe`, `investigate`, `contain`, `remediate`, `data_release`, `system_change`), step-up TOTP verification, provisional containment with automated TTL rollback, and the emergency kill-switch (`ecosystem.freeze`).
- **`ecosystem_auth`** (`auth/python`): HMAC-SHA256 replay-resistant request signing (timestamp, nonce, and payload digest) and fail-closed key derivation.
- **`ecosystem_client`** (`ecosystem_client/` & `ecosystem_client_js/`): Discovery cascade (Registry → mDNS → Static → Standalone), heartbeat registration, and canonical event pub/sub.
- **`ecosystem-compute`** (`packages/ecosystem-compute`): Multi-provider compute broker (Local Metal/CUDA, LAN peer nodes, RunPod, SkyPilot, OpenAI API) with cloud disabled by default, hard budget enforcement (`monthly_usd`), and a sensitive data egress gate. Includes the `ecosystem doctor gpu` diagnostics suite.
- **`ecosystem-voice`** (`packages/ecosystem-voice`): Hardware-tier adaptive on-device voice recognition (`whisper.cpp` / `faster-whisper`) with **zero raw audio retention** (memory buffers zeroed out post-transcription). Voice intents are restricted from lowering policy restrictions or approving actions.
- **`ecosystem-ui-controls`** (`packages/ecosystem-ui-controls`): Zero-dependency Apple HIG Web Components (`<ecosystem-policy-toggle>`, `<ecosystem-approval-badge>`, `<ecosystem-status-indicator>`, `<ecosystem-step-up-modal>`) styled by `theme/ecosystem-theme.css`.

---

## 3. Quickstart & CLI

### Installation

```bash
# 1. Install ecosystem daemon as a system service
./scripts/install.sh                 # macOS launchd / Linux systemd

# 2. Provision the shared HMAC secret
ecosystem secret generate            # Primary device
ecosystem secret import <value>      # Additional nodes (export via `ecosystem secret show`)

# 3. Start the registry daemon
ecosystem start
```

### Essential CLI Commands

```bash
# Health & Status
ecosystem status                     # Verify registry and connected service health
ecosystem apps                       # Inspect installed ecosystem applications
ecosystem doctor gpu                 # Diagnose local GPU backends and Docker acceleration

# Forensic Scanning (Zero Breach Toolkit)
ecosystem scan targets               # List enrolled devices and auto-scan grants
ecosystem scan run --profile quick   # Execute an authorized local endpoint scan
ecosystem scan status <scan_id>      # View high-level scan findings and report refs

# Control Plane & Approvals
ecosystem approval list              # List pending policy approval checkpoints
ecosystem approval decide <id> allow # Approve a checkpoint (prompts for step-up TOTP)
```

The HIG Control Plane dashboard is served locally at:
👉 **`http://127.0.0.1:8500/ui`**

---

## 4. Cross-Application Integration Architecture & Examples

`appEcosystem` enables real-time collaboration between specialized member services through canonical event publication, unified policy enforcement, and shared capability discovery.

```text
  ┌──────────────┐                  ┌──────────────────┐                  ┌──────────────┐
  │   OpenEye    │──(physical.alert)▶│   appEcosystem   │◀──(security.alert)──│  AegisSIEM   │
  │ RTSP Cameras │                  │  Control Plane   │                  │ Router Syslog│
  └──────────────┘                  └─────────┬────────┘                  └──────────────┘
                                              │
                      ┌───────────────────────┼───────────────────────┐
                      ▼                       ▼                       ▼
             ┌────────────────┐      ┌────────────────┐      ┌────────────────┐
             │  cyber-agents  │      │ AI-for-Survival│      │  MagicMirror³  │
             │ SOAR Playbooks │      │ Offline RAG/LLM│      │ Ambient Display│
             └────────────────┘      └────────────────┘      └────────────────┘
```

### Scenario 1: Network Threat Detection to Automated Endpoint Inspection
1. **Perimeter Ingestion (`AegisSIEM`)**: An external IP (`45.227.253.13`) brute-forces a router management port or triggers a Sigma anomaly rule. AegisSIEM records the threat, performs GeoIP/ASN enrichment, and emits a `security.threat` event to `appEcosystem`.
2. **Autonomous Triage (`cyber-agents`)**: Subscribes to `security.threat`, runs an automated incident triage pass, and correlates the IP with internal network flows.
3. **Forensic Inspection (`Zero-Breach-Toolkit` & `ScanRunner`)**: If internal devices communicated with the attacker, `ScanRunner` evaluates enrolled device grants. With valid authorization, it executes a read-only endpoint sweep, persisting AES-256-GCM encrypted reports (`0600`) and publishing redacted summaries (`security.scan_completed`).
4. **Playbook Execution (`AI-for-Survival`)**: Ingests threat IOCs into its local database, allowing the operator to query offline playbooks (e.g., `Mobile Security Assessment`, `Incident Triage`) using local LLM inference.

### Scenario 2: Physical Surveillance Correlated with Cyber Perimeter Defense
1. **Motion & Face Detection (`OpenEye`)**: RTSP cameras detect an unrecognized subject near physical infrastructure after business hours. OpenEye emits `physical.motion` and `physical.intrusion`.
2. **Multi-Domain Correlation (`AegisSIEM` & `cyber-agents`)**: Cross-references the camera timestamp with internal DHCP leases and Wi-Fi probe requests. If an unrecognized mobile device associates during the physical intrusion window, incident severity escalates from `MEDIUM` to `CRITICAL`.
3. **Automated Notification Fan-out**: `NotificationRouter` dispatches deduplicated alerts across configured sinks (iMessage, Slack Block Kit, Discord Rich Embeds, Telegram, and companion push).

### Scenario 3: Ambient Monitoring & Emergency Containment
1. **Wall Display Status (`MagicMirror-Custom`)**: Aggregates live system telemetry: active threat counters from AegisSIEM, camera alerts from OpenEye, and overall mesh status from the ecosystem registry.
2. **One-Click Emergency Freeze**: The wall display exposes a physical/touch emergency kill switch (`ecosystem.freeze`). When triggered, the policy engine suspends active scans and mutations across all nodes. Resuming normal operations requires an authenticated operator entering a valid 6-digit TOTP code.

### Scenario 4: Hardware-Adaptive AI Model Packaging
1. **Hardware Profiling (`model-forge`)**: Host hardware (Apple Silicon Metal / NVIDIA CUDA / CPU) is profiled (`model-forge recommend`) to select an appropriate parameter and quantization tier (`T0_MINIMAL` to `T3_HIGH_END`).
2. **Model Distillation & Packaging**: Abliterates refusal vectors and compiles optimized GGUF Modelfiles signed with Ed25519 publisher keys.
3. **Local Serving (`AI-for-Survival` & `cyber-agents`)**: Runtimes serve the packaged model locally via Ollama with zero cloud leakage.

---

## 5. Documentation Suite

Detailed architecture specifications and operational guides are maintained in [`docs/`](docs/):

1. **[Hub Modes (`docs/HUB_MODES.md`)](docs/HUB_MODES.md)**: Standalone, Sync, and Edge modes, leader election, mDNS failover, and policy lease expiry.
2. **[Notifications (`docs/NOTIFICATIONS.md`)](docs/NOTIFICATIONS.md)**: Canonical envelope v1, delivery channels, deduplication, and alert routing.
3. **[Policy Engine (`docs/POLICY_ENGINE.md`)](docs/POLICY_ENGINE.md)**: Cryptographic policy state, action classification, and provisional containment with TTL rollbacks.
4. **[Dashboard Controls (`docs/POLICY_DASHBOARD_CONTROLS.md`)](docs/POLICY_DASHBOARD_CONTROLS.md)**: Apple HIG Web Components, 44px touch targets, ambient view modes, and step-up TOTP verification.
5. **[Scan Authorization (`docs/SCAN_AUTHORIZATION.md`)](docs/SCAN_AUTHORIZATION.md)**: Consent architecture, AUP recording, Ed25519 device key binding, DHCP churn resistance, and encrypted reports at rest (`0600`).
6. **[Commands (`docs/COMMANDS.md`)](docs/COMMANDS.md)**: Invoking a registered capability through the hub — the two policy gates, statuses, approvals, idempotency, and how an app provides a handler.
7. **[Capability Contracts (`docs/CAPABILITY_CONTRACTS.md`)](docs/CAPABILITY_CONTRACTS.md)**: Draft 2020-12 JSON Schemas for Events, Commands, Notifications, Capabilities, and Policy.
8. **[Ollama, GPU & Docker Guide (`docs/OLLAMA_GPU_AND_DOCKER.md`)](docs/OLLAMA_GPU_AND_DOCKER.md)**: Comprehensive accelerator setup, macOS Docker lack of Metal passthrough vs host Ollama, and authenticated LAN inference.
9. **[Cloud GPU Providers (`docs/CLOUD_GPU_PROVIDERS.md`)](docs/CLOUD_GPU_PROVIDERS.md)**: Multi-provider compute broker, sensitive data egress gates, and hard budget spend caps.
10. **[Acceptable Use Policy Template (`docs/AUP_TEMPLATE.md`)](docs/AUP_TEMPLATE.md)**: Standard AUP legal template for endpoint forensic sweeps.
11. **[Threat Model (`docs/THREAT_MODEL.md`)](docs/THREAT_MODEL.md)**: STRIDE analysis for the distributed mesh, ambient display boundaries, and audit logging.

---

## 6. Security & Privacy Commitments

- **Secure by Design**: Fail-closed architecture across all communication boundaries. The ecosystem refuses to start without a valid HMAC secret.
- **Fail-Closed Blue-Team Default**: Silence or omission never creates consent to scan or lowers security restrictions.
- **Microphone Privacy**: Audio buffers are scrubbed immediately in volatile memory. No audio is persisted to disk or sent to cloud APIs.
- **License Compliance**: MIT across core packages; strict subprocess boundary for AGPL tools (`Heritic` and `model-forge`) ensuring zero AGPL library imports into MIT codebases.

For full disclosures, consult [PRIVACY.md](PRIVACY.md) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

---

## 7. License

Copyright © 2026 Smart Industries LLC (Mikel Smart).  
Licensed under the [MIT License](LICENSE).
