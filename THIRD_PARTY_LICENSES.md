# Third-Party Licenses & Component Disclosures

The `appEcosystem` control plane, shared libraries, and companion services integrate or interface with the following third-party open-source projects, tools, and protocols:

---

### 1. Zero Breach Toolkit (ZBT)
- **License**: Apache License, Version 2.0
- **Upstream Repository**: [github.com/interplains/Zero-Breach-Toolkit](https://github.com/interplains/Zero-Breach-Toolkit)
- **Role**: Local-first endpoint forensic auditor, spyware scanner, and system integrity evaluator.
- **Integration Pattern**: Subprocess execution via `ScanRunner` utilizing CLI flags (`--json`, `--share-json`, `--describe`). Full reports are encrypted at rest with AES-256-GCM.

---

### 2. Heretic (AI Model Production)
- **License**: GNU Affero General Public License, Version 3.0 (AGPL-3.0)
- **Upstream Repository**: [github.com/p-e-w/heretic](https://github.com/p-e-w/heretic)
- **Fork Repository**: [github.com/M1K31/Heritic](https://github.com/M1K31/Heritic)
- **Role**: Representation engineering and steering-vector model distillation.
- **Integration & Isolation Boundary**: Executed strictly as an isolated subprocess from the standalone `model-forge` repository (also AGPL-3.0). **Zero** AGPL code, libraries, or modules are imported into the MIT-licensed `appEcosystem` control plane or its client libraries.

---

### 3. SkyPilot
- **License**: Apache License, Version 2.0
- **Upstream Repository**: [github.com/skypilot-org/skypilot](https://github.com/skypilot-org/skypilot)
- **Role**: Multi-cloud orchestration and batch compute abstraction used within `ecosystem-compute`'s `SkyPilotComputeProvider`.

---

### 4. Whisper.cpp / faster-whisper
- **License**: MIT License
- **Upstream Repositories**:
  - whisper.cpp: [github.com/ggerganov/whisper.cpp](https://github.com/ggerganov/whisper.cpp)
  - faster-whisper: [github.com/SYSTRAN/faster-whisper](https://github.com/SYSTRAN/faster-whisper)
- **Role**: On-device speech-to-text inference for the local `ecosystem-voice` pipeline, operating with zero raw audio retention.

---

### 5. ntfy
- **License**: Apache License, Version 2.0 / GNU General Public License v2.0
- **Upstream Repository**: [github.com/binwiederhier/ntfy](https://github.com/binwiederhier/ntfy)
- **Role**: Optional self-hosted HTTP-based push notification server for mobile and desktop notification forwarding in `NotificationRouter`.

---

### 6. Core Python Libraries
- **FastAPI**: MIT License ([github.com/tiangolo/fastapi](https://github.com/tiangolo/fastapi))
- **Starlette**: BSD 3-Clause License ([github.com/encode/starlette](https://github.com/encode/starlette))
- **Pydantic**: MIT License ([github.com/pydantic/pydantic](https://github.com/pydantic/pydantic))
- **Uvicorn**: BSD 3-Clause License ([github.com/encode/uvicorn](https://github.com/encode/uvicorn))
- **Cryptography**: Apache-2.0 / BSD 3-Clause ([github.com/pyca/cryptography](https://github.com/pyca/cryptography))
- **HAP-Python (HomeKit)**: Apache License 2.0 ([github.com/ikalchev/HAP-python](https://github.com/ikalchev/HAP-python))

