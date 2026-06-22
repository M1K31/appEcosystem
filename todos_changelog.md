# Todos & Changelog

This document tracks completed changes, active items, and planned improvements for the central **appEcosystem** layer.

---

## Active & Pending Todos

### Phase 1: Security & Cryptography
- [x] **Fix GET Request Verification Bug**: Resolve the disconnect between `CommandRouter` (which signs `{"url": url, "method": method}`) and `require_ecosystem_auth` (which expects a JSON request body and tries to call `request.json()`, failing with `400 Bad Request` on GETs). [RESOLVED]
- [x] **Registry Access Control**: Implement signature verification or token-based authentication on registry endpoints (`/register`, `/deregister/{name}`) to prevent malicious services from spoofing or hijacking registrations. [RESOLVED]
- [x] **HMAC Token Replay Protection**: Modify ecosystem tokens to include a short-lived nonce or timestamp verification in the signature payload (currently only signing static `service`, `issued_at`, and `expires_at`), which allows replay attacks within the 24-hour expiration window. [RESOLVED]
- [x] **Bind Token Field**: Include the generated secure random `token` hex in the HMAC signature payload of the ecosystem token so that the random token actually acts as a cryptographic anchor. [RESOLVED]

### Phase 2: Architecture & Code Quality
- [x] **FastAPI Event Loop Blocking**: Fix the `Zeroconf` discovery blocking issue. Currently, `EcosystemDiscovery.discover_services()` calls `time.sleep(2)`, which blocks the main thread and halts the entire FastAPI event loop for 2 seconds. Rewrite to use `asyncio.sleep()` or run it inside an executor thread pool using `asyncio.to_thread`. [RESOLVED]
- [x] **Client Connection Pooling**: Replace inline `async with httpx.AsyncClient()` instances inside loops (e.g. in `HealthMonitor` checks and `EventBus` webhook delivery retries) with a single, persistent, and shared `httpx.AsyncClient` session. [RESOLVED]
- [x] **Safe Start Command Split**: Refactor `subprocess.Popen(cmd.split())` inside `cli/commands.py` to use `shlex.split(cmd)` to safely handle start commands with shell arguments and quotes. [RESOLVED]
- [x] **Self-Contained Client Packaging**: Restructure the Python client package (`packages/ecosystem-client`) to bundle or depend on the `ecosystem_auth` package to prevent runtime `ImportError` on client-only installations. [RESOLVED]

### Phase 3: UI/UX & Theming
- [x] **Unified Theme Switcher**: Build a global CSS layout that toggles classes between Light Mode (`ecosystem-theme-light.css`) and Dark Mode (`ecosystem-theme.css`) dynamically. [RESOLVED]
- [x] **Apple HIG Responsive Layout**: Implement custom grid systems using the 8pt spacing system (`--spacing-xs` to `--spacing-2xl`) and ensure all interactive elements maintain the `--touch-target-min` of `44px`. [RESOLVED]
- [x] **Magic Mirror Color Degrade**: Create a specialized high-contrast monochrome utility class for MagicMirror's HUD display, respecting its limited color-serving hardware. [RESOLVED]

### Phase 4: DevOps, Lifecycle & Orchestration
- [x] **Ecosystem Process Daemonization**: Generate robust lifecycle scripts with signal interception (`SIGINT`, `SIGTERM`) for graceful shutdowns. [RESOLVED]
- [x] **Timeout to SIGKILL Escalation**: Refactor `cmd_stop_all` to poll active processes and force-terminate with `SIGKILL` (signal 9) if they fail to shut down gracefully within 5 seconds. [RESOLVED — escalation now in `cli/commands.py` `_terminate_pid`, used by `cmd_stop`/`cmd_stop_all`, not just `process_manager.py`]
- [x] **Linux systemd Installer**: Create systemd configuration templates to support Arm Linux (Raspberry Pi) and Intel Linux deployment parity with macOS launchd. [RESOLVED]

### Phase 6: Hardening & Observability (2026-06-16)
- [x] **Token lifetime cap**: `verify_ecosystem_token` rejects implausibly long-lived tokens (>48h) and future `issued_at`, bounding a leaked-secret blast radius (Python + JS). [RESOLVED]
- [x] **Observability**: Prometheus `GET /metrics` (counters + live service gauges), structured JSON logging via `ECOSYSTEM_LOG_FORMAT`, and a non-root `Dockerfile` with `HEALTHCHECK`; CI builds the image. [RESOLVED]
- [x] **Optional read-endpoint auth**: `ECOSYSTEM_REQUIRE_READ_AUTH` gates auth on `/services*`; in-repo discovery clients and CLI sign their GETs so enabling it is non-breaking. [RESOLVED]
- [x] **Self-hosted fonts**: Replaced the render-blocking `fonts.googleapis.com` `@import` with local `@font-face` declarations pointing to vendored variable WOFF2 files (`theme/fonts/`). `scripts/fetch_fonts.py` re-downloads them; system-font fallbacks keep the UI working offline (privacy + MagicMirror HUD). [RESOLVED]

### Backlog (future)
- [ ] **Branch protection / required checks**: Enable branch protection on `main` requiring the CI workflow (tests, audits, shellcheck, docker build) to pass before merge.
- [ ] **Publish Docker image to GHCR on tag**: Add a release workflow that builds and pushes `ghcr.io/<owner>/appecosystem-registry` on `v*` tags.

### Ecosystem-wide initiative (see [ECOSYSTEM_AUDIT.md](ECOSYSTEM_AUDIT.md) + [ECOSYSTEM_AI_PLAN.md](ECOSYSTEM_AI_PLAN.md))
- [~] **Phase A — Port reconciliation** (in progress):
  - [x] `ecosystem.yaml` AsusGuard 8088→8089 (harness keeps 8088).
  - [x] OpenEye: `resolve_service_port()` (ECOSYSTEM_SERVICE_PORT→OPENEYE_PORT→PORT→8200); bind＝register; fixed bind≠register bug; tests.
  - [x] LogAnalysis: `resolve_service_port()` honors ECOSYSTEM_SERVICE_PORT for bind＝register (default 8089); tests.
  - [x] AFS: `resolve_service_port()` (ECOSYSTEM_SERVICE_PORT→PORT→config→8000); bind＝register; tests.
  - [ ] MagicMirror: standardize on ECOSYSTEM_SERVICE_PORT→MM_PORT→8080. **Deferred** — repo has active WIP (ecosystem-auth edits + new MMM-AsusGuard-SIEM / MMM-CyberHarness modules); already consistent at 8080.
  - [ ] `port-doctor` preflight (registered＝listening, port-free) in appEcosystem CLI + per-app startup.
  - Note: OpenEye and MagicMirror have **uncommitted WIP touching `ecosystem_auth`/`ecosystem-auth`** (looks like a started Phase E auth sync) — left untouched.
- [x] **Phase B0 — `ecosystem_ai` foundation**: new installable package `packages/ecosystem-ai/`. Provider interface + `OllamaProvider` (default, local-first), `ProviderRouter` (local-first + cloud fallback), `HardwareProbe`/`CapabilityTier` (T0–T3) + tier→model, `CapabilityManager` (feature gating w/ cloud-lift), and the syncable `AIProfile` schema (version/with_change/merge — the shared source of truth that makes a selection in one app appear in all). 25 tests passing.
- [x] **Phase B1 — Provider plug-ins**: `AnthropicProvider`, `OpenAIProvider` (configurable base_url for OpenAI-compatible/Copilot-style gateways), `GeminiProvider` — httpx-based (no heavy SDKs), opt-in via env keys, uniform `ChatResult`. `build_providers()`/`build_router()` factory assembles the set from a profile (Ollama always + enabled cloud). Copilot deferred per decision. 36 package tests passing.
- [x] **Phase B2 — Ecosystem AI profile (registry side)**: `AIProfileStore` (JSON-persisted, version-bumped, last-write-wins); `GET /ai-profile` (read) and `PUT /ai-profile` (signed write) on the registry; writes broadcast `ecosystem.ai_profile_changed` so a selection in one app propagates live to all. `ai:` section seeded in `ecosystem.yaml`; `ECOSYSTEM_AI_PROFILE_FILE` documented. Tests for store + endpoints. *(Client-side `EcosystemConfig` precedence + live event handling is part of B3 adoption.)*
- [~] **Phase B3 — Adopt in each app** (in progress):
  - [x] Shared `AIProfileClient` (in `ecosystem_ai/sync.py`): fetch/write the shared profile, local fallback, live event handling, auth-agnostic signer. 42 package tests.
  - [x] **AFS reference adoption**: `ecosystem_ai_bridge` propagates an LLM switch to the shared profile and `GET /api/v1/models/shared` reads it; guarded/best-effort so standalone still works. Tests added.
  - [x] LogAnalysis: `ecosystem_ai_bridge` (prefer shared model in `_select_ollama_model`; propagate on settings save). **Scaffolding only — dormant until Phase E** (its vendored `ecosystem_auth` lacks `sign_request`).
  - [ ] OpenEye: adopt `ecosystem_ai` **and add an Ollama path** (Claude stays optional).
  - [ ] MagicMirror (JS): consume the shared profile for HUD AI widgets (pairs with its in-flight ecosystem WIP).
  - Note: activating sync at runtime needs `ecosystem-ai` installed in each app's env (path install until the package is published) — guarded imports keep apps working without it.
- [ ] **Phase C — Hardware-adaptive feature gating**: per-app feature requirements → tier-based enable/disable + graceful degradation matrix.
- [ ] **Phase D — AFS↔LogAnalysis synergy**: first-class log/network agent tools + event-bus correlation.
- [~] **Phase E — Hardening parity / client re-sync** (in progress):
  - [x] Shared packages bumped to **v0.3.0**; fixed an invalid `build-backend` in `ecosystem-auth` that blocked installation.
  - [x] **AFS converted**: retired vendored `ecosystem_auth`/`ecosystem_client`, repointed to the path-installed shared v0.3.0 packages; app imports clean, tests pass. Registration + AI sync now work against the v0.3.0 registry.
  - [x] **Secret model decided: fail-closed everywhere** (no default). Implemented in `get_ecosystem_secret` (Python), `EcosystemConfig` (client, `hmac_secret=""` + warning), and JS `getEcosystemSecret`. Tests + conftest updated. 195 appEcosystem + 9 JS tests pass.
  - [x] **LogAnalysis converted**: retired vendored auth/client → shared v0.3.0 packages; bridge now active; full suite 243 passed, 1 skipped.
  - [x] **OpenEye converted**: stashed old-scheme WIP, retired vendored auth/client → shared v0.3.0 packages (verified on Python 3.9), dropped the superseded `claude/mystifying-gauss-3aefaf` branch + embedded worktree. Required lowering `ecosystem-auth` requires-python to >=3.9 (compatibility tenet).
  - [x] **MagicMirror converted**: replaced vendored `js/ecosystem-auth`/`ecosystem-client` with the canonical v0.3.0 JS (signRequest/verifyRequest/NonceStore), repointed the auth require to MM's sibling dir; verified via node require smoke. Old-scheme WIP stashed.
  - **Phase E COMPLETE for all 4 apps.** OpenEye stash review: `stash@{0}` (mine) is obsolete old-scheme cleanup (safe to drop); `stash@{1}` is **pre-existing substantial WIP** (two-way audio, scheduled tasks, install/setup scripts) — left for the user to salvage (its auth/client parts now conflict with Phase E).
  - Original blocker context: the member apps' vendored `ecosystem_auth` is the OLD scheme (`sign_payload` only; no `sign_request`/`verify_request`/replay protection). Since the registry was upgraded to the v0.3.0 replay-resistant scheme, **the apps can no longer authenticate to it** (register/deregister/AI-profile writes 401). Must re-sync v0.3.0 auth+client into every app (recommended: turn `ecosystem-auth` + `ecosystem-client` into path-installed shared packages and retire the vendored copies, per the "one package" decision). Unblocks registration AND the AI-profile sync.
  - Document: [PUBLISHING.md](PUBLISHING.md). Path-install wired into appEcosystem `scripts/install.sh`.
- [ ] **Phase F — Facilitator placement**: resource-budget signals → place LLM load on the most capable host.

### Phase 5: Audit Remediation (2026-06-14)
- [x] **Critical: systemd installer crash**: Removed orphan `EOF` in `scripts/install_systemd.sh` that aborted the installer (exit 127) under `set -euo pipefail`. [RESOLVED]
- [x] **Fail-closed HMAC secret**: `get_ecosystem_secret()` now refuses the insecure default when `ECOSYSTEM_ENV != dev` (Python + JS); single source of truth replaces four duplicated lookups. Added `.env.example`. [RESOLVED]
- [x] **Loopback bind + scoped CORS**: Registry defaults to `127.0.0.1`; CORS origins configurable via `ECOSYSTEM_CORS_ORIGINS`; method/header allowlists replace wildcards. [RESOLVED]
- [x] **CommandRouter pooling + path-param encoding**: Shared `httpx.AsyncClient` with `aclose()`; LLM-supplied path params URL-encoded to block traversal. [RESOLVED]
- [x] **CLI lifecycle parity**: Added `restart` and `monitor` commands; `_terminate_pid` SIGKILL escalation; launchd plist now wraps uvicorn in `process_manager.py` for macOS/Linux parity. [RESOLVED]
- [x] **Static service resilience**: Config-defined services are retained (not auto-deregistered) so they recover; static load validates per-project. [RESOLVED]
- [x] **App.state dependencies**: Registry/health-monitor resolved via FastAPI dependencies returning 503 before startup, instead of module globals. [RESOLVED]
- [x] **Machine-agnostic base path**: `ECOSYSTEM_BASE_PATH` override; removed hardcoded developer path from `ecosystem.yaml`. [RESOLVED]
- [x] **CI + lockfiles**: GitHub Actions (pytest matrix, pip-audit, npm audit, shellcheck); committed `package-lock.json`. [RESOLVED]
- [x] **HMAC replay protection (request signature path)**: The `X-Ecosystem-Signature` scheme now binds a timestamp, a unique nonce, and a body digest over a host-independent canonical path. Verifiers enforce a ±300s freshness window and a `NonceStore` rejects replays. Implemented and tested in Python and JS (cross-language signature parity verified); all signers (`CommandRouter`, Python/JS discovery clients) and both middlewares updated. [RESOLVED]

---

## Changelog

### [v0.3.0] — 2026-06-14
#### Security
- Replay-resistant request signatures: `X-Ecosystem-Signature` now binds a timestamp, nonce, and body digest over a canonical (host-independent) path; verifiers enforce a freshness window and a nonce store (Python + JS, cross-language parity tested).
- Fail-closed HMAC secret resolution (`get_ecosystem_secret`) across Python and JS; refuses the insecure default outside `dev`.
- Registry binds to `127.0.0.1` by default; CORS origins configurable and method/header allowlists scoped.
- URL-encode LLM-supplied path params in `CommandRouter` to prevent path traversal.
- Fixed a shadowed `import json` in the auth middleware that broke signature-body parsing.
#### Added
- `ecosystem restart` and `ecosystem monitor` CLI commands.
- `.env.example`, GitHub Actions CI (tests, pip-audit, npm audit, shellcheck), committed `package-lock.json`.
- `static` service flag; config-defined services are retained on failure for recovery.
#### Fixed
- Critical: orphan `EOF` aborting the systemd installer.
- CLI `stop`/`stop-all` now escalate SIGTERM → SIGKILL.
- Registry singletons resolved via `app.state` dependencies (503 before startup, not AttributeError).
- Removed hardcoded developer `base_path` from `ecosystem.yaml` (use `ECOSYSTEM_BASE_PATH`).
#### Changed
- `CommandRouter` uses a single pooled `httpx.AsyncClient`.
- launchd plist wraps uvicorn in `process_manager.py` for macOS/Linux shutdown parity.

### [v0.2.0] — 2026-03-24
#### Added
- Added `cyber_harness` section to `ecosystem.yaml` to configure the cybersecurity daemon on port `8088`.
- Integrated `CommandRouter` with `cyber-claude-harness` daemon (`localhost:8088`), prioritizing it for security capabilities (`threat_analysis`, `log_analysis`, `security_scan`, `incident_triage`, `block_ip`, `security_status`).
- Added automatic fallback to legacy direct API routes if the cybersecurity daemon is offline or returns an error.
- Added platform compatibility logs to `vault/platform-compatibility.md`.

### [v0.1.0] — 2026-02-10
#### Added
- Initial release of the `appEcosystem` coordination layer.
- Implemented **3-Mode Discovery Cascade**: central registry -> local mDNS (Zeroconf) -> static configuration (`ecosystem.yaml`).
- Implemented **Event Bus**: webhook-based publish/subscribe system supporting wildcard channels (e.g. `security.*`).
- Implemented **HMAC-SHA256 inter-service authentication** middleware for FastAPI and Express.
- Created `ecosystem` CLI tool with `start`, `stop`, `start-all`, `stop-all`, `status`, `logs`, `install`, and `uninstall` commands.
- Implemented launchd integration for macOS.
