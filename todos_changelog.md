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
