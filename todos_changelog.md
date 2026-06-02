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
- [x] **Timeout to SIGKILL Escalation**: Refactor `cmd_stop_all` to poll active processes and force-terminate with `SIGKILL` (signal 9) if they fail to shut down gracefully within 5 seconds. [RESOLVED]
- [x] **Linux systemd Installer**: Create systemd configuration templates to support Arm Linux (Raspberry Pi) and Intel Linux deployment parity with macOS launchd. [RESOLVED]

---

## Changelog

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
