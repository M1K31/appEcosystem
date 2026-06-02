# Cyber Claude Harness Integration — 2026-03-24

## Changes
- Added harness preference to `llm/command_router.py` — security capabilities route through daemon first
- Added `asusguard_daemon` service entry to `ecosystem.yaml` (port 8088)
- Added `cyber_harness` configuration section to `ecosystem.yaml`
- Updated playbooks with `prefer_harness: true` flag for security-related steps

## New Dependencies
- None (httpx already present; harness is optional)

## Fallback Behavior
- CommandRouter caches harness availability (30s TTL)
- Security capabilities try daemon, fall back to direct project API calls
- Non-security capabilities unaffected

## Configurable Daemon Port (2026-03-24)

- `llm/command_router.py`: `_HARNESS_BASE_URL` now reads `ASUSGUARD_PORT` env var (default: 8088)
- `ecosystem.yaml` still has `daemon_url: "http://localhost:8088"` as the config default
- Set `ASUSGUARD_PORT=9090` to use a non-default port across the entire ecosystem
