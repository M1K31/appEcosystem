# Unified Security & AI Ecosystem (appEcosystem)

A robust, **offline-first** ecosystem combining AI, surveillance, intrusion
detection, and smart displays into a single cohesive home network. `appEcosystem`
is the **control plane**: a service registry, event bus, shared-secret/auth layer,
and shared AI profile that ties the apps together — while every app still runs
**standalone** when the registry is absent.

## Architecture

**Standalone-first:** if the central coordination layer goes offline, every
connected app degrades gracefully and keeps working as an independent system.
When the registry *is* present, apps discover each other, share events, and sync
their LLM selection.

| Component | Role |
|-----------|------|
| **appEcosystem** (this repo) | Service registry + event bus + shared AI profile + shared auth |
| **AI-for-Survival** | Offline LLM assistant (Ollama + RAG) + cyber triage |
| **AegisSIEM** (LogAnalysis) | Router syslog SIEM + honeypot + active threat mitigation |
| **OpenEye** | OpenCV surveillance (face/object recognition, recording, alerts) |
| **MagicMirror³** | Visual hub / dashboards for the ecosystem |

### Shared packages (path-installed into each app)
- **`ecosystem_auth`** (`auth/python`) — HMAC-SHA256 replay-resistant request signing
  (timestamp + nonce + body digest), fail-closed shared-secret resolution, and the
  in-app "Ecosystem Setup" secret helpers.
- **`ecosystem_client`** (`ecosystem_client/`) — discovery cascade (registry → mDNS →
  static → standalone), self-registration heartbeat, event pub/sub, topology
  (`local`|`lan`) resolution.
- **`ecosystem-ai`** (`packages/ecosystem-ai`) — provider abstraction (Ollama default
  + Anthropic/OpenAI/Gemini), hardware capability tiers, syncable AI profile.

### Deployment modes (`ECOSYSTEM_MODE`)
- **`local`** (default) — everything on one machine; services bind + advertise on
  loopback. Nothing is exposed on the network.
- **`lan`** — services may live on different devices; they bind on all interfaces and
  advertise their real LAN IP via self-registration. Set `ECOSYSTEM_MODE=lan` per device.

## Quickstart

```bash
# 1. Install the registry as a service + provision the shared secret (internal disk)
./scripts/install.sh                 # macOS launchd / Linux systemd

# 2. Provision / share the HMAC secret (same machine is automatic; joining devices import it)
ecosystem secret generate            # primary device
ecosystem secret import <value>      # additional devices (value from `ecosystem secret show`)

# 3. Check the ecosystem
ecosystem status                     # registry + registered services health
ecosystem apps                       # which apps are installed on THIS device
```

The `ecosystem` CLI (or `python -m cli.main`) controls the registry:
`start` · `stop` · `restart` · `start-all` · `stop-all` · `status` · `monitor` ·
`logs <app>` · `secret <generate|show|import|path>` · `apps [--json]` ·
`install` · `uninstall`.

See [usage.md](usage.md) for the registry API, HMAC signing, and per-app integration.

## Requirements
- Python 3.10–3.12 (the registry); the shared `ecosystem_auth` supports 3.9+ for apps
  on older runtimes (e.g. OpenEye).
- macOS (launchd) or Linux (systemd) for the installed service.
- Ollama (default LLM provider) — optional but recommended.
