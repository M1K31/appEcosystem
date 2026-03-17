# appEcosystem

Integration layer for a multi-project smart home/security/AI ecosystem. Provides service registry, event bus, peer discovery, and CLI lifecycle management — while every project continues to work standalone.

## Projects

| Project | Port | Stack | Description |
|---------|------|-------|-------------|
| AI-for-Survival | 8000 | Python FastAPI | Offline LLM assistant with RAG pipeline |
| OpenEye | 8200 | Python FastAPI + React | OpenCV home security surveillance |
| MagicMirror | 8080 | Node.js + Electron | Smart mirror HUD with modular widgets |
| AsusGuard (LogAnalysis) | 8088 | Python Flask | Router log analysis & network security |
| appEcosystem (Registry) | 8500 | Python FastAPI | Service registry & event bus |

## Quick Start

```bash
# 1. Set the shared HMAC secret on all devices
export ECOSYSTEM_HMAC_SECRET="your-secret-here"

# 2. Start everything
python -m cli start-all

# 3. Check status
python -m cli status

# 4. View logs
python -m cli logs                    # list available logs
python -m cli logs ai_for_survival    # tail a project's log
python -m cli logs openeye -n 100     # last 100 lines

# 5. Stop everything
python -m cli stop-all
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `start` | Start the ecosystem registry only |
| `stop` | Stop the ecosystem registry only |
| `start-all` | Start registry + all configured projects |
| `stop-all` | Stop all projects + registry |
| `status` | Health check all services |
| `logs [project] [-n N]` | View project log files |
| `install` | Install registry as macOS launchd service |
| `uninstall` | Remove launchd service |

## Architecture

### Discovery Cascade

Services find each other using a 3-mode cascade:

1. **Registry** — query the central registry at port 8500
2. **mDNS** — discover peers on the local network via `_ecosystem._tcp.local.`
3. **Static peers** — fall back to `ecosystem.yaml` project definitions
4. **Standalone** — if no peers found, operate independently (no-op)

### Event Bus

Projects publish and subscribe to typed events for real-time cross-project awareness:

- **OpenEye** publishes: `security.alert`, `security.intrusion`, `security.motion_detected`, `security.threat_blocked`
- **LogAnalysis** publishes: `security.threat_blocked`, `network.anomaly`, `security.alert`
- **AI-for-Survival** publishes: `ai.analysis_complete`, `ai.recommendation`, `ai.playbook_triggered`
- **MagicMirror** subscribes to all event types for HUD display

All events are HMAC-signed. Unsigned events are rejected.

### Standalone-First Design

Every project functions independently without the ecosystem. Integration is additive:

- Ecosystem client initialization is wrapped in try/catch with graceful fallback
- No project imports ecosystem code at the module level
- Missing peers = features degrade, never crash

## Configuration

All project definitions live in `ecosystem.yaml`:

```yaml
ecosystem:
  name: "appEcosystem"
  base_path: "/Volumes/Locker2/GitHub"

projects:
  ai_for_survival:
    name: "AI_For_Survival"
    path: "AI-for-Survival/backend"
    port: 8000
    health_endpoint: "/health"
    start_command: "python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000"
```

## LAN Cluster Deployment

The ecosystem is designed for distribution across 2-3 devices on the same network:

1. **Clone repos** to each device where a project will run
2. **Set `ECOSYSTEM_HMAC_SECRET`** to the same value on all devices
3. **Start the registry** on one device: `python -m cli start`
4. **Start projects** on their respective devices using each project's start command
5. **mDNS discovery** handles cross-device peer finding automatically
6. **Static fallback**: if mDNS is unavailable, configure peer addresses in `ecosystem.yaml`

## Security

- **HMAC-SHA256** signing on all inter-service communication
- **Ecosystem tokens**: 24-hour validity, 12-hour proactive rotation
- **Shared secret**: `ECOSYSTEM_HMAC_SECRET` env var, same across all cluster devices
- No service trusts unsigned requests from ecosystem peers
