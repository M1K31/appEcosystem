# Ecosystem Usage & API Guide

How to run the control plane, sign requests, consume the registry API, and wire an
app into the ecosystem. The registry listens on `http://127.0.0.1:8500` by default
(loopback in `local` mode; `0.0.0.0` in `lan` mode).

---

## 1. Lifecycle (the `ecosystem` CLI)

`ecosystem` (console script) or `python -m cli.main`:

```bash
ecosystem start            # start the registry only
ecosystem stop
ecosystem restart
ecosystem start-all        # registry + all configured projects
ecosystem stop-all
ecosystem status           # registry + registered-service health
ecosystem monitor -i 10    # live health dashboard (10s refresh)
ecosystem logs openeye     # tail a project's logs
ecosystem apps [--json]    # which apps are installed on THIS device
ecosystem install          # install registry as a launchd/systemd service
ecosystem uninstall
```

Install the service (internal-disk runtime, provisions the shared secret):

```bash
./scripts/install.sh                          # delegates to scripts/install-local.sh
ECOSYSTEM_MODE=lan ./scripts/install.sh       # networked: bind 0.0.0.0, advertise LAN IP
```

---

## 2. Shared secret

All services read one file-backed secret (`~/.config/ecosystem/secret.env`), so a
single provisioning step covers every app on the host. Fail-closed: there is **no**
default; unset means requests are rejected.

```bash
ecosystem secret generate          # create + persist (primary device)
ecosystem secret show              # print it (to copy to another device)
ecosystem secret import <value>    # set it on a joining device
ecosystem secret path              # where it lives
```

The registry never stores or distributes the secret. In-app, each UI app has an
"Ecosystem Setup" panel that calls the same `ecosystem_auth.setup` helpers.

---

## 3. Registry API

Read endpoints are open on loopback by default (set `ECOSYSTEM_REQUIRE_READ_AUTH=1`
to require signing); **writes always require an HMAC signature**.

```bash
curl http://127.0.0.1:8500/health                    # {"status":"healthy",...}
curl http://127.0.0.1:8500/services                  # all registered services
curl http://127.0.0.1:8500/services/priority         # sorted by priority/health
curl http://127.0.0.1:8500/services/openeye          # one service
curl http://127.0.0.1:8500/services/openeye/health   # on-demand health check
curl http://127.0.0.1:8500/ai-profile                # shared LLM profile (source of truth)
curl http://127.0.0.1:8500/ai-placement              # recommended host for LLM workloads
curl http://127.0.0.1:8500/metrics                   # Prometheus metrics
```

Writes — `POST /register`, `DELETE /deregister/{name}`, `PUT /ai-profile` — must be
signed (see §4).

---

## 4. Signing requests (HMAC, replay-resistant)

Use the shared `ecosystem_auth` helper rather than hand-rolling. `sign_request`
returns the `X-Ecosystem-Signature` / `X-Ecosystem-Timestamp` / `X-Ecosystem-Nonce`
headers over the canonical path + body digest.

### Python
```python
from ecosystem_auth.tokens import sign_request, get_ecosystem_secret
secret = get_ecosystem_secret()                       # override→env→secret.env
url = "http://127.0.0.1:8500/register"
payload = {"name": "myapp", "host": "127.0.0.1", "port": 9000,
           "health_endpoint": "/health", "priority": 10}
headers = sign_request("POST", url, secret, payload)
httpx.post(url, json=payload, headers=headers)
```

### Node / JS
```js
// npm install @smartindustriesllc/ecosystem-auth
const { signRequest } = require('@smartindustriesllc/ecosystem-auth')
const url = 'http://127.0.0.1:8500/register'
const payload = { name: 'mm', host: '127.0.0.1', port: 8080, health_endpoint: '/health' }
const headers = signRequest('POST', url, secret, payload)
await fetch(url, { method: 'POST', headers, body: JSON.stringify(payload) })
```

### Update the shared AI profile (propagates to all apps)
```python
changes = {"selected_model": "llama3.2:3b"}
headers = sign_request("PUT", "http://127.0.0.1:8500/ai-profile", secret, changes)
httpx.put("http://127.0.0.1:8500/ai-profile", json=changes, headers=headers)
# bumps version + emits ecosystem.ai_profile_changed so other apps update live
```

---

## 5. Integrating an app (`ecosystem_client`)

```python
from ecosystem_client import EcosystemClient
eco = EcosystemClient(service_name="myapp", service_port=9000, priority=10)
await eco.start()        # detects mode, self-registers, starts the heartbeat
peer = await eco.discover("aegissiem")    # find another service
await eco.publish("security.alert", {"src": "203.0.113.5", "severity": "high"})
```

- The client **re-registers on an interval** (heartbeat), so a DHCP/IP change pushes
  the new advertise host instead of leaving a stale registration.
- Host resolution follows `ECOSYSTEM_MODE`: loopback in `local`, the detected LAN IP
  in `lan` (override with `ECOSYSTEM_BIND_HOST` / `ECOSYSTEM_ADVERTISE_HOST`).
- Imports are guarded: with no registry/secret the app runs standalone.

---

## 6. Acceptance test

```bash
./scripts/smoke-ecosystem.sh    # single-host + subset + networked guarantees (no ports/services)
```


---

## 7. Policy Engine, Step-Up Approvals & Emergency Freeze

The policy engine guards all mutations, scanning requests, containment actions, and administrative overrides.

### API Endpoints
- `GET /api/policy/state`: Retrieve current active policy mode (`normal`, `incident`, `emergency`, `survival`, `freeze`), restrictions status, and effective bypass grants.
- `POST /api/policy/mode`: Set operational mode. Requires signed HMAC request and administrative step-up TOTP code if raising privileges or unfreezing.
- `POST /api/policy/freeze`: Emergency containment kill-switch (`ecosystem.freeze`). Immediately stops new mutation and scan jobs and cancels interruptible work. Can be invoked without step-up authentication.
- `POST /api/policy/resume`: Resumes normal operations from freeze. **Always** requires valid administrative step-up TOTP verification.
- `GET /api/approvals`: List pending, approved, or rejected checkpoints.
- `POST /api/approvals/{id}/decide`: Approve or reject a checkpoint:
  ```json
  { "decision": "allow", "operator": "admin", "totp_code": "123456" }
  ```

---

## 8. Forensic Scanning Service (Zero Breach Toolkit)

The integrated scanning subsystem executes authorized endpoint scans with encrypted-at-rest persistence and redacted event summaries.

### API Endpoints
- `POST /scans/run`: Request an authorized scan.
  ```json
  { "device_id": "self", "profile": "quick", "reason": "security.audit" }
  ```
- `GET /scans`: List all scan jobs and summary status.
- `GET /scans/{id}`: Fetch high-level redacted scan summary (`share.json`).
- `GET /scans/{id}/full`: Decrypt and view full scan report (`full.json`). **Requires step-up TOTP** in headers or query params (`X-Ecosystem-TOTP`).
- `GET /scans/targets`: List enrolled devices, reachability status, and active auto-scan designations.

---

## 9. Compute Broker & Hardware Acceleration Diagnostics

`ecosystem-compute` manages multi-provider AI model execution across local accelerators, LAN peers, and optional cloud providers.

### CLI Diagnostics
```bash
# Diagnose host GPU, Metal, CUDA, ROCm, and Docker VM passthrough status
ecosystem doctor gpu
```

### Python Broker Usage
```python
from ecosystem_compute import ComputeBroker, ComputeConfig

broker = ComputeBroker(config=ComputeConfig(
    providers={
        "local": {"enabled": True},
        "lan_node": {"enabled": True, "endpoints": ["http://192.168.1.50:11434"]},
        "runpod": {"enabled": False, "monthly_usd": 25.0}  # Cloud off by default
    }
))

# Ensure model endpoint with automatic fallback
endpoint = await broker.ensure_endpoint(task="chat", classification="standard")
print(f"Connected to {endpoint.provider_name} at {endpoint.base_url}")
```

---

## 10. Apple HIG Web Components & Control Plane UI

A zero-dependency Web Component bundle is served at `/ui/ecosystem-ui-controls.js` alongside standard styling `/ui/ecosystem-theme.css`:

```html
<link rel="stylesheet" href="/ui/ecosystem-theme.css">
<script type="module" src="/ui/ecosystem-ui-controls.js"></script>

<!-- Policy Restrictions Toggle with Step-Up Modal -->
<ecosystem-policy-toggle endpoint="/api/policy/state"></ecosystem-policy-toggle>

<!-- Emergency Freeze Button -->
<button class="ecosystem-button ecosystem-button--destructive" onclick="EcosystemUI.requestFreeze()">
  Emergency Freeze
</button>
```
Access the complete control plane at: `http://127.0.0.1:8500/ui`

---

## 11. Inter-Application Practical Workflow Examples

### Example A: Physical Security to Network SIEM Correlation
When `OpenEye` detects an unrecognized visitor near physical infrastructure, it publishes a canonical `physical.intrusion` event:

```python
from ecosystem_client import EcosystemClient

eco = EcosystemClient(service_name="openeye", service_port=8200)
await eco.start()

await eco.publish("physical.intrusion", {
    "camera_id": "server-room-cam1",
    "zone": "critical-perimeter",
    "unrecognized_faces": 1,
    "confidence": 0.96,
    "timestamp": "2026-11-02T19:45:00Z"
})
```

`AegisSIEM` and `cyber-agents` consume this event from the event bus and correlate it with real-time router association logs:

```python
# In AegisSIEM / cyber-agents event handler:
async def handle_physical_event(event: dict):
    if event["type"] == "physical.intrusion":
        camera_ts = event["data"]["timestamp"]
        # Check router DHCP & ARP table for new devices within ±3 minutes
        anomalies = db.get_recent_unseen_devices(window_seconds=180, reference_ts=camera_ts)
        for dev in anomalies:
            logger.warning("Correlated Physical & Cyber Intrusion! Device: %s (IP: %s)", dev["mac"], dev["ip"])
            await trigger_escalation(dev["ip"], severity="CRITICAL")
```

---

### Example B: AegisSIEM Querying AI-for-Survival for Offline Playbooks
When `AegisSIEM` discovers a suspicious brute-force or exploitation attempt, it queries `AI-for-Survival`'s local RAG knowledge base for defensive remediation procedures without touching external APIs:

```python
import httpx

async def fetch_defense_playbook(threat_type: str, service_banner: str):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://127.0.0.1:8000/api/knowledge/search",
            json={
                "query": f"remediation and hardening playbook for {threat_type} targeting {service_banner}",
                "top_k": 2
            },
            timeout=10.0
        )
        if response.status_code == 200:
            return response.json()
    return None
```

---

### Example C: Policy-Gated Endpoint Quarantine with Rollback Plan
`cyber-agents` requests containment of an internal endpoint. The cryptographic `PolicyEngine` validates whether an active bypass grant exists or if step-up approval is required:

```python
from ecosystem_policy import PolicyEngine, ActionRequest

engine = PolicyEngine.load()
req = ActionRequest(
    actor="cyber-agents/triage-daemon",
    model="security_analysis:local-llama3",
    action="isolate_device",
    action_class="contain",
    target={"device_id": "workstation-alpha", "ip": "192.168.1.142"},
    context={"incident_id": "INC-8812", "severity": "HIGH"},
    rationale="Repeated brute force against internal gateway detected."
)

decision = engine.decide(req)
if decision.result in ("allow", "allow_and_notify"):
    # Apply containment rule with automated TTL revert plan
    await router_mgr.block_lan_traffic(req.target["ip"])
    await scheduler.schedule_revert(decision.revert_plan)
elif decision.result == "require_approval":
    # Submit to unified approvals queue; surfaces in Control Plane & AegisSIEM UI
    await approvals_client.request_approval(req, deadline=decision.deadline)
```

---

### Example D: Emergency Mesh Freeze from MagicMirror or iOS Shortcut
An operator can instantly freeze all scanning, container alterations, and automated changes across every connected app using the unauthenticated freeze route:

```bash
# Emergency freeze (allowed from any enrolled control surface without password)
curl -X POST http://127.0.0.1:8500/api/policy/freeze \
  -H "Content-Type: application/json" \
  -d '{"initiated_by": "magicmirror-wall", "reason": "Operator physical alert button pressed"}'

# Verify freeze state across the mesh
curl -s http://127.0.0.1:8500/api/policy/state | jq .mode
# Output: "freeze"

# Resuming normal operations ALWAYS requires step-up TOTP verification
curl -X POST http://127.0.0.1:8500/api/policy/resume \
  -H "Content-Type: application/json" \
  -d '{"operator_id": "admin", "totp_code": "123456"}'
```

