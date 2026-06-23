# Developer & Integration Guide (usage.md)

This guide provides practical examples, code snippets, and terminal commands to consume the **appEcosystem** layer across all connected projects.

---

## 1. Inter-Service Authentication

The ecosystem supports two forms of authentication using a shared `ECOSYSTEM_HMAC_SECRET`:
* **Bearer Token Auth**: Used for service-to-service RPC calls (e.g., AI-for-Survival calling OpenEye).
* **Webhook Signature Auth**: Used for payload verification on event-bus notifications.

### 1.1 Bearer Token Auth (Service-to-Service)

#### Python (Client-Side Request)
```python
import httpx
import json
import time
from ecosystem_auth.tokens import create_ecosystem_token

secret = "your-shared-hmac-secret"
service_name = "ai_for_survival"

# 1. Create the signed token
token_data = create_ecosystem_token(secret, service_name)

# 2. Attach token in the Authorization header as a Bearer JSON string
headers = {
    "Authorization": f"Bearer {json.dumps(token_data)}",
    "X-Ecosystem-Source": service_name
}

# 3. Make request
with httpx.Client() as client:
    resp = client.get("http://localhost:8200/api/camera/status", headers=headers)
    print(resp.json())
```

#### Node.js / Express (Server-Side Verification)
```javascript
const express = require("express");
const { requireEcosystemAuth } = require("./ecosystem-auth/middleware");

const app = express();
app.use(express.json());

// Apply the authentication middleware to secure this endpoint
app.get("/api/v1/hud/status", requireEcosystemAuth, (req, res) => {
  // req.ecosystemAuth contains: { auth_method: 'token', service: 'ai_for_survival' }
  res.json({ status: "active", caller: req.ecosystemAuth.service });
});

app.listen(8080);
```

### 1.2 Webhook Signature Auth (Event Bus Payloads)

#### Python (Event Publishing)
```python
import httpx
from ecosystem_auth.tokens import sign_payload

secret = "your-shared-hmac-secret"
payload = {
    "id": "evt_12345",
    "type": "security.alert",
    "source": "openeye",
    "timestamp": 1711200000.0,
    "data": {"threat": "motion_detected", "zone": "front_door"}
}

# Sign the compact JSON payload deterministically
signature = sign_payload(payload, secret)

headers = {
    "Content-Type": "application/json",
    "X-Ecosystem-Signature": signature
}

with httpx.Client() as client:
    resp = client.post("http://localhost:8500/events/publish", json=payload, headers=headers)
    print(resp.status_code)
```

#### FastAPI (Server-Side Middleware Guard)
```python
from fastapi import FastAPI, Depends
from ecosystem_auth.middleware import require_ecosystem_auth

app = FastAPI()

@app.post("/webhooks/security-alerts")
async def handle_alert(auth: dict = Depends(require_ecosystem_auth)):
    # auth contains: { "auth_method": "hmac", "payload": { ... } }
    event_data = auth["payload"]
    print(f"Verified event {event_data['type']} received!")
    return {"status": "processed"}
```

### 1.3 Replay-Resistant REST Requests

Authenticated REST calls (e.g. `/register`, `/deregister/{name}`) must use
`sign_request`, which adds timestamp + nonce + body-digest headers. The server
rejects signatures outside a ±300s window and any replayed nonce.

#### Python
```python
import httpx
from ecosystem_auth.tokens import sign_request

secret = "your-shared-hmac-secret"
body = {"name": "openeye", "host": "127.0.0.1", "port": 8200}
url = "http://localhost:8500/register"

headers = sign_request("POST", url, secret, body)
# headers = {X-Ecosystem-Signature, X-Ecosystem-Timestamp, X-Ecosystem-Nonce}

with httpx.Client() as client:
    resp = client.post(url, json=body, headers=headers)
    print(resp.status_code)  # 201
```

#### Node.js
```javascript
const { signRequest } = require("./ecosystem-auth/tokens");

const url = "http://localhost:8500/register";
const body = { name: "magicmirror", host: "127.0.0.1", port: 8080 };
const headers = signRequest("POST", url, process.env.ECOSYSTEM_HMAC_SECRET, body);

await fetch(url, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify(body) });
```

> The `ecosystem_client` / `ecosystem_client_js` `register_self()` / `deregister_self()`
> helpers already apply this scheme for you.

---

## 2. Discovery Cascade

Services dynamically locate each other by querying the central registry, querying mDNS local peers, or falling back to static peers.

```python
from ecosystem_client.config import EcosystemConfig
from ecosystem_client.discovery import DiscoveryManager

# 1. Initialize config (loads variables from environment / files)
config = EcosystemConfig(
    enabled=True,
    registry_url="http://localhost:8500",
    peers={"magicmirror": "http://localhost:8080"}
)

# 2. Run discovery manager
discovery = DiscoveryManager(config)

async def locate_peers():
    # Detects mode: REGISTRY -> PEER_TO_PEER -> STANDALONE
    mode = await discovery.detect_mode()
    print(f"Operating in {mode.value} mode")
    
    # Retrieve resolved peers
    peers = await discovery.get_peers()
    for name, peer_data in peers.items():
        print(f"Found Peer: {name} at {peer_data['base_url']}")
        
    # Register self with the registry (if Registry mode is active)
    await discovery.register_self(
        name="ai_for_survival",
        host="127.0.0.1",
        port=8000,
        health_endpoint="/health"
    )
```

---

## 3. Event Bus (Pub/Sub)

The central event bus allows decoupled cross-project awareness.

### 3.1 Subscribing to Events
To receive events, register your service with a `webhook_url` and a list of `subscriptions` (supports wildcards):

```json
POST http://localhost:8500/register
Content-Type: application/json

{
  "name": "magicmirror",
  "host": "127.0.0.1",
  "port": 8080,
  "health_endpoint": "/api/v1/health",
  "webhook_url": "http://127.0.0.1:8080/api/v1/events",
  "subscriptions": ["security.*", "ai.recommendation"]
}
```

### 3.2 Publishing an Event
Any service can publish an event wrapped in the `EventEnvelope`:

```python
import httpx
from events.schemas import EventEnvelope

# 1. Create standard envelope
event = EventEnvelope(
    type="security.alert",
    source="openeye",
    data={"intrusion_detected": True, "camera_id": "cam_east"}
)

# 2. Publish to registry's event bus
async def publish_alert():
    async with httpx.AsyncClient() as client:
        # Note: the EventBus.publish() method handles automatic signature signing
        resp = await client.post("http://localhost:8500/events/publish", json=event.model_dump())
        print(resp.json()) # Returns: {"delivered": 2, "failed": 0, "subscribers": ["magicmirror", "aegissiem"]}
```

---

## 4. UI Theming Integration

Connected project user interfaces must inherit the core design tokens for high-fidelity visual cohesion and strict Apple HIG compliance.

### 4.1 Consuming the CSS Custom Properties
Import the global theme in your main entrypoint (e.g., `index.js`, `main.css`, or HTML header):

```html
<!-- Main theme definition -->
<link rel="stylesheet" href="/theme/ecosystem-theme.css">

<!-- Dynamic Light Mode Override (applied when light class is set on HTML) -->
<script>
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    document.documentElement.classList.add('light-mode');
  }
</script>
```

In your CSS file:
```css
/* Import themes */
@import url("/theme/ecosystem-theme.css");
@import url("/theme/ecosystem-theme-light.css");

body {
  background-color: var(--bg-main);
  color: var(--text-primary);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  padding: var(--spacing-md);
  transition: background-color var(--anim-normal) var(--anim-ease), color var(--anim-normal) var(--anim-ease);
}

.card {
  background-color: var(--bg-panel);
  border: 1px solid var(--border-panel);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-md);
  padding: var(--spacing-lg);
  margin-bottom: var(--spacing-md);
}

.btn-primary {
  min-height: var(--touch-target-min); /* 44px HIG Compliance */
  background-color: var(--button-primary-bg);
  color: var(--button-primary-text);
  border: none;
  border-radius: var(--radius-sm);
  padding: var(--spacing-sm) var(--spacing-md);
  cursor: pointer;
  transition: background var(--anim-fast) linear;
}

.btn-primary:hover {
  background-color: var(--button-primary-hover-bg);
}
```

---

## 5. Lifecycle Management

Use the Python CLI wrapper to gracefully start, stop, monitor, and daemonize the services.

### 5.1 Basic CLI Commands
```bash
# Start the central Service Registry daemon
python -m cli start

# Stop the central Service Registry daemon
python -m cli stop

# Start registry + all configured ecosystem projects (AI, OpenEye, AegisSIEM, MM)
python -m cli start-all

# Stop all running ecosystem services and the registry
# (SIGTERM, escalating to SIGKILL after a 5s grace period)
python -m cli stop-all

# Restart the registry
python -m cli restart

# Check health and status of all services
python -m cli status

# Live health dashboard (refreshes every 5s; --once for a single snapshot)
python -m cli monitor
python -m cli monitor -i 10
python -m cli monitor --once
```

### 5.2 Log Monitoring
```bash
# List all available logs and sizes
python -m cli logs

# Tail the logs for AI-for-Survival
python -m cli logs ai_for_survival

# Show the last 150 lines of OpenEye log
python -m cli logs openeye -n 150
```

### 5.3 Background Service Installer (macOS Launchd)
The ecosystem can run as a background agent in macOS, launching automatically on system startup/user login:

```bash
# Install and register as a background service
python -m cli install

# Check if the service is loaded in launchctl
launchctl list | grep com.ecosystem.registry

# Uninstall and stop the background service
python -m cli uninstall
```
