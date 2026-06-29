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
const { signRequest } = require('./js/ecosystem-client/tokens') // shipped into each app
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
