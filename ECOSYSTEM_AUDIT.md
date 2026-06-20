# Ecosystem-Wide Audit — Ports, LLM Consistency & Embedded Integration

**Prepared for:** Smart Industries LLC
**Date:** 2026-06-20
**Scope:** Cross-repo audit of the four ecosystem member projects plus the
`appEcosystem` coordination layer:

| Repo | Role | Stack |
|------|------|-------|
| `AI-for-Survival` (AFS) | Survival assistant + **LLM/agent hub** (RAG, tool-calling) | Python/FastAPI + Ollama/OpenAI/Anthropic |
| `LogAnalysis` (AsusGuard) | Router log analysis, SIEM, honeypot, **cyber-harness** | Python/Flask + Ollama |
| `OpenEye` | OpenCV home-security surveillance | Python/FastAPI + React + Anthropic |
| `MagicMirror-Custom` | HUD / dashboard | Node/Electron/Express + multi-provider LLM |
| `appEcosystem` | Registry / event bus / discovery facilitator | Python/FastAPI |

Method: tracked-file scans (`git grep`) per repo for port usage, LLM provider
config, and ecosystem-client integration. Evidence is cited as `file:line`.

---

## 1. Top-Level Overview

The ecosystem is **structurally sound**: every member app embeds the
`ecosystem_client` (config, discovery cascade, HMAC auth) and has
`standalone`/`fallback` paths, so the "works without appEcosystem, accelerated
with it" goal is met at the architecture level. The replay-resistant auth and
discovery cascade shipped in appEcosystem v0.3.0 are mirrored in the clients.

However, three systemic gaps undermine the goals you called out:

1. **Port allocation is inconsistent and partly wrong.** The `appEcosystem`
   `ecosystem.yaml` port map disagrees with what the apps actually bind, apps
   use *different* env vars for "bind" vs "register", and `OpenEye` registers a
   different port than it listens on. Custom ports are **not** navigated
   gracefully — changing a port can silently break health checks and
   inter-service comms.
2. **There is no shared LLM configuration.** Each app configures its own Ollama
   URL / model independently; selecting Ollama + model X in AFS does **not**
   propagate to LogAnalysis or the others. `OpenEye` is Anthropic-only and
   cannot currently participate in a unified local-LLM posture. Local model
   stores are not coordinated, risking duplication.
3. **AFS↔LogAnalysis synergy is latent, not wired.** AFS is built as the agent
   hub (`ecosystem_tools.py` turns discovered services into LLM tools) and
   LogAnalysis exposes the cyber-harness, but there is no first-class,
   documented flow that has AFS delegate log/network reasoning to LogAnalysis.

None of these are architectural dead-ends; they are integration/config
consistency problems. A focused remediation (a shared "ecosystem profile" for
ports + LLM, plus a port-reconciliation fix) resolves them.

---

## 2. Findings

### 2.1 Ports & Custom-Port Handling

**Declared vs. actual:**

| Service | `ecosystem.yaml` declares | App actually binds | Registers as | Verdict |
|---------|---------------------------|--------------------|--------------|---------|
| AFS | 8000 | 8000 (`PORT`, `main.py:84` / start_command) | `PORT`=8000 | OK |
| OpenEye | 8200 | **8000** (`OPENEYE_PORT`, `backend/main.py:956`) | **8200** (`PORT`, `main.py:497`) | **bind ≠ register ≠ declared** |
| LogAnalysis / AsusGuard | **8088** | 8089 (`config.py:35`, `dashboard/app.py:321`) | 8089 | **declared 8088 ≠ actual 8089** |
| AsusGuard daemon (harness) | 8088 | 8088 (`ASUSGUARD_PORT`) | n/a | OK (8088 = harness) |
| MagicMirror | 8080 | 8080 (`MM_PORT`) | 8080 | OK |

**Concrete issues:**

1. **OpenEye binds 8000 but registers 8200** — `backend/main.py:497` registers
   `service_port=PORT(8200)` while the server listens on
   `OPENEYE_PORT(8000)` (`main.py:956`) and builds self/webhook URLs from
   `OPENEYE_PORT` (`api/routes/ecosystem.py:197,1473,1843`). Health checks and
   peer calls to the registered 8200 fail when OpenEye is run standalone.
2. **`ecosystem.yaml` is stale** for OpenEye (8200 vs real 8000) and AsusGuard
   (8088 vs real 8089). The harness daemon legitimately uses 8088, so
   LogAnalysis's dashboard should be 8089 in the map.
3. **8000 three-way collision risk.** AFS *and* OpenEye both default to 8000 in
   their own code; co-located standalone they conflict. The map only avoids this
   because appEcosystem's `start_command` forces `--port 8200` for OpenEye — a
   coincidence that breaks the moment a user runs OpenEye directly.
4. **No single source of truth for the port.** `ecosystem_client/config.py`
   reads `ECOSYSTEM_SERVICE_PORT` (all repos, e.g. `config.py:41`), but every
   `main.py` passes an explicit `service_port` from a *different* var
   (`PORT`, `OPENEYE_PORT`, or a config file), so **`ECOSYSTEM_SERVICE_PORT` is
   effectively dead** and a user who sets it is ignored. This is exactly the
   "custom port not saved/associated" failure you flagged.

### 2.2 LLM Consistency & Resource Usage

**Provider posture per app:**

- **AFS** — full hub: Ollama (`OLLAMA_BASE_URL`, default `:11434`,
  `config.llm.ollama_base_url`), OpenAI, Anthropic, model selection
  (`selected_model`, `model_id`), and `tools/ecosystem_tools.py` that exposes
  discovered services as agent tools.
- **LogAnalysis** — Ollama (`services.ollama.url`, default `:11434`) with a
  configurable `services.ollama.models_dir` (falls back to `~/.ollama/...`).
- **OpenEye** — **Anthropic/Claude only**; no Ollama path.
- **MagicMirror** — multi-provider module (`ollama`/`openai`/`anthropic` with
  `*_api_key`), lightest integration.

**Issues:**

1. **No ecosystem-level LLM config.** `EcosystemConfig` carries
   `registry_url, hmac_secret, service_name, service_port, health_endpoint,
   peers` — **no LLM fields**. `appEcosystem/ecosystem.yaml` has no `llm:`
   section. So provider/host/model selection is per-app and must be set 4×; it
   never propagates. Directly contradicts the "select Ollama for AFS → used
   everywhere" goal.
2. **Model store not coordinated.** AFS pulls via the Ollama server
   (`/api/pull`, uses Ollama's own `~/.ollama` store); LogAnalysis reads a
   configurable `models_dir`. If both point at the *same* Ollama instance they
   already share one store — the natural dedup — but nothing enforces or
   documents this, so divergent hosts ⇒ duplicated multi-GB models.
3. **OpenEye can't join the local-LLM posture.** Its alerting is Claude-only,
   so a user standardizing on Ollama still incurs cloud calls (cost/privacy)
   for OpenEye unless an Ollama path is added.

### 2.3 Embedded Ecosystem Features & Standalone Operation

- **Good:** all four embed `ecosystem_client` + `ecosystem_auth`, use the
  `EcosystemConfig`/`DiscoveryManager` cascade, and have `standalone`/`fallback`
  branches (AFS 23/48, LogAnalysis 5/16, OpenEye 8/42, MM 4/18 files). The
  "facilitator-optional" design goal is met.
- **Risk:** the standalone↔registry switch keys off discovery, but because the
  *registered* port can be wrong (§2.1), "registry present" mode can be **worse**
  than standalone for OpenEye (peers get a dead 8200). Fixing ports is a
  prerequisite for trusting the facilitated mode.
- **Synergy gap (AFS↔LogAnalysis):** the appEcosystem `CommandRouter` already
  prefers the harness for security capabilities, but AFS's agent does not have a
  documented, first-class "ask LogAnalysis" tool flow for log/network triage;
  it relies on generic service discovery.

---

## 3. Remediation Plan

### Phase A — Port reconciliation (highest priority, mostly mechanical)
1. **One port variable.** Standardize every app on `ECOSYSTEM_SERVICE_PORT` as
   the single source of truth for *both* bind and register; keep the legacy var
   (`PORT`/`OPENEYE_PORT`) as a fallback only. Update each `main.py` to bind and
   register the same resolved value.
2. **Fix OpenEye bind≠register.** Make `backend/main.py` derive the registered
   `service_port` and the uvicorn bind port from the same resolved port; update
   `api/routes/ecosystem.py` self/webhook URLs to use it.
3. **Correct `appEcosystem/ecosystem.yaml`:** OpenEye → 8000 (or pick a
   non-colliding default and set it consistently), AsusGuard dashboard → 8089
   (leave the harness daemon on 8088). Document the canonical port map.
4. **Pick collision-free defaults:** AFS 8000, OpenEye 8200, LogAnalysis 8089,
   harness 8088, MagicMirror 8080, registry 8500 — and make each app *default*
   to its assigned port (not 8000).
5. **Add a `port-doctor`/preflight** (CLI in appEcosystem + per-app startup
   check) that detects a port already in use or a registered≠listening mismatch
   and logs/fails clearly.
6. **Tests:** each repo gets a `test_port_config` asserting bind==register and
   that `ECOSYSTEM_SERVICE_PORT` is honored (LogAnalysis already has one to
   model after).

### Phase B — Shared LLM profile
1. **Add an `llm:` section to `ecosystem.yaml`** (provider, `ollama_base_url`,
   default model per task class, optional `models_dir`) and expose it via a new
   registry endpoint `GET /llm-profile`.
2. **Extend `EcosystemConfig`** with `llm_provider`, `ollama_base_url`,
   `llm_model`, resolved in this precedence: explicit app config → ecosystem
   profile (when registry present) → app default. This makes "set it once in the
   profile, all apps follow" real, while preserving standalone defaults.
3. **Point all apps at one Ollama instance** by default (single model store);
   document `models_dir`/`OLLAMA_BASE_URL` so users can relocate the store to a
   large/local drive once and have every app reuse it.
4. **Add an Ollama path to OpenEye** alerting (provider-pluggable, Claude
   remains an option) so a local-only posture is achievable end-to-end.

### Phase C — AFS↔LogAnalysis synergy
1. **First-class log/network tools in AFS's agent** that call LogAnalysis
   (threat summary, recent anomalies, block IP) via discovery, mirroring the
   harness capability set already in appEcosystem's `CommandRouter`.
2. **Event-bus wiring:** LogAnalysis publishes `security.*` events; AFS
   subscribes and can summarize/triage with the shared LLM; OpenEye motion
   events can enrich LogAnalysis correlation.

### Phase D — Hardening parity
- Roll the appEcosystem v0.3.0 hardening (fail-closed secret, replay-resistant
  signing, loopback defaults, token TTL cap) through each embedded
  `ecosystem_client` copy so the members match the registry's verifier.
  *(These clients are vendored copies of the same library — they must be
  re-synced or the new signature scheme will fail against an upgraded registry.)*

---

## 4. Suggestions & Feature Ideas

**appEcosystem (facilitator):**
- **Canonical port + LLM profile registry** (`GET /llm-profile`,
  `GET /port-map`) as the single source of truth; members pull on startup.
- **Client library packaging** — publish `ecosystem_client` as one versioned
  package instead of vendored copies, so security fixes (Phase D) land
  everywhere at once. Add a CI check that flags drift between copies.
- **`ecosystem doctor`** command: cross-repo preflight (ports free,
  registered==listening, Ollama reachable, secret not default, client version).
- **Capability catalog**: aggregate each member's declared capabilities so the
  AFS agent gets a single, typed tool manifest.

**Member apps:**
- **Unified model manager** (shared Ollama + one `models_dir` on a user-chosen
  drive) with a small UI to pick provider/model once, ecosystem-wide.
- **Graceful degradation matrix** documented per app (what still works with no
  registry / no Ollama / no cloud key).
- **OpenEye → LogAnalysis** feed: surveillance events as a correlation source
  for SIEM; **AFS → all**: natural-language "what happened on my network/
  cameras last night" answered by orchestrating LogAnalysis + OpenEye + LLM.
- **Resource budget signals** on the event bus (CPU/RAM/GPU/VRAM) so the
  facilitator can place LLM load on the best host and avoid oversubscription.

---

*Report by Smart Industries LLC.*
