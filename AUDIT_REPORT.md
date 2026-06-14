# appEcosystem — Comprehensive Audit Report

**Prepared for:** Smart Industries LLC
**Date:** 2026-06-14
**Scope:** `/Volumes/Locker2/GitHub/appEcosystem` @ `main` (213df29)
**Method:** Line-by-line review of all 84 tracked files (~5,800 LOC Python/JS/CSS/Bash). Test suite executed: **92 passed in 1.59s.**

---

## Executive Summary

appEcosystem is a well-structured, lightweight coordination layer (FastAPI registry + HMAC auth + webhook event bus + mDNS discovery + LLM command router + CLI/launchd/systemd lifecycle). Code quality is generally high: clean module boundaries, Pydantic models, async throughout, parity Python/JS auth libs, and a full passing test suite. The Phase 1–4 remediation work logged in `todos_changelog.md` is real and mostly landed.

However, **three changelog items marked `[RESOLVED]` are only partially implemented**, and there is **one installer that is broken on every run**. The highest-priority risks are all in the trust model: a known default shared secret, an unauthenticated control plane bound to `0.0.0.0`, and replay protection that exists for *tokens* but not for the *signature-header* request path.

**Severity tally:** 1 Critical (broken systemd installer), 4 High (secret default, CORS+bind exposure, unauth read endpoints, replay gap), ~8 Medium, several Low/quality.

### Top 5 — fix before any user-facing deployment
1. **[CRITICAL]** `scripts/install_systemd.sh:66` — orphan `EOF` aborts the installer (exit 127).
2. **[HIGH]** Known default secret `dev-ecosystem-secret-change-in-production` fallback in 5 locations; no fail-closed boot check.
3. **[HIGH]** Registry binds `0.0.0.0:8500` with wildcard CORS and **unauthenticated** `/services*` read endpoints → LAN topology disclosure.
4. **[HIGH]** Replay protection gap: the `X-Ecosystem-Signature` path signs no timestamp/nonce window; events carry a timestamp but no receiver enforces it.
5. **[HIGH/Quality]** Changelog drift — SIGKILL escalation and connection pooling claimed `[RESOLVED]` are missing from `ecosystem stop-all` and `CommandRouter` respectively.

---

## Phase 1 — Deep Code Review & Security Audit

### 1.1 Secrets & Data Exposure
- **[HIGH] Hardcoded default secret in 5 places** — `auth/python/ecosystem_auth/middleware.py:16`, `llm/command_router.py:41`, `events/event_bus.py:35`, `auth/js/src/middleware.js:13`, `ecosystem.yaml:12`. If `ECOSYSTEM_HMAC_SECRET` is unset, the entire inter-service trust model collapses to a publicly known key. There is **no startup guard** that refuses to boot on the default.
  ```python
  # auth/python/ecosystem_auth/middleware.py — fail closed
  _DEFAULT = "dev-ecosystem-secret-change-in-production"
  def get_ecosystem_secret() -> str:
      secret = os.environ.get("ECOSYSTEM_HMAC_SECRET", _DEFAULT)
      if secret == _DEFAULT and os.environ.get("ECOSYSTEM_ENV", "dev") != "dev":
          raise RuntimeError("Refusing to start: ECOSYSTEM_HMAC_SECRET is the insecure default.")
      return secret
  ```
- **[MEDIUM] `.env.example` is whitelisted in `.gitignore:27` but does not exist.** Operators get no template and silently fall back to the insecure default. Add one (see Phase 5).
- **Good:** No real secrets, API keys, or PII committed. `.env*` ignored, `data/` and `*.json` ignored. `base_path: /Volumes/Locker2/GitHub` in `ecosystem.yaml:7` leaks a developer-specific absolute path — move to env/relative.

### 1.2 Cybersecurity
- **[HIGH] Unauthenticated control plane on all interfaces.** `cmd_start` (`cli/commands.py:105`), the launchd plist (`cli/commands.py:300`), and systemd (`scripts/install_systemd.sh:42`) all bind `--host 0.0.0.0`. `/services`, `/services/{name}`, `/services/{name}/health` (`registry/app.py:109-137`) have **no `Depends(require_ecosystem_auth)`**, exposing host/port/stack topology to anyone on the LAN (also advertised via mDNS). Bind to `127.0.0.1` by default, or auth the read endpoints, or front with a firewall ACL.
- **[HIGH] Wildcard CORS on an authenticated service** — `registry/app.py:74-79` sets `allow_origins/methods/headers=["*"]`. Restrict to known origins; never pair `*` with credentials.
- **[HIGH] Replay protection gap (changelog overstated).** The Bearer-*token* path was correctly hardened (token value now bound into the signature, `auth/python/ecosystem_auth/tokens.py:62`). But the **signature-header path** signs only `{"url","method"}` for GET/DELETE or the raw body for POST (`middleware.py:32-51`, `auth/js/src/middleware.js:33-52`) — **no timestamp or nonce**, so any captured signed request replays forever. Events *do* carry `id`+`timestamp` in `signable_dict()` (`events/schemas.py:32`) but **no receiver enforces a freshness window or de-dupes the id**. Add a signed `ts`, reject `abs(now-ts) > 300s`, and keep an LRU of seen `id`/nonce.
- **[MEDIUM] Path-param injection** — `CommandRouter._execute` (`llm/command_router.py:109-111`) substitutes LLM-supplied `path_params` via raw `str.replace` with no encoding. A value like `../admin` enables path traversal against the target service. Use `urllib.parse.quote(value, safe="")`.
- **[MEDIUM] Signature canonicalization fragility** — client signs `{"url": base_url+path}` (`command_router.py:118`) while the server verifies `str(request.url)` (`middleware.py:37`), which includes query string and host normalization. Mismatch → fails closed (good) but brittle across proxies/interfaces, and query params are outside the signed surface. Define one canonical form (method + path + sorted query + body hash + ts).
- **[LOW] No injection/XSS surface of note** (no SQL, no template HTML rendering server-side). `yaml.safe_load` used correctly (`cli/commands.py:29`, `registry/app.py:149`).

### 1.3 Code Quality / SOLID
- **[MEDIUM] Module-level singletons typed `= None`** in `registry/app.py:24-26` are dereferenced directly in handlers (`registry.register`, etc.). A request arriving before `lifespan` finishes → `AttributeError`. Use `app.state` or a dependency provider.
- **[MEDIUM] Duplicated secret-resolution logic** across 4 modules (DRY/SOLID). `CommandRouter` and `EventBus` reimplement the env lookup instead of importing `get_ecosystem_secret()`.
- **[LOW] `_register_static_projects` swallows all exceptions** (`registry/app.py:163`) and uses `proj["port"]` (KeyError aborts the whole load). Validate per-project, log per-project.
- **[LOW] `install.sh:27`** `pip install ... 2>/dev/null || pip install -e .` hides the real failure reason.

### 1.4 Optimization / Dead Code
- **[MEDIUM] Connection pooling NOT applied to `CommandRouter`** (changelog claims pooling `[RESOLVED]`). `EventBus`/`HealthMonitor` use a persistent `self._client`, but `CommandRouter._execute/_harness_available/_route_via_harness` (`command_router.py:124,146,159`) still create a fresh `httpx.AsyncClient()` per call in the hot path. Promote to a shared client with `aclose()` on shutdown.
- **[LOW] Config drift** — `CommandRouter._HARNESS_BASE_URL` (`command_router.py:32`) hardcodes `localhost` + `ASUSGUARD_PORT`, ignoring `ecosystem.yaml:cyber_harness.daemon_url`. Single source of truth needed.

### 1.5 Infrastructure / Longevity
- **[MEDIUM] Aggressive auto-deregistration** — `HealthMonitor._poll_loop` permanently deregisters a service after `max_failures` (`health_monitor.py:129-150`). A transient blip evicts it until it re-registers; statically pre-registered projects never re-add themselves. Prefer marking `UNHEALTHY` + backoff over deletion, or auto-re-seed statics.
- **[LOW] PID-file collision** — `cli.cmd_start` writes the uvicorn PID and `scripts/process_manager.py:136` writes the *supervisor* PID to the same `data/registry.pid`. `ecosystem start` and systemd-via-supervisor disagree on what the PID means.

---

## Phase 2 — Dependency & Framework Health
- **No lockfiles / floor-only pins.** `pyproject.toml:10-17` uses `>=` with no upper bounds; `package-lock.json` is whitelisted in `.gitignore` but absent. Builds are non-reproducible. Commit lockfiles; add Dependabot/Renovate.
- **No automated audit.** Add `pip-audit` and `npm audit --omit=dev` to CI. Current stack (FastAPI ≥0.100, uvicorn, httpx, pydantic v2, pyyaml, zeroconf) has no known critical CVEs at these floors, but `zeroconf` is network-facing — pin and track.
- **Deprecated pattern:** wildcard `CORSMiddleware` (see 1.2). No deprecated FastAPI/Pydantic-v1 APIs detected — lifespan + Pydantic v2 are current.

## Phase 3 — UI/UX & Apple HIG
**Strengths:** `theme/ecosystem-theme.css` is a clean token system — 8pt grid (`--spacing-*`), `--touch-target-min: 44px` (applied in `demo.html:67,205`), light/dark/cyberpunk via `[data-theme]`, HSL palette, Out-Quint easing.

**Gaps:**
- **[MEDIUM] No `@media (prefers-reduced-motion: reduce)`** — animations always on (WCAG 2.3.3 / HIG reduce-motion fail). Wrap transitions.
- **[MEDIUM] No `@media (prefers-color-scheme)`** — theme only flips via JS attribute, risking a first-paint flash and ignoring OS preference. Seed `:root` defaults from the media query.
- **[MEDIUM] No `:focus-visible` styles** — only `a:hover { filter }` (`ecosystem-theme.css:161`). Keyboard users get no focus indicator (WCAG 2.4.7).
- **[MEDIUM] Cyberpunk contrast** — neon-on-near-black (cyan `hsl(180,100%,50%)`, magenta, yellow, `ecosystem-theme.css:110-120`) almost certainly fails WCAG AA 4.5:1. Verify and adjust luminance.
- **[LOW] Google Fonts `@import`** (`ecosystem-theme.css:7`) is render-blocking + external (privacy/offline concern, esp. MagicMirror HUD). Self-host with `font-display: swap`.

Suggested additions:
```css
@media (prefers-reduced-motion: reduce){*,*::before,*::after{transition:none!important;animation:none!important}}
@media (prefers-color-scheme: light){:root:not([data-theme]){/* light token overrides */}}
:focus-visible{outline:2px solid var(--color-accent);outline-offset:2px}
```

## Phase 4 — DevOps, Lifecycle & Memory
- **[CRITICAL] `scripts/install_systemd.sh:66`** — a stray `EOF` (orphan heredoc terminator) is executed as a command; under `set -euo pipefail` the installer exits 127 ("EOF: command not found") **every run**. **Fix: delete line 66.**
- **[HIGH] SIGKILL escalation missing from the CLI.** Changelog claims escalation `[RESOLVED]`; it exists only in `process_manager.py:70-87`. `cmd_stop_all` (`cli/commands.py:236`) sends bare `SIGTERM` with no grace-poll or SIGKILL, so `ecosystem stop-all` can leave hung processes. Route CLI stops through the supervisor or replicate the escalation.
- **[MEDIUM] macOS/Linux parity gap.** Linux systemd wraps uvicorn in `process_manager.py` (good); the launchd plist (`cli/commands.py:294-304`) runs uvicorn directly — no process-group cleanup or SIGKILL escalation on macOS.
- **[MEDIUM] Missing `restart` and `monitor` subcommands.** Phase 4 requires start/stop/**restart**/**monitor**; `cli/main.py` ships start, stop, start-all, stop-all, status, logs, install, uninstall — no `restart`/`monitor`.
- **`process_manager.py` is otherwise solid:** SIGINT/SIGTERM trap, `shlex.split`, `start_new_session` process group, 5s grace poll → SIGKILL, PID cleanup. Good reference implementation.
- **venv:** `install.sh` creates/reuses `.venv` correctly and `.venv/` is gitignored. Document `pip install -e .` for client-only installs.

## Phase 5 — Documentation
`README.md`, `usage.md`, `todos_changelog.md` all exist and are solid. Required actions:
1. **Reconcile `todos_changelog.md`** — un-mark or footnote the three partial items: replay protection (signature path), SIGKILL escalation (CLI), connection pooling (CommandRouter).
2. **Add `.env.example`** documenting `ECOSYSTEM_HMAC_SECRET`, `ECOSYSTEM_ENV`, `ECOSYSTEM_REGISTRY_FILE`, `ECOSYSTEM_HEALTH_INTERVAL`, `ASUSGUARD_PORT`.
3. **No inline `TODO`/`FIXME` found** in source — the tracker is the single source; keep it accurate.

## Phase 6 — Production Readiness Roadmap
1. **Harden (gate):** fail-closed secret check; bind `127.0.0.1` or auth read endpoints + scope CORS; add ts+nonce replay window; fix `install_systemd.sh`; add CLI SIGKILL escalation + `restart`/`monitor`.
2. **CI/CD:** GitHub Actions matrix (py3.10–3.12) → `pytest`, `ruff`, `pip-audit`, `npm audit`, shellcheck on `scripts/*.sh`; block merge on failure. Commit lockfiles.
3. **Testing thresholds:** unit coverage ≥80% (add tests for replay rejection, auth failure paths, path-param encoding); E2E smoke: start registry → register → publish event → verify delivery.
4. **Infra/scaling:** Dockerfile + compose for the registry; health/readiness probes; the registry is in-memory+JSON — document single-instance constraint or move to Redis/SQLite for HA.
5. **Observability:** structured JSON logging, `/metrics` (Prometheus) for health-poll outcomes and event delivery success/fail, request tracing via `correlation_id` (already in `EventEnvelope`).
6. **Rollout:** alpha on one node (loopback) → beta on LAN with real secret + firewall → staged enablement of `cyber_harness`; document rollback (`ecosystem uninstall` + systemd disable).

---
*Report by Smart Industries LLC.*
