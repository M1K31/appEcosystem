# Ecosystem Publishing & Third‑Party Onboarding Plan

> Supersedes and expands `walkthrough.md`. Goal: publish the shared SDKs **and** let
> third parties register their own apps into the ecosystem — **without** weakening the
> security or breaking the functionality of the existing first‑party apps
> (appEcosystem registry, OpenEye, AI‑for‑Survival, AegisSIEM/LogAnalysis, MagicMirror,
> cyber‑claude‑agents daemon).

---

## Part 0 — Why the first publishing attempt was rolled back

The initial `walkthrough.md` run made three problems that we reverted:

1. **Deleted app‑owned code as if it were vendored.** It removed
   `AI-for-Survival/backend/src/auth/{auth.py,system_auth.py,__init__.py}` — that is
   AFS's *own* application auth (JWT persistence, `dscl` OS‑recovery, `get_current_admin_user`),
   not a vendored copy of `ecosystem_auth`. Deleting it breaks AFS login entirely.
2. **Repointed downstream installs to packages that don't exist yet.** Editing the four
   downstream dependency files to fetch `@smartindustriesllc/*` / PyPI dists *before*
   publishing means every fresh install and CI run fails until upload succeeds — and
   there's no fallback if a name is taken or a token is wrong.
3. **Changed distribution without changing the trust model.** Publishing the SDK does
   not, by itself, make third‑party participation safe. The registry still trusts a
   single shared secret (see Part B).

**Principle going forward:** distribution (Part A) and trust (Part B) are separate
efforts. Publish behind fallbacks so nothing breaks; open the trust model deliberately.

---

## Part A — Publish the shared SDKs (distribution) safely

### A.1 Package inventory (6)

| Package | Ecosystem | Registry name (proposed) |
|---|---|---|
| `packages/ecosystem-client` | PyPI | `smartindustriesllc-ecosystem-client` |
| `packages/ecosystem-ai` | PyPI | `smartindustriesllc-ecosystem-ai` |
| `auth/python` | PyPI | `smartindustriesllc-ecosystem-auth` |
| `ecosystem_client_js` | npm | `@smartindustriesllc/ecosystem-client` |
| `auth/js` | npm | `@smartindustriesllc/ecosystem-auth` |
| `theme` | npm | `@smartindustriesllc/ecosystem-theme` |

### A.2 Ordering rule (non‑negotiable)

1. **Reserve/verify names first.** `pip index versions <name>` / `npm view <name>` — confirm
   each name is free or owned by Smart Industries LLC. Register the npm `@smartindustriesllc`
   org and PyPI project owners before uploading.
2. **Build + validate** (`python -m build`, `twine check`, `npm pack`) into `dist/` — but
   keep `dist/`, `build/`, `*.egg-info`, `*.tgz` **git‑ignored** (they leaked into the tree
   last time).
3. **Publish to a test index first**: TestPyPI + an npm `--dry-run`/`--tag next`. Install
   from the test index into a scratch venv to prove importability.
4. **Publish to prod.** Only now do the downstream repoint (A.4).

### A.3 Do NOT delete app‑owned code

Only remove a vendored directory once its published replacement imports cleanly, and only
if it is genuinely a *copy* of the shared package. Confirmed classifications:

- **Vendored (safe to remove after publish):** `MagicMirror-Custom/js/ecosystem-client/`,
  `MagicMirror-Custom/js/ecosystem-auth/` — copies of the shared JS client/auth.
- **App‑owned (never remove):** `AI-for-Survival/backend/src/auth/**` — AFS's own auth.
  (OpenEye/AegisSIEM import `ecosystem_auth`/`ecosystem_client` as packages already; verify
  each has no app code under a same‑named path before touching anything.)

### A.4 Downstream repoint — behind a fallback

For each downstream app, depend on the published package **with a source fallback** so a
from‑checkout dev install still works and CI isn't hostage to the index:

- **Python** (`requirements.txt` / `pyproject.toml`): pin `>=0.1,<0.2`, but keep the existing
  installers' behavior of `pip install <local path>` when `ECOSYSTEM_BASE_PATH` is set (the
  AFS/OpenEye/AegisSIEM `install-local.sh` already do this — leave that path intact as the
  offline/dev route).
- **npm** (`package.json`): depend on `@smartindustriesllc/ecosystem-client@^0.1`, keeping a
  documented `npm link` path for local development.
- **Version pin discipline:** semver; a downstream app pins a caret range, never `*`.

### A.5 Publishing hygiene

- Per‑package `LICENSE` (MIT) + `README` are fine — but generate them into the package dir
  and **commit them intentionally**, don't leave them as stray untracked artifacts.
- Add `provenance`/`--provenance` (npm) and PyPI Trusted Publishing (OIDC via GitHub Actions)
  so tokens don't live on a laptop. Replace the `export TWINE_PASSWORD=…` step in
  `walkthrough.md` with a `release.yml` workflow gated on a tag.
- `.gitignore` additions per package: `dist/ build/ *.egg-info/ *.tgz`.

**Deliverable of Part A:** the SDKs are installable by anyone via PyPI/npm, and every
first‑party app still installs and runs unchanged (published dep OR local fallback).

---

## Part B — Open the trust model (the real third‑party enabler)

### B.1 Where we are today

Every registry **write** — `POST /register`, `DELETE /deregister/{name}`,
`POST /events/publish`, `PUT /ai-profile` — is gated by `require_ecosystem_auth`
(`registry/app.py`), which is **HMAC‑SHA256 over a single symmetric secret** in
`~/.config/ecosystem/secret.env` (`sign_request`/`verify_request` in `ecosystem_auth`,
carrying `X-Ecosystem-Signature/Timestamp/Nonce`). Reads are gated by an optional
`require_read_auth`.

This is correct for **one household, one owner**. It is unsafe to hand to a third party,
because that one secret grants the power to:
- impersonate any existing service (register/heartbeat as `openeye`),
- **deregister** your services,
- **rewrite the shared AI profile** (trust‑critical — same class of gap we already closed
  in AFS's `/ecosystem/secret` endpoints),
- forge security events consumed by AegisSIEM / MagicMirror,
- and it cannot be revoked for one app without rotating for all.

### B.2 Target model — per‑app identity + enrollment + scopes

Introduce **per‑app credentials** and an **enrollment** step, keeping the existing HMAC
envelope (so first‑party apps keep working) but keying it per app.

**Data model (registry side):**
```
App {
  app_id            # stable id, e.g. "org.acme.thermostat"
  display_name
  owner             # "first-party" | third-party contact
  key_id            # header the client sends
  secret_or_pubkey  # Phase 1: shared HMAC secret per app; Phase 3: Ed25519 public key
  owned_names[]     # service names this app may register/heartbeat/deregister
  scopes[]          # e.g. register:self, events:publish:<topic>, ai-profile:read
  status            # pending | approved | suspended
  rate_limit
  created_at, approved_at
}
```

**Request auth becomes:** client sends `X-Ecosystem-Key-Id: <key_id>` alongside the existing
signature headers; `require_ecosystem_auth` looks up that app's key, verifies the HMAC
against it, then enforces scopes + name ownership. **The existing single‑secret path stays
as the "first‑party/owner" identity during migration** so nothing breaks.

### B.3 Enrollment / pairing flow (mirrors the TOFU‑approve pattern you already use)

1. Owner runs `ecosystem apps invite --name "Acme Thermostat"` → registry mints a **one‑time
   enrollment token** (short TTL).
2. Third‑party app calls `POST /enroll` with the token + a **manifest** (name request,
   version, health endpoint, capabilities, event topics produced/consumed) → receives its
   `key_id` + secret (Phase 1) or registers its public key (Phase 3). Status = `pending`.
3. Owner approves in the CLI / a small admin page (`ecosystem apps approve <app_id>`), like
   the router‑trust and honeypot‑approval flows already in the ecosystem. Only then can the
   app perform writes.
4. Revocation: `ecosystem apps suspend <app_id>` flips status; that app's key stops
   verifying immediately — **no global rotation**.

### B.4 Name ownership + scopes (least privilege)

- Bind `app_id ↔ owned_names` at approval. An app may only `register`/`heartbeat`/`deregister`
  a name it owns. First‑party names (`openeye`, `aegissiem`, `aegissiem_daemon`,
  `ai_for_survival`, `magicmirror`, `registry`) are **reserved**.
- Scope the trust‑critical writes: `PUT /ai-profile` and secret rotation remain
  **owner/admin + loopback‑only** (reuse the exact `get_current_admin_user` + loopback
  pattern we shipped for AFS's `/ecosystem/secret`). Third‑party apps get `ai-profile:read`
  at most.
- Event publishing is **topic‑scoped**: an app declares topics in its manifest; the registry
  only accepts `events:publish:<topic>` it was granted. Consumers subscribe by topic.

### B.5 Membership: static `ecosystem.yaml` vs dynamic enrollment

- Keep `ecosystem.yaml` for **your locally‑managed** apps (drives `start-all`, pre‑registration,
  health ports) — unchanged, so the current fleet behaves exactly as now.
- Third parties are **not** added to `ecosystem.yaml`; they join at runtime via enrollment and
  live only in the registry's App/Service store. This is what makes it "open" without editing
  a first‑party config file.

### B.6 Hardening required before untrusted members exist

- **SSRF fix (important):** the health monitor currently polls whatever URL a registrant
  supplies. Restrict health polling to the host:port the app enrolled with, block RFC‑1918/loopback
  targets for third‑party apps, and cap redirects/timeouts. (First‑party apps on the LAN are
  exempt by policy.)
- **Per‑app rate limits** on register/heartbeat/publish; global backpressure.
- **Event payload validation**: JSON‑schema per topic + size caps; reject unknown topics.
- **Audit log** of all writes (who/app_id, what, when) — feeds naturally into AegisSIEM.
- **Fail‑closed** everywhere (already the ecosystem's convention): missing/invalid key → 401,
  never a silent allow.
- **Never log secrets** (we already redacted webhook URLs in OpenEye — apply the same rule to
  enrollment tokens and app secrets).

### B.7 Phasing

- **Phase 1 (MVP third‑party) — ✅ DELIVERED (2026‑07‑11).** Per‑app HMAC keys, owner‑CLI
  provisioning (`ecosystem partner add|list|show|suspend|resume|remove`), name‑ownership binding,
  reserved first‑party names, and immediate `suspend`/`remove` revocation (AppStore live‑reloads,
  so no registry restart needed). The existing shared secret is grandfathered as the privileged
  `__owner__` identity, so all first‑party apps keep working unchanged; `PUT /ai-profile` is
  owner‑only. Spec: `docs/superpowers/specs/2026-07-10-per-app-auth-enrollment-design.md`; plan:
  `docs/superpowers/plans/2026-07-11-per-app-auth-enrollment.md`. → *A third party can now safely join.*
  - **Chosen for Phase 1:** owner‑CLI provisioning (Approach A) rather than self‑service `/enroll`;
    the HTTP `/enroll` + invite‑token flow moves to Phase 2.
- **Phase 1.5 (follow‑up):** migrate first‑party apps (openeye, aegissiem, aegissiem_daemon,
  ai_for_survival, magicmirror) to their own per‑app keys and retire the grandfathered shared‑secret
  owner for day‑to‑day writes, once the flow is proven.
- **Phase 2:** self‑service `POST /enroll` + one‑time invite tokens + `pending→approved` state;
  scopes beyond `register:self` + topic‑scoped events + per‑topic JSON schemas; per‑app rate limits;
  the SSRF fix on health polling; write audit log; admin page.
- **Phase 3:** asymmetric keys (Ed25519; registry stores only public keys — secrets never
  travel), topic ACLs, and an app **catalog** (discover third‑party apps + their capabilities),
  optional signed‑manifest / review process.

---

## Part C — Third‑party developer experience

- **SDK:** the published `ecosystem-client` (py + js) gains an `enroll()` + `register()`
  quickstart; a third‑party app should reach "registered + heartbeating" in <20 lines.
- **Manifest schema:** documented JSON (`name`, `version`, `health_endpoint`, `capabilities`,
  `events_produced`, `events_consumed`, `contact`).
- **Published contract:** registry OpenAPI spec + documented, versioned event schemas.
- **"Build an ecosystem app" guide:** enroll → await approval → register → heartbeat →
  discover peers → publish/subscribe events. Include a runnable **example app** and a
  **sandbox** registry mode for local development.
- **Compatibility policy:** semver on SDKs; event schema versioning; deprecation windows.

---

## Part D — Invariants that must hold throughout

1. Existing apps keep working with **zero required changes** at each step (fallbacks + auto‑provisioned
   first‑party identity).
2. Trust‑critical operations (secret rotation, `PUT /ai-profile`) stay **admin + loopback‑only**
   (the AFS pattern), never reachable by a third‑party key.
3. No secret/token is ever logged; all writes are authenticated and audited; auth fails closed.
4. `ecosystem.yaml` remains the source of truth for the first‑party fleet; third parties never
   appear there.

---

## Suggested execution order

1. **Part A** publishing (behind fallbacks) — ship the SDKs; prove every first‑party app still
   installs/runs. *No trust changes yet.*
2. **Phase 1** of Part B — per‑app keys + enrollment + name binding, with first‑party
   auto‑provisioning. Ship the CLI (`ecosystem apps invite|approve|suspend|list`).
3. **Phase 2** — scopes, event schemas, rate limits, SSRF fix, audit log, admin page.
4. **Part C** developer guide + example app + sandbox (can overlap Phase 2).
5. **Phase 3** — asymmetric keys + catalog.

Each of steps 1–5 is its own spec → plan → implementation cycle (same flow used for the
OpenEye automation feature). Phase 1 is the minimum that satisfies "third parties can add
their apps" while preserving current functionality and security.

## Risks / watch‑items

- **Name squatting** on PyPI/npm — reserve immediately.
- **Downstream breakage window** — never repoint deps before the package is live and
  install‑verified; keep the local‑path fallback.
- **SSRF via health polling** — must land before any untrusted app can enroll.
- **AI‑profile as a shared‑trust surface** — keep it owner‑only; a bad third‑party write here
  would poison model selection ecosystem‑wide.
- **Migration ordering** — provision first‑party app identities from the existing secret in the
  same release that introduces per‑app keys, so there is never a window where the current apps
  can't authenticate.
