# Per-App Credentials + Name Ownership — Design (Phase 1)

**Date:** 2026-07-10 · **Status:** Approved (design) · **Repo:** appEcosystem
**Parent:** `ECOSYSTEM_OPENING_PLAN.md` Part B, Phase 1 (Part A publishing deferred).

## Problem

Every registry **write** — `POST /register`, `DELETE /deregister/{name}`, `PUT /ai-profile`
— is gated by `require_ecosystem_auth`, which verifies an HMAC-SHA256
signature against a **single shared secret** (`~/.config/ecosystem/secret.env`, resolved by
`ecosystem_auth.tokens.get_ecosystem_secret`). Any holder of that secret can impersonate any
service, deregister others, and rewrite the shared AI profile; there is no per-app identity and
no way to revoke one participant without rotating for all. This is safe for one owner but cannot
be handed to a third party.

**Goal (Phase 1):** give third-party apps their own credentials and bind each to the service
names it may manage, **without changing how the existing first-party apps authenticate**.

## Decisions (from brainstorming)

1. **Hybrid migration.** The existing shared secret stays valid and is treated as a privileged
   **owner** identity. Existing first-party apps (openeye, aegissiem, aegissiem_daemon,
   ai_for_survival, magicmirror, the daemon) change nothing. Only new third-party apps get
   per-app keys. First-party per-app migration is a logged follow-up, not built now.
2. **Provisioning: owner CLI (Approach A).** The owner runs `ecosystem apps add …` to mint a
   credential and hand it to the third party out-of-band. No HTTP `/enroll` endpoint or
   invite-token/approval state machine in Phase 1 (records are born `approved`; `suspend` is the
   revocation lever). Self-service `/enroll` is a logged Phase-2 follow-up.
3. **Storage: JSON file** matching the existing `ProfileStore` pattern — no new dependency, no
   SQLite (the registry uses JSON files throughout).
4. **Credential type: per-app symmetric HMAC secret.** Verification needs the raw secret, so the
   registry stores it (0600), same trust level as `secret.env` today. Asymmetric keys (registry
   stores only public keys) are Phase 3.

## Architecture

### Component 1 — `AppStore` (`registry/app_store.py`, new)

In-memory dict + JSON persistence, mirroring `registry/profile_store.py`.

- **Path:** `ECOSYSTEM_APPS_FILE` env, else `~/.config/ecosystem/apps.json`. Written `0600`
  (contains secrets — stricter than `data/registry.json`). Atomic write (temp + `os.replace`).
- **Record:**
  ```
  App {
    app_id: str          # stable, e.g. "org.acme.thermostat"; unique
    key_id: str          # opaque random (secrets.token_urlsafe(12)); sent in X-Ecosystem-Key-Id; unique
    secret: str          # per-app HMAC secret, secrets.token_urlsafe(32)
    display_name: str
    owner: str           # contact string
    owned_names: list[str]   # service names this app may register/heartbeat/deregister
    scopes: list[str]        # Phase 1 third-party default: ["register:self"]
    status: str          # "approved" | "suspended"  (no "pending" in Phase 1)
    created_at: str      # ISO8601
    approved_at: str     # ISO8601 (== created_at in Phase 1)
  }
  ```
- **API:**
  - `add(app_id, display_name, owner, owned_names, scopes=None) -> (record, secret)` — generates
    key_id + secret, persists (status `approved`), returns the record and the **raw secret once**.
  - `get_by_key_id(key_id) -> App | None`
  - `get(app_id) -> App | None`
  - `list() -> list[App]` (records without secrets for display)
  - `set_status(app_id, status)` / `remove(app_id)`
  - `all_owned_names() -> set[str]` (for collision checks)
- **Load tolerance:** missing/corrupt file → empty store, logged warning, never raises (only the
  grandfathered owner works until fixed).
- **Reserved names constant** (module-level): `{"registry", "openeye", "aegissiem",
  "aegissiem_daemon", "ai_for_survival", "magicmirror"}`.

### Component 2 — Auth resolver in `ecosystem_auth.middleware`

`require_ecosystem_auth` gains an optional **key resolver** so the package stays generic and
backward compatible; the registry injects the resolver, other apps don't.

- New header constant `KEY_ID_HEADER = "X-Ecosystem-Key-Id"` in `tokens.py`.
- `sign_request(..., key_id: str | None = None)` — when given, adds the `X-Ecosystem-Key-Id`
  header to the returned headers. Canonical signed payload is **unchanged** (existing signatures
  stay valid).
- `require_ecosystem_auth(request, credentials, key_resolver=None)`:
  - If `X-Ecosystem-Key-Id` present **and** `key_resolver` provided:
    `principal = key_resolver(key_id)`. If `None` (unknown/suspended) → **401**. Else verify HMAC
    against `principal.secret`; on success return
    `{"auth_method": "hmac", "app_id": principal.app_id, "scopes": principal.scopes,
       "owned_names": principal.owned_names}`.
  - Else (no key id, or no resolver): verify against the shared secret exactly as today; return
    the **owner principal**: `{"auth_method": "hmac", "app_id": "__owner__", "scopes": ["*"],
    "owned_names": ["*"]}`.
  - Bearer-token path unchanged.
  - Nonce/timestamp replay protection applies to both paths (unchanged `_nonce_store`).
- The registry wires it via a thin dependency (`registry/auth.py` or inline in `app.py`) that
  builds `key_resolver` from `AppStore.get_by_key_id`, skipping `suspended` records.

### Component 3 — Route enforcement (`registry/app.py`)

A small helper `require_name_owner(name, auth)`:
- `auth["owned_names"] == ["*"]` (owner) → allow any name.
- name in `RESERVED_NAMES` and caller not owner → **403**.
- name in `auth["owned_names"]` → allow; else **403** (`"app '<app_id>' does not own service
  name '<name>'"`).

The registry's write routes are exactly: `POST /register`, `DELETE /deregister/{name}`,
`PUT /ai-profile`. **Heartbeat is a re-POST to `/register`** (registration upsert — there is no
separate heartbeat route), so the `/register` check covers it. There is **no external
`/events/publish` HTTP route** in the registry — event publishing is internal (the registry emits
`ecosystem.ai_profile_changed` from within `PUT /ai-profile`), so there is no third-party publish
surface to gate in Phase 1.

Apply enforcement to:
- `POST /register` — `require_name_owner(registration.name, auth)`. Covers heartbeat.
- `DELETE /deregister/{name}` — `require_name_owner(name, auth)`.
- `PUT /ai-profile` — **owner-only**: if `auth["app_id"] != "__owner__"` → **403** (trust-critical
  surface stays closed to third parties in Phase 1). `updated_by` now uses `auth["app_id"]`
  (was `auth.get("service")` → "unknown").

### Component 4 — CLI (`cli/commands.py`, `ecosystem apps …`)

Owner-run subcommands (joins the existing `secret`/`apps`/service command family):
- `ecosystem apps add <app_id> --name <display> --owner <contact> --service-names a,b`
  → `AppStore.add(...)`, prints key_id + secret **once** (like `secret generate`), never re-shown.
  Rejects `--service-names` that hit `RESERVED_NAMES` or collide with another app's `owned_names`.
- `ecosystem apps list` — table: app_id, name, status, owned_names, created (no secrets).
- `ecosystem apps show <app_id>` — metadata only, never the secret.
- `ecosystem apps suspend <app_id>` / `resume <app_id>` — flip status (immediate effect).
- `ecosystem apps remove <app_id>` — delete record (hard revocation).

## Data flow (third-party register)

1. Owner: `ecosystem apps add org.acme.thermostat --name "Acme" --owner dev@acme --service-names acme_thermostat` → key_id + secret printed once.
2. Third-party app signs `POST /register {name: "acme_thermostat", …}` with its secret + `X-Ecosystem-Key-Id: <key_id>`.
3. Registry resolver finds the (approved) app → verifies HMAC → principal has `owned_names=["acme_thermostat"]`.
4. `require_name_owner("acme_thermostat", auth)` passes → service registered.
5. `POST /register {name: "openeye"}` from the same key → 403 (reserved). Suspended key → 401.

## Error handling

- Unknown / suspended key_id → **401** ("Invalid or unknown ecosystem key").
- Valid key, unowned name → **403**. Reserved name by non-owner → **403**.
- Corrupt/missing `apps.json` → empty store, warning logged, owner path still works.
- Secrets (per-app + shared) never logged. CLI prints a secret exactly once on `add`.
- Fail-closed: any resolver/verify ambiguity → 401.

## Testing

- **AppStore** (`registry/tests`): add→list→suspend→remove roundtrip; secret returned once and
  persisted; 0600 perms; atomic write; corrupt-file tolerance → empty store; reserved/collision
  rejection in `add`.
- **Auth resolver** (`auth/python` tests): enrolled key valid → principal; suspended/unknown →
  401; absent header → `__owner__` principal (grandfather); app A's signature under app B's
  key_id → 401 (secret isolation); `sign_request` without `key_id` produces byte-identical
  headers to today (back-compat).
- **Route enforcement** (`registry/tests`): enrolled app registers its owned name → 201; foreign
  name → 403; reserved name → 403; owner registers anything → 201; deregister-not-owned → 403;
  third-party `PUT /ai-profile` → 403; owner `PUT /ai-profile` → 200.
- **Back-compat:** `scripts/smoke-ecosystem.sh` stays green; existing single-secret tests pass
  unchanged.
- **CLI:** `apps add` prints a credential and creates an approved record; reserved/collision
  service-name rejected; `list`/`show` never emit secrets; `suspend` then a signed request → 401.

## Success criteria

1. A third-party app provisioned via `ecosystem apps add` can register **only** its owned
   service name(s), heartbeat, and be discovered — signing with its own key.
2. That app cannot register/deregister a reserved or foreign name (403), and cannot write the AI
   profile (403).
3. `ecosystem apps suspend` revokes that app immediately (401) with **no** effect on any other
   app.
4. All existing first-party apps and `smoke-ecosystem.sh` work unchanged (grandfathered owner
   identity; `sign_request` without `key_id` unchanged).
5. Per-app secrets and the shared secret never appear in logs; `apps.json` is `0600`.

## Out of scope (logged follow-ups)

- **Phase 1.5:** migrate first-party apps to their own per-app keys (retire the grandfathered
  owner for day-to-day writes) once the flow is proven.
- **Phase 2:** self-service `POST /enroll` + one-time invite tokens + `pending→approved` state;
  scopes beyond `register:self`; topic-scoped `events/publish`; per-app rate limits; SSRF fix on
  health polling (restrict to enrolled host:port, block RFC-1918/loopback for third parties);
  write audit log; admin page.
- **Phase 3:** asymmetric keys (Ed25519; registry stores only public keys — secrets never
  travel); app catalog.
