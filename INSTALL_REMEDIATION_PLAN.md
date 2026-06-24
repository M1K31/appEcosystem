# Install/Deploy Remediation Plan — Make Fresh Installs "Just Work"

**Prepared for:** Smart Industries LLC
**Date:** 2026-06-23
**Goal:** A user who installs any app (or the whole ecosystem) on a clean
machine should not hit any of the issues surfaced during the reinstall test.
Each fix is judged by: *does a clean-machine install start, serve its UI, and
join the ecosystem without manual intervention?*

---

## 1. Issues found (root cause → user impact → fix)

| # | Issue | Root cause | User impact | Sev | Status |
|---|-------|-----------|-------------|-----|--------|
| 1 | **OpenEye install fails on `av`/`aiortc`** | `aiortc` (WebRTC) needs `av<15` compiled against system **ffmpeg**; only `av 15` has a wheel | Install aborts; OpenEye unusable | **Critical** | open |
| 2 | **OpenEye backend won't import without WebRTC** | hard `import aiortc.MediaStreamTrack` at module load (two-way audio) | Even a partial install can't serve the UI | **Critical** | open |
| 3 | **OpenEye venv left incomplete** | pip aborts on `av`, so `bcrypt`/`multidict`/… never install | Broken venv; cryptic `ModuleNotFoundError` | High | open |
| 4 | **No shared secret provisioned by installers** | fail-closed `get_ecosystem_secret` requires `ECOSYSTEM_HMAC_SECRET`; installers don't set one | Registry won't start (EventBus raises); cross-app auth 401 | **Critical** | open |
| 5 | **Secret not persistent** | set via `launchctl setenv` only | Ecosystem breaks after reboot | High | open |
| 6 | **Registry launchd fails from external volume** | venv on `/Volumes/Locker2`; macOS launchd TCC/exec restriction (exit 78) | Registry never starts as a service | **Critical** | open |
| 7 | **`ecosystem.yaml` hardcodes LAN IP `192.168.50.73`** | static host baked in | Health checks fail on any other network/localhost; services show "unhealthy" | High | open |
| 8 | **MagicMirror has no `config.js` on fresh install** | only `config.js.sample` ships | MM won't start / serves default until manually seeded | High | open |
| 9 | **MagicMirror doesn't self-register / binds IPv6-only** | no dynamic registration; `serveronly` binds `::1` | MM stays "unhealthy" in registry; IPv4 clients/health checks miss it | Med | open |
| 10 | **AegisSIEM example config dashboard port 8088** | stale value collided with harness | dashboard bound onto harness port | High | **fixed** |
| 11 | **`install-local.sh` didn't install shared packages** (AFS, AegisSIEM) | step missing | ecosystem sync dormant after install | High | **fixed** |
| 12 | **OpenEye installer is interactive** (`read -p`) | prompts mid-install | breaks unattended/scripted installs | Med | open |
| 13 | **Stale entries persist in `data/registry.json`** | old service names survive a rename/restart | registry shows dead/renamed services | Low | open |

---

## 1a. Deployment topologies (the design must serve BOTH)

The ecosystem must work (1) **single-host** — all apps on one machine — and
(2) **networked** — apps spread across devices on a LAN — and (3) **subset** —
only some apps installed. A single deployment "mode" selects sane defaults:

| Mode | `ECOSYSTEM_MODE` | Bind host | Advertised host | Secret | Registry URL |
|------|------------------|-----------|-----------------|--------|--------------|
| Single-host (default, secure) | `local` | `127.0.0.1` | `127.0.0.1` | generated locally | `http://127.0.0.1:8500` |
| Networked | `lan` | `0.0.0.0` | auto-detected LAN IP / `${ECOSYSTEM_ADVERTISE_HOST}` | **shared across devices** | registry device's IP |

Key principle: **bind host ≠ advertised host.** A service binds where it
*listens*; it registers the address *peers use to reach it*. These differ in LAN
mode. Discovery (registry → mDNS → static → standalone) already tolerates absent
peers, so subset installs work; the registry must just not treat
never-installed members as hard failures (see D).

## 2. Cross-cutting fixes (these resolve most rows at once)

### A. Secret provisioning — works single-host AND multi-device (fixes #4, #5)
There is exactly ONE secret per *ecosystem*, which every device in that ecosystem
must share. Resolution order on each install:
1. If `ECOSYSTEM_HMAC_SECRET` is set in the env → use it (the networked path:
   the operator sets the same value on every device).
2. Else if `~/.config/ecosystem/secret.env` exists → reuse it (idempotent).
3. Else (first device / single-host) → **generate**, write to
   `~/.config/ecosystem/secret.env` (`chmod 600`), and **print it with
   instructions** to set the identical value on any other device that should
   join (`export ECOSYSTEM_HMAC_SECRET=…` or copy the file).
4. Provide `ecosystem secret show` / `ecosystem secret import <value>` helpers so
   joining a second device is one command — no manual file editing.
5. Every service's launchd plist / systemd unit sources `secret.env` (launchd
   wrapper: `set -a; . secret.env`; systemd: `EnvironmentFile=`).
- **Single-host:** step 3 auto-generates; every app installed on that machine
  finds and reuses the same `secret.env` — zero config, fully automatic.
- **Networked:** generate on the first device, then supply the *same* value once
  on each other device (steps 1/4). After that it's saved locally there too.
- **Subset:** unaffected — each installed app just needs the shared secret to
  talk to the others; apps you didn't install simply aren't contacted.
- **Security invariant:** the **registry never stores or distributes the
  secret** — it only *verifies* signatures made with it. Non-secret config (AI
  profile, ports, discovery) propagates through the registry (Phase B2); the
  secret is deliberately kept out of that channel, so cross-device sharing is a
  one-time manual copy rather than an automatic network push.

### B. Internal-disk runtime for the registry (fixes #6)
Add `appEcosystem/scripts/install-local.sh` mirroring AFS/AegisSIEM: build the
venv + shared packages under `~/.local/share/ecosystem`, write the launchd plist
to run from there (not the external volume), reading `ECOSYSTEM_CONFIG` from the
repo. Update `cli install` (or the plist generator) to point at the internal
interpreter.

### C. Host/advertise — works single-host AND networked (fixes #7, #9)
Split the two concepts the old plan conflated:
- **Bind host** = `ECOSYSTEM_BIND_HOST` (default by mode: `127.0.0.1` local,
  `0.0.0.0` lan). What the server listens on.
- **Advertised host** = `ECOSYSTEM_ADVERTISE_HOST` = the address registered with
  peers. Default: `127.0.0.1` in local mode; in lan mode, **auto-detect the
  primary non-loopback IPv4** (or honor an explicit override / hostname).
- Each service registers its *advertised* host:port; the registry health-checks
  that same reachable address (not a baked `192.168.50.73`).
- `ECOSYSTEM_REGISTRY_URL` per device points at the registry's location
  (loopback if co-located, the registry device's IP otherwise).
- Security: lan mode reopens LAN exposure the audit flagged, so the **shared
  secret + fail-closed auth + `ECOSYSTEM_REQUIRE_READ_AUTH`** are the controls
  there; local mode stays loopback-only. The mode makes the trade-off explicit.
- Remove the hardcoded `192.168.50.73` from `ecosystem.yaml`; derive host from
  mode/advertise settings. Also bind MagicMirror's `serveronly` to the mode host
  (not IPv6-only `::1`) and have it self-register like the Python apps.

### D. Subset installs & registry tolerance (fixes #9, #13, topology)
- `ecosystem.yaml` lists *potential* members; the registry should **only
  actively health-check members that register or are explicitly enabled** for
  this deployment (e.g. an `enabled`/`expected` flag, or only monitor
  dynamically-registered services). Never-installed apps must not show as
  alarming "unhealthy" or generate error spam.
- Each app remains standalone-capable; discovery already degrades gracefully when
  a peer is absent (verified: AFS/AegisSIEM ran and self-registered; absent
  OpenEye/MM statics simply showed unknown/unhealthy).
- An install-time prompt/flag records which apps this device runs, so the local
  registry view matches reality.

### E. Installer hygiene (fixes #8, #11, #12, idempotency)
Every installer should, idempotently and non-interactively (with an opt-in
prompt flag): create/refresh the (internal-disk) venv, install app + shared
packages, **seed config from the sample if absent** (MM `config.js`, app config
files), provision/reuse the shared secret, and install the OS-appropriate
service. Add a `--yes`/`--non-interactive` flag to OpenEye's installer.

---

## 3. OpenEye WebRTC/av blocker (fixes #1, #2, #3) — needs a decision

Three viable paths (pick one; A+B together is best):

- **A. Make WebRTC optional (code).** Guard the `aiortc`/two-way-audio imports
  so the backend imports and serves with the feature disabled when `aiortc`
  isn't installed (mirrors the "degrade gracefully" pattern used elsewhere).
  Move `aiortc`/`av` to an optional `[webrtc]` extra. → UI installs cleanly
  everywhere; two-way audio available only where ffmpeg/av is present.
- **B. Document + script the ffmpeg path.** Installer detects missing ffmpeg,
  offers to `brew install ffmpeg` (macOS) / `apt install ffmpeg` (Linux), and
  pins a compatible `av`/`aiortc` pair so the wheel builds.
- **C. Pin to a prebuilt-wheel combo** (e.g. an `av`/`aiortc` release with
  arm64/py3.9 wheels) to avoid source builds entirely, if one exists.

**DECISION (confirmed, revised):** Install the WebRTC packages **by default** —
they stay in the core `requirements.txt` — but make the *feature* optional and
crash-proof. Concretely:
1. **Installer ensures `ffmpeg` first** (the missing build dep): detect it, and
   on macOS `brew install ffmpeg` / Linux `apt install ffmpeg` (prompt unless
   `--yes`) *before* pip, so `av`/`aiortc` build and install every time.
2. Pin a compatible `av`/`aiortc` pair (aiortc needs `av<15`) so the build is
   deterministic once ffmpeg is present.
3. **Import-guard** every `aiortc`/`av`/two-way-audio import purely as
   resilience — if the wheel is somehow missing/broken, the backend still
   imports and serves with two-way audio disabled (fixes #2/#3) instead of
   dying at `class AudioTrack(MediaStreamTrack)`.
4. A runtime toggle (config flag) can disable the feature without uninstalling.

Net: packages are present out-of-the-box (feature works), the install never
hard-fails on the native build, and the app degrades gracefully if WebRTC is
unavailable.

---

## 4. Phased execution

- **Phase 1 — Unblock installs (Critical):** OpenEye optional-WebRTC + `[webrtc]`
  extra (#1–3); **shared-secret provisioning that works single-host AND
  multi-device** (§2.A: env → file → generate+print, plus `secret show/import`);
  registry internal-disk install (#6). After this, every app installs and starts
  on a clean machine, single-host or networked.
- **Phase 2 — Topology correctness (High):** introduce `ECOSYSTEM_MODE`
  (local|lan) with bind-vs-advertise host resolution (§2.C); remove the baked
  `192.168.50.73`; MM config seeding + self-registration + mode-correct bind
  (#8, #9); registry tolerance of subset/absent members (§2.D, #13).
- **Phase 3 — Hygiene (Med/Low):** non-interactive installer flags (#12);
  per-device "enabled apps" record; idempotency pass.
- **Phase 4 — Acceptance test:** `scripts/smoke-ecosystem.sh` for BOTH
  topologies — (a) single-host all-five, (b) two-device split (registry+AFS on
  host A, AegisSIEM on host B) — on macOS (launchd) and Linux (systemd). See §5.

---

## 5. Acceptance criteria ("done")

A fresh checkout on a clean machine, running each app's documented install
command (no manual edits), results in:
1. Install completes with **no build/dep errors** (or a clear, guided prompt for
   an optional system dep like ffmpeg).
2. Each service **starts and serves its UI**: AFS :8000, AegisSIEM :8089,
   OpenEye :8200, MagicMirror :8080, registry :8500.
3. A **shared secret is auto-provisioned**; AFS/AegisSIEM/OpenEye/MagicMirror
   **self-register as healthy** with the registry; `/ai-placement` returns a host.
4. Reboot → all services come back healthy (persistent secret + service manager).
5. Uninstall removes services cleanly; `--purge` removes venv/config.
6. Re-run of any installer is **idempotent** (no duplication, no breakage).
7. **Networked:** with `ECOSYSTEM_MODE=lan` and the same secret on two devices,
   a service on device B self-registers with the registry on device A using its
   LAN address and is reachable/healthy from A.
8. **Subset:** installing only a subset (e.g. AFS + MagicMirror) works — the
   installed apps run and federate; absent apps are not reported as failures and
   cause no errors.

A repeatable smoke script (`scripts/smoke-ecosystem.sh`) should assert 1–6
single-host, plus a two-device harness for 7 and a subset run for 8.

---

*Plan by Smart Industries LLC.*
