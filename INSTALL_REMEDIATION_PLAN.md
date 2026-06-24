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

## 2. Cross-cutting fixes (these resolve most rows at once)

### A. Secret provisioning (fixes #4, #5) — *highest priority*
Installers must establish ONE shared secret, persistently, for all services:
1. On first install, generate `ECOSYSTEM_HMAC_SECRET` (`secrets.token_hex(32)`)
   and write it to a single shared, `chmod 600` file — e.g.
   `~/.config/ecosystem/secret.env` (`ECOSYSTEM_HMAC_SECRET=…`).
2. Every service's launchd plist / systemd unit sources that file (launchd:
   bake into `EnvironmentVariables` or have the wrapper `set -a; . secret.env`;
   systemd: `EnvironmentFile=`).
3. Subsequent installs reuse the existing file (idempotent).
4. Document it; never commit a real secret.

### B. Internal-disk runtime for the registry (fixes #6)
Add `appEcosystem/scripts/install-local.sh` mirroring AFS/AegisSIEM: build the
venv + shared packages under `~/.local/share/ecosystem`, write the launchd plist
to run from there (not the external volume), reading `ECOSYSTEM_CONFIG` from the
repo. Update `cli install` (or the plist generator) to point at the internal
interpreter.

### C. Host/IP configuration (fixes #7, #9 partly)
- Default `ecosystem.yaml` project `host` to `127.0.0.1` (or `${ECOSYSTEM_HOST}`)
  instead of the baked LAN IP; auto-detect the primary IP only when binding for
  LAN use.
- Health checks should target the host the service actually binds; prefer
  loopback for single-machine installs.

### D. Installer hygiene (fixes #8, #11, #12, idempotency)
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

**Recommendation:** A (optional WebRTC) so installs never fail, **plus** B so
users who want two-way audio get a guided ffmpeg setup. Also fix #3 by ensuring
the optional extra means the core `requirements.txt` no longer hard-pulls `av`.

---

## 4. Phased execution

- **Phase 1 — Unblock installs (Critical):** OpenEye optional-WebRTC (#1–3);
  secret provisioning A (#4–5); registry internal-disk install (#6). After this,
  every app installs and starts on a clean machine.
- **Phase 2 — Correctness (High):** host/IP config (#7); MM config seeding +
  self-registration + bind host (#8, #9); confirm #10/#11 in a clean run.
- **Phase 3 — Hygiene (Med/Low):** non-interactive installer flags (#12);
  registry stale-entry cleanup/TTL (#13); idempotency pass.
- **Phase 4 — Acceptance test:** scripted clean-machine install of all five on
  macOS (launchd) and Linux (systemd) — see §5.

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

A repeatable smoke script (`scripts/smoke-ecosystem.sh`) should assert 1–6.

---

*Plan by Smart Industries LLC.*
