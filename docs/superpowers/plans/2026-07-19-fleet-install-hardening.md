# Fleet Install Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the install/runtime defects found during the 2026-07-19 full-purge uninstall→reinstall test, so every ecosystem service installs to the internal disk, restarts on boot, uninstalls without damaging its neighbours, and advertises only endpoints that are actually alive.

**Architecture:** Each project owns its runtime under `~/.local/share/<app>/` (never the external `/Volumes/Locker2` volume, which caused SIGBUS crashes), is supervised by a launchd agent, and exposes two uninstall entry points (`uninstall.sh` full purge, `uninstall-keep-data.sh`). Shared secrets stay file-backed at `~/.config/ecosystem/secret.env`. Changes are per-repo and independently verifiable; there is no shared code between tasks except the ecosystem-client package.

**Tech Stack:** bash installers, macOS launchd (plist), Python 3.12 venvs (OpenEye: 3.9), FastAPI/Flask services, Node 22 (MagicMirror).

## Global Constraints

- Runtime venvs MUST live on the internal disk under `~/.local/share/<app>/venv`. Never under `/Volumes/`.
- Every installer MUST be non-interactive-capable via `-y` / `--yes` / `<APP>_NONINTERACTIVE=1` / `CI=true`.
- Every repo MUST expose `uninstall.sh` (full removal, confirm-gated) and `uninstall-keep-data.sh` (preserves user data).
- An uninstaller MUST only delete paths its own project owns. Never another project's directory.
- The shared HMAC secret is file-backed at `~/.config/ecosystem/secret.env`. Do not require `ECOSYSTEM_HMAC_SECRET` in the environment.
- Fixed ports: registry 8500, AI-for-Survival 8000, OpenEye 8200, MagicMirror 8080, AegisSIEM dashboard 8089, cyber-harness daemon 8088.
- Do not commit generated artifacts (`.env`, `start.sh`, `stop.sh`, `config/config.js`, venvs).
- Commit after each task. Do not batch unrelated changes.

**Verification baseline (all tasks assume this passes at the end):**
```bash
for u in http://127.0.0.1:8500/health http://127.0.0.1:8000/health \
         http://127.0.0.1:8200/api/health http://127.0.0.1:8089/api/status \
         http://127.0.0.1:8080 http://127.0.0.1:8088/api/status; do
  printf '%-46s %s\n' "$u" "$(curl -s -o /dev/null -w '%{http_code}' "$u" 2>/dev/null || echo ERR)"
done
```
(Use `~/.local/share/ecosystem/venv/bin/python -c "import httpx; ..."` if `curl` is blocked by hooks.)

> **Health-check caveat:** OpenEye's `/health` is served by the SPA catch-all and returns
> `200 text/html` even when the backend is broken — it is NOT a health check. Always use
> `/api/health` (JSON), which is what `ecosystem.yaml` registers for the service.

---

## Priority Order

| Task | Severity | Why |
|---|---|---|
| 1 | **P0** | OpenEye venv on external volume — the known SIGBUS crash class |
| 2 | **P0** | OpenEye has no launchd agent — dies on reboot |
| 3 | **P1** | AFS wrapper inside `~/.aegissiem` — AegisSIEM uninstall breaks AFS |
| 4 | **P1** | cyber-harness (8088) — **moved to the AI-providers plan** (see Task 4) |
| 5 | **P2** | ecosystem-client's undeclared `ecosystem_auth` import blocks third-party installs |
| 6 | **P2** | JS client source/vendored drift silently reintroduced a dev-secret bug |
| 7 | **P3** | MagicMirror launchd PATH warning + LAN access undocumented |
| 8 | **P3** | `test_guardrail_engine.py` fails collection in the prod venv |

---

### Task 1: Move OpenEye's runtime venv to the internal disk

The installer builds the venv at `opencv_surveillance/venv` — on `/Volumes/Locker2`. A force-unmount of that volume makes mmap'd C-extensions (opencv, av, face_recognition) fault with SIGBUS/KERN_MEMORY_ERROR. Every other service was already moved to `~/.local/share/`; OpenEye is the last one.

**Files:**
- Modify: `OpenEye-OpenCV_Home_Security/opencv_surveillance/scripts/install-local.sh` (venv creation ~line 155, activations at ~185, ~258, ~309, generated `start.sh` heredoc ~line 427-443, plist ProgramArguments ~line 375)
- Modify: `OpenEye-OpenCV_Home_Security/uninstall.sh` (venv removal block)

**Interfaces:**
- Produces: `OPENEYE_VENV` env override and the canonical path `$HOME/.local/share/openeye/venv`. Task 2's plist consumes `$VENV/bin/python3`.

- [ ] **Step 1: Write the failing assertion**

Create `OpenEye-OpenCV_Home_Security/scripts/check-venv-location.sh`:

```bash
#!/usr/bin/env bash
# Fails if the OpenEye runtime venv lives on a removable/external volume.
# An mmap'd C-extension (opencv/av) on a force-unmounted volume crashes with SIGBUS.
set -euo pipefail
VENV="${OPENEYE_VENV:-$HOME/.local/share/openeye/venv}"
if [ -d "$(dirname "${BASH_SOURCE[0]}")/../opencv_surveillance/venv" ]; then
    echo "FAIL: legacy venv still present on the repo volume (opencv_surveillance/venv)"; exit 1
fi
case "$VENV" in
  /Volumes/*) echo "FAIL: venv is on an external volume: $VENV"; exit 1 ;;
esac
[ -x "$VENV/bin/python3" ] || { echo "FAIL: no interpreter at $VENV/bin/python3"; exit 1; }
echo "OK: internal-disk venv at $VENV"
```

- [ ] **Step 2: Run it to verify it fails**

```bash
chmod +x OpenEye-OpenCV_Home_Security/scripts/check-venv-location.sh
OpenEye-OpenCV_Home_Security/scripts/check-venv-location.sh
```
Expected: `FAIL: legacy venv still present on the repo volume (opencv_surveillance/venv)` (exit 1)

- [ ] **Step 3: Introduce the VENV variable in the installer**

In `opencv_surveillance/scripts/install-local.sh`, immediately after `PROJECT_DIR="$(dirname "$SCRIPT_DIR")"` (line 17), add:

```bash
# Runtime venv lives on the INTERNAL disk. The repo may sit on an external
# volume (/Volumes/...); a force-unmount there makes mmap'd C-extensions
# (opencv, av, face_recognition) fault with SIGBUS and kills the daemon.
VENV="${OPENEYE_VENV:-$HOME/.local/share/openeye/venv}"
```

- [ ] **Step 4: Point venv creation and every activation at $VENV**

In `setup_venv()` (~line 155) replace the creation block so it builds at `$VENV`:

```bash
setup_venv() {
    log_info "Creating virtual environment at $VENV (internal disk)..."
    mkdir -p "$(dirname "$VENV")"
    if [ -d "$VENV" ]; then
        # Idempotent default: keep the existing venv unless asked to recreate.
        if [ -n "${OPENEYE_RECREATE_VENV:-}" ]; then
            rm -rf "$VENV"
            $PYTHON_CMD -m venv "$VENV"
        fi
    else
        $PYTHON_CMD -m venv "$VENV"
    fi
    source "$VENV/bin/activate"
}
```

Then replace every remaining bare activation — `source venv/bin/activate` at approximately lines 185, 258, 309 — with:

```bash
source "$VENV/bin/activate"
```

Verify none remain:
```bash
grep -n 'source venv/bin/activate' OpenEye-OpenCV_Home_Security/opencv_surveillance/scripts/install-local.sh
```
Expected: no output (the generated `start.sh` heredoc is handled in Step 5).

- [ ] **Step 5: Bake the absolute venv path into the generated start.sh**

The `start.sh` heredoc is quoted (`<< 'EOF'`), so `$VENV` will not expand. Use the placeholder + `sed` pattern already used by AI-for-Survival (`@@PROJECT_DIR@@`). Change the activation line inside the `cat > start.sh << 'EOF'` block from `source venv/bin/activate` to:

```bash
source "@@VENV@@/bin/activate"
```

and immediately after the closing `EOF` of that heredoc, add:

```bash
# Portable placeholder substitution. Do NOT use `sed -i`: BSD/macOS requires a
# detached backup suffix (-i '') while GNU/Linux forbids it, and this installer
# supports both. Redirect-and-move works identically everywhere.
sed "s|@@VENV@@|$VENV|g" start.sh > start.sh.tmp && mv start.sh.tmp start.sh
chmod +x start.sh
```

Do the same for `stop.sh` if it references the venv.

- [ ] **Step 6: Point the launchd plist at the internal interpreter**

In `create_systemd_service()` (~line 375) change:

```bash
    <string>$PROJECT_DIR/venv/bin/python3</string>
```
to:
```bash
    <string>$VENV/bin/python3</string>
```

- [ ] **Step 7: Teach the uninstaller about the new location**

In `OpenEye-OpenCV_Home_Security/uninstall.sh`, replace the venv-removal loop with one that also removes the internal prefix:

```bash
for vdir in "$OPENCV_DIR/venv" "$OPENCV_DIR/.venv" "${OPENEYE_VENV:-$HOME/.local/share/openeye/venv}"; do
    [ -d "$vdir" ] && run "rm -rf \"$vdir\"" && echo "  ✓ venv removed ($vdir)"
done
run "rmdir \"$HOME/.local/share/openeye\" 2>/dev/null || true"
```

- [ ] **Step 8: Reinstall and verify the assertion passes**

```bash
cd /Volumes/Locker2/GitHub/OpenEye-OpenCV_Home_Security
./uninstall.sh --yes
cd opencv_surveillance && OPENEYE_NONINTERACTIVE=1 ECOSYSTEM_BASE_PATH=/Volumes/Locker2/GitHub bash scripts/install-local.sh
cd .. && ./scripts/check-venv-location.sh
```
Expected: `OK: internal-disk venv at /Users/<you>/.local/share/openeye/venv`

- [ ] **Step 9: Verify the service still runs**

```bash
cd opencv_surveillance && nohup bash start.sh > /tmp/openeye.log 2>&1 &
sleep 25
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8200/api/health
grep -c 'weak SECRET_KEY' /tmp/openeye.log
```
Expected: `200`, and `0` weak-secret warnings.

- [ ] **Step 10: Commit**

```bash
git -C /Volumes/Locker2/GitHub/OpenEye-OpenCV_Home_Security add \
  opencv_surveillance/scripts/install-local.sh uninstall.sh scripts/check-venv-location.sh
git -C /Volumes/Locker2/GitHub/OpenEye-OpenCV_Home_Security commit -m "fix(install): build the runtime venv on the internal disk

The venv was created at opencv_surveillance/venv on the external volume; a
force-unmount makes mmap'd C-extensions (opencv/av/face_recognition) fault with
SIGBUS and kill the daemon. Every other service already installs to
~/.local/share. Adds scripts/check-venv-location.sh as a regression guard."
```

---

### Task 2: Install OpenEye's launchd agent by default

OpenEye is the only service with no LaunchAgent, so it does not come back after a reboot — a non-interactive install answers "N" to the auto-start prompt unless `OPENEYE_INSTALL_SERVICE=1` is set. Make supervised install the default and add an explicit opt-out, matching the other services.

**Files:**
- Modify: `OpenEye-OpenCV_Home_Security/opencv_surveillance/scripts/install-local.sh` (`create_systemd_service()` ~line 357-362)

**Interfaces:**
- Consumes: `$VENV` from Task 1.
- Produces: launchd label `com.smartindustries.openeye` at `~/Library/LaunchAgents/com.smartindustries.openeye.plist`.

- [ ] **Step 1: Write the failing assertion**

```bash
test -f ~/Library/LaunchAgents/com.smartindustries.openeye.plist \
  && echo "OK: plist present" || { echo "FAIL: no launchd agent"; }
```
Expected now: `FAIL: no launchd agent`

- [ ] **Step 2: Flip the non-interactive default to install the service**

In `create_systemd_service()` replace the default block:

```bash
    # Non-interactive default: only create the service when explicitly requested
    # via OPENEYE_INSTALL_SERVICE=1, matching the interactive "N" default.
    local svc_default="N"; [ -n "${OPENEYE_INSTALL_SERVICE:-}" ] && svc_default="Y"
```

with:

```bash
    # An unsupervised install does not survive a reboot, so a service is the
    # default. Opt out with OPENEYE_SKIP_SERVICE=1 (e.g. for CI or a dev box
    # that starts the app by hand with ./start.sh).
    if [ -n "${OPENEYE_SKIP_SERVICE:-}" ]; then
        log_info "OPENEYE_SKIP_SERVICE=1 — not creating an auto-start service."
        return
    fi
    local svc_default="Y"
```

- [ ] **Step 3: Reinstall and load the agent**

```bash
cd /Volumes/Locker2/GitHub/OpenEye-OpenCV_Home_Security/opencv_surveillance
pkill -f 'uvicorn.*backend.main:app' 2>/dev/null; sleep 2
OPENEYE_NONINTERACTIVE=1 ECOSYSTEM_BASE_PATH=/Volumes/Locker2/GitHub bash scripts/install-local.sh
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.smartindustries.openeye.plist 2>/dev/null || \
  launchctl kickstart -k gui/$(id -u)/com.smartindustries.openeye
```

- [ ] **Step 4: Verify the assertion passes and the service answers**

```bash
test -f ~/Library/LaunchAgents/com.smartindustries.openeye.plist && echo "OK: plist present"
launchctl list | grep com.smartindustries.openeye
sleep 25; curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8200/api/health
```
Expected: `OK: plist present`, a launchctl row, and `200`.

- [ ] **Step 5: Verify it restarts after a kill (KeepAlive)**

```bash
pkill -f 'uvicorn.*backend.main:app'; sleep 25
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8200/api/health
```
Expected: `200` (launchd restarted it).

- [ ] **Step 6: Commit**

```bash
git -C /Volumes/Locker2/GitHub/OpenEye-OpenCV_Home_Security add opencv_surveillance/scripts/install-local.sh
git -C /Volumes/Locker2/GitHub/OpenEye-OpenCV_Home_Security commit -m "fix(install): create the launchd agent by default

OpenEye was the only service without a LaunchAgent, so it never came back after
a reboot. Supervised install is now the default; opt out with OPENEYE_SKIP_SERVICE=1."
```

---

### Task 3: Move the AI-for-Survival daemon wrapper out of `~/.aegissiem`

`bin/install-local.sh:65` renders AFS's launchd wrapper to `$HOME/.aegissiem/scripts/start-afs.sh`, and the AFS plist's `ProgramArguments` points there. AegisSIEM's full uninstall does `rm -rf ~/.aegissiem`, which deletes AFS's startup wrapper — uninstalling one app silently breaks another.

**Files:**
- Modify: `AI-for-Survival/bin/install-local.sh:65-70` (WRAPPER_DIR) and the plist `ProgramArguments` block (~line 86-87)
- Modify: `AI-for-Survival/bin/uninstall.sh` (remove the new wrapper dir; clean up the legacy one)

**Interfaces:**
- Produces: wrapper at `$HOME/.local/share/ai-survival/scripts/start-afs.sh`, referenced by `com.mikelsmart.ai-for-survival`.

- [ ] **Step 1: Write the failing assertion**

Create `AI-for-Survival/bin/check-wrapper-ownership.sh`:

```bash
#!/usr/bin/env bash
# The AFS launchd wrapper must live under an AFS-owned path. Living inside
# ~/.aegissiem means a full AegisSIEM uninstall (rm -rf ~/.aegissiem) deletes it
# and breaks this service.
set -euo pipefail
PLIST="$HOME/Library/LaunchAgents/com.mikelsmart.ai-for-survival.plist"
[ -f "$PLIST" ] || { echo "SKIP: no plist installed"; exit 0; }
if grep -q '\.aegissiem' "$PLIST"; then
    echo "FAIL: plist references another project's directory (~/.aegissiem)"; exit 1
fi
WRAPPER="$HOME/.local/share/ai-survival/scripts/start-afs.sh"
[ -x "$WRAPPER" ] || { echo "FAIL: wrapper missing at $WRAPPER"; exit 1; }
echo "OK: wrapper is AFS-owned at $WRAPPER"
```

- [ ] **Step 2: Run it to verify it fails**

```bash
chmod +x AI-for-Survival/bin/check-wrapper-ownership.sh
AI-for-Survival/bin/check-wrapper-ownership.sh
```
Expected: `FAIL: plist references another project's directory (~/.aegissiem)` (exit 1)

- [ ] **Step 3: Relocate the wrapper**

In `AI-for-Survival/bin/install-local.sh`, replace line 65:

```bash
WRAPPER_DIR="$HOME/.aegissiem/scripts"
```

with:

```bash
# AFS-owned location. This previously lived in ~/.aegissiem/scripts, which meant a
# full AegisSIEM uninstall (rm -rf ~/.aegissiem) deleted this service's startup
# wrapper. Each project only owns paths under its own prefix.
WRAPPER_DIR="$HOME/.local/share/ai-survival/scripts"
```

- [ ] **Step 4: Migrate any existing install and remove the legacy wrapper**

Immediately after the `chmod +x "$WRAPPER"` line (~line 69), add:

```bash
# One-time migration off the old cross-project location.
LEGACY_WRAPPER="$HOME/.aegissiem/scripts/start-afs.sh"
if [ -f "$LEGACY_WRAPPER" ]; then
    rm -f "$LEGACY_WRAPPER"
    rmdir "$HOME/.aegissiem/scripts" 2>/dev/null || true
    echo "==> Removed legacy wrapper from $LEGACY_WRAPPER"
fi
```

- [ ] **Step 5: Teach the uninstaller to remove the wrapper**

In `AI-for-Survival/bin/uninstall.sh`, the `$PREFIX` removal (`~/.local/share/ai-survival`) already covers the new wrapper. Add legacy cleanup next to the stale-venv loop:

```bash
# Legacy cross-project wrapper location (pre-2026-07 installs).
run "rm -f \"$HOME/.aegissiem/scripts/start-afs.sh\""
```

- [ ] **Step 6: Reinstall with the plist and verify**

```bash
cd /Volumes/Locker2/GitHub/AI-for-Survival
ECOSYSTEM_BASE_PATH=/Volumes/Locker2/GitHub bash bin/install-local.sh --plist
./bin/check-wrapper-ownership.sh
sleep 20; curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/health
```
Expected: `OK: wrapper is AFS-owned at ...`, then `200`.

- [ ] **Step 7: Prove the cross-project bug is fixed**

```bash
# Full-purge AegisSIEM, then confirm AFS still starts.
bash /Volumes/Locker2/GitHub/LogAnalysis/scripts/uninstall.sh --yes
launchctl kickstart -k gui/$(id -u)/com.mikelsmart.ai-for-survival
sleep 20; curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/health
```
Expected: `200` — AFS survives an AegisSIEM purge.

Reinstall AegisSIEM afterwards:
```bash
cd /Volumes/Locker2/GitHub/LogAnalysis
ECOSYSTEM_BASE_PATH=/Volumes/Locker2/GitHub bash scripts/install-local.sh --plist
```

- [ ] **Step 8: Commit**

```bash
git -C /Volumes/Locker2/GitHub/AI-for-Survival add bin/install-local.sh bin/uninstall.sh bin/check-wrapper-ownership.sh
git -C /Volumes/Locker2/GitHub/AI-for-Survival commit -m "fix(install): own the daemon wrapper instead of living in ~/.aegissiem

The launchd wrapper was rendered into AegisSIEM's state dir, so a full AegisSIEM
uninstall (rm -rf ~/.aegissiem) deleted it and broke this service. Moved to
~/.local/share/ai-survival/scripts with a one-time migration + regression check."
```

---

### Task 4: (MOVED) Cyber-harness daemon integration

This task grew beyond install hardening — it now covers multi-provider AI
selection (Claude/Gemini/OpenAI vs local Ollama), secure API-key storage with
management UI in every relevant app, opt-in bundling, and single-instance
enforcement. It is a separate subsystem and lives in its own plan:

**→ `docs/superpowers/plans/2026-07-20-ai-providers-and-harness.md`**

Execute that plan after Tasks 1-3 here. Nothing in Tasks 5-8 below depends on it.

---

### Task 5: Make ecosystem-client's dependency on ecosystem-auth explicit

`ecosystem_client/discovery.py` and `config.py` both import `ecosystem_auth`, but `packages/ecosystem-client/pyproject.toml` only declares `httpx`. It works today solely because every first-party installer happens to install `auth/python` alongside it. A third party doing `pip install ecosystem-client` gets an ImportError at request-signing time — directly at odds with the goal of letting third parties add their own apps.

`ecosystem-auth` is not on a package index yet (publishing is deferred), so declaring a hard dependency would break local path installs. Instead: fail loudly with an actionable message, and document the peer requirement.

**Files:**
- Modify: `appEcosystem/ecosystem_client/config.py` (the `except Exception` fallback added on 2026-07-19)
- Modify: `appEcosystem/ecosystem_client/discovery.py` (the three `from ecosystem_auth.tokens import sign_request` sites)
- Modify: `appEcosystem/packages/ecosystem-client/pyproject.toml` (document the peer dep)
- Modify: `appEcosystem/packages/ecosystem-client/README.md` (create if absent)

**Interfaces:**
- Produces: `ecosystem_client._require_auth()` helper raising a single actionable `ImportError`.

- [ ] **Step 1: Write the failing test**

Create `appEcosystem/tests/test_client_auth_dependency.py`:

```python
"""ecosystem_client must fail with an actionable message when ecosystem_auth is absent."""
import builtins
import importlib
import pytest


def test_missing_ecosystem_auth_raises_actionable_error(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("ecosystem_auth"):
            raise ImportError("No module named 'ecosystem_auth'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    from ecosystem_client import discovery

    importlib.reload(discovery)
    with pytest.raises(ImportError) as exc:
        discovery._require_auth()
    msg = str(exc.value)
    assert "ecosystem-auth" in msg
    assert "pip install" in msg
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Volumes/Locker2/GitHub/appEcosystem
~/.local/share/ecosystem/venv/bin/python -m pytest tests/test_client_auth_dependency.py -v
```
Expected: FAIL — `AttributeError: module 'ecosystem_client.discovery' has no attribute '_require_auth'`

- [ ] **Step 3: Add the helper**

At the top of `appEcosystem/ecosystem_client/discovery.py`, add:

```python
def _require_auth():
    """Import ecosystem_auth.tokens or explain how to install it.

    ecosystem-auth is a peer requirement rather than a hard dependency because it
    is distributed as a local path package alongside this one; declaring it would
    break path installs until both are published.
    """
    try:
        from ecosystem_auth import tokens

        return tokens
    except ImportError as e:
        raise ImportError(
            "ecosystem-client requires the ecosystem-auth package for request "
            "signing, but it is not installed. Install it alongside this "
            "package:  pip install <appEcosystem>/auth/python"
        ) from e
```

- [ ] **Step 4: Route the three signing call sites through it**

Replace each `from ecosystem_auth.tokens import sign_request` (three occurrences in `discovery.py`) with:

```python
            sign_request = _require_auth().sign_request
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
~/.local/share/ecosystem/venv/bin/python -m pytest tests/test_client_auth_dependency.py -v
```
Expected: PASS

- [ ] **Step 6: Document the peer requirement**

In `packages/ecosystem-client/pyproject.toml`, directly above `dependencies`, add:

```toml
# NOTE: ecosystem-client also requires the `ecosystem-auth` package at runtime for
# HMAC request signing. It is intentionally NOT listed below because both are
# distributed as local path packages today; a hard dependency would make
# `pip install <path>/packages/ecosystem-client` fail to resolve. Install both:
#     pip install <appEcosystem>/auth/python <appEcosystem>/packages/ecosystem-client
# Convert this to a real dependency when the packages are published (Part A).
```

- [ ] **Step 7: Run the full client test suite**

```bash
~/.local/share/ecosystem/venv/bin/python -m pytest tests/ -q --ignore=tests/test_guardrail_engine.py
```
Expected: all pass, no new failures.

- [ ] **Step 8: Commit**

```bash
git -C /Volumes/Locker2/GitHub/appEcosystem add \
  ecosystem_client/discovery.py packages/ecosystem-client/pyproject.toml tests/test_client_auth_dependency.py
git -C /Volumes/Locker2/GitHub/appEcosystem commit -m "fix(client): explain the ecosystem-auth peer requirement

discovery.py imports ecosystem_auth but pyproject only declared httpx, so a
third-party 'pip install ecosystem-client' failed at signing time with a bare
ModuleNotFoundError. Routes the imports through _require_auth() with an
actionable message and documents the peer requirement."
```

---

### Task 6: Guard against JS ecosystem-client drift

The MagicMirror vendored client (`MagicMirror-Custom/js/ecosystem-client/`) and the source package (`appEcosystem/ecosystem_client_js/src/`) are maintained separately. They already diverged once: the vendored copy had the fail-closed `secret.js` while the source still defaulted `hmacSecret` to the committed dev secret. Add a parity check so drift fails loudly.

**Files:**
- Create: `appEcosystem/scripts/check-js-client-parity.sh`
- Modify: `appEcosystem/.github/workflows/ci.yml` (add a step; create the workflow if absent)

**Interfaces:**
- Produces: exit-1 on drift in the shared modules `secret.js`, `config.js`, `discovery.js`, `events.js`, `peer.js`.

- [ ] **Step 1: Write the check script**

Create `appEcosystem/scripts/check-js-client-parity.sh`:

```bash
#!/usr/bin/env bash
# The JS ecosystem client is vendored into MagicMirror. The two copies drifted
# once already (the source kept a dev-default HMAC secret after the vendored copy
# was fixed), which silently broke registry auth. Fail on drift.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ecosystem_client_js/src"
VENDOR="${MAGICMIRROR_PATH:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/MagicMirror-Custom}/js/ecosystem-client"

if [ ! -d "$VENDOR" ]; then
    echo "SKIP: vendored copy not found at $VENDOR"; exit 0
fi

status=0
for f in secret.js; do
    if [ ! -f "$SRC/$f" ] || [ ! -f "$VENDOR/$f" ]; then
        echo "FAIL: $f missing from one side (src=$SRC vendor=$VENDOR)"; status=1; continue
    fi
    if ! diff -q "$SRC/$f" "$VENDOR/$f" >/dev/null; then
        echo "FAIL: $f differs between source and vendored copy"
        diff -u "$SRC/$f" "$VENDOR/$f" || true
        status=1
    else
        echo "OK: $f in sync"
    fi
done

# Neither copy may fall back to the known dev secret.
for d in "$SRC" "$VENDOR"; do
    if grep -rn 'hmacSecret *=.*dev-ecosystem-secret-change-in-production' "$d" 2>/dev/null; then
        echo "FAIL: $d defaults hmacSecret to the committed dev secret"; status=1
    fi
done

[ $status -eq 0 ] && echo "JS client parity OK"
exit $status
```

- [ ] **Step 2: Run it — expect PASS now, and prove it catches drift**

```bash
cd /Volumes/Locker2/GitHub/appEcosystem
chmod +x scripts/check-js-client-parity.sh
./scripts/check-js-client-parity.sh
```
Expected: `OK: secret.js in sync` then `JS client parity OK`

Prove it detects drift:
```bash
echo "// drift" >> ../MagicMirror-Custom/js/ecosystem-client/secret.js
./scripts/check-js-client-parity.sh; echo "exit=$?"
git -C ../MagicMirror-Custom checkout js/ecosystem-client/secret.js
```
Expected: `FAIL: secret.js differs...` and `exit=1`, then the file is restored.

- [ ] **Step 3: Wire it into CI**

Add to `appEcosystem/.github/workflows/ci.yml` under the existing job's steps (create the workflow with a `runs-on: ubuntu-latest` job if the file does not exist):

```yaml
      - name: Check JS client parity
        run: ./scripts/check-js-client-parity.sh
```

Note the check exits 0 (SKIP) in CI when MagicMirror is not checked out beside appEcosystem, so it does not produce false failures.

- [ ] **Step 4: Commit**

```bash
git -C /Volumes/Locker2/GitHub/appEcosystem add scripts/check-js-client-parity.sh .github/workflows/ci.yml
git -C /Volumes/Locker2/GitHub/appEcosystem commit -m "test: fail on JS ecosystem-client drift

The vendored MagicMirror copy and the source package diverged once already —
the source kept a dev-default HMAC secret after the vendored copy was fixed,
silently breaking registry auth. Adds a parity + dev-secret check."
```

---

### Task 7: Fix the MagicMirror launchd PATH warning and document LAN access

MagicMirror's stderr shows `/bin/sh: node: command not found` — a module shells out to `node`, but launchd's minimal PATH does not include the Node install dir. The main process works (it is launched by absolute path), so this is cosmetic, but it pollutes logs and will break any module that shells out. Separately, the service binds `127.0.0.1` unless `ECO_LAN` is set, which is undocumented.

**Files:**
- Modify: `MagicMirror-Custom/scripts/install.sh` (plist `EnvironmentVariables`, ~line 28-47)
- Modify: `MagicMirror-Custom/README.md` (LAN access section)

- [ ] **Step 1: Confirm the warning is present**

```bash
grep -c 'node: command not found' ~/Library/Logs/MagicMirror/stderr.log
```
Expected: a non-zero count.

- [ ] **Step 2: Add PATH to the plist**

In `MagicMirror-Custom/scripts/install.sh`, inside the plist heredoc's `<dict>`, add an `EnvironmentVariables` entry that includes the directory of the resolved Node binary:

```xml
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>$(dirname "$NODE_BIN"):/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    <key>MM_PORT</key><string>$PORT</string>
  </dict>
```

If an `EnvironmentVariables` dict already exists in that heredoc, add the `PATH` key to it rather than adding a second dict.

- [ ] **Step 3: Reinstall and verify the warning is gone**

```bash
cd /Volumes/Locker2/GitHub/MagicMirror-Custom
: > ~/Library/Logs/MagicMirror/stderr.log
MM_NONINTERACTIVE=1 bash scripts/install.sh
launchctl kickstart -k gui/$(id -u)/com.smartindustries.magicmirror
sleep 15
grep -c 'node: command not found' ~/Library/Logs/MagicMirror/stderr.log || echo "0 (clean)"
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080
```
Expected: `0 (clean)` and `200`.

- [ ] **Step 4: Document LAN access**

Add to `MagicMirror-Custom/README.md`:

```markdown
### Network (LAN) access

By default the server binds `127.0.0.1`, so it is reachable only from this
machine. To expose it to other devices on your LAN, set `ECO_LAN` before
installing (it makes `config.js.sample` bind `0.0.0.0` and clear `ipWhitelist`):

    ECO_LAN=true ./scripts/install.sh

To pin a specific address instead, set `MM_ADDRESS`:

    MM_ADDRESS=192.168.50.73 ./scripts/install.sh

`config/config.js` is generated on first install from `config.js.sample`; edit it
directly to change the bind address or whitelist afterwards. A full
`./scripts/uninstall.sh` deletes it — use `./scripts/uninstall-keep-data.sh` to
keep your customisations.
```

- [ ] **Step 5: Commit**

```bash
git -C /Volumes/Locker2/GitHub/MagicMirror-Custom add scripts/install.sh README.md
git -C /Volumes/Locker2/GitHub/MagicMirror-Custom commit -m "fix(install): give launchd a PATH with node + document LAN access

Modules that shell out hit '/bin/sh: node: command not found' because launchd's
default PATH omits the Node install dir. Also documents ECO_LAN/MM_ADDRESS for
network access and the config.js lifecycle."
```

---

### Task 8: Fix `test_guardrail_engine.py` collection in the AI-for-Survival venv

`test_guardrail_engine.py` fails collection with `ModuleNotFoundError: No module named 'guardrail_engine'`, so the suite can only run with `--ignore`. This has been carried as a follow-up since the model-management work.

**Files:**
- Modify: `AI-for-Survival/backend/requirements-dev.txt` (create if absent) **or** `AI-for-Survival/pytest.ini` / `setup.cfg` (whichever configures `pythonpath`)
- Modify: `AI-for-Survival/todos_changelog.md`

- [ ] **Step 1: Reproduce the failure and locate the module**

```bash
cd /Volumes/Locker2/GitHub/AI-for-Survival
~/.local/share/ai-survival/venv/bin/python -m pytest backend -q 2>&1 | tail -20
find . -name 'guardrail_engine*' -not -path '*/venv/*' -not -path '*/.git/*'
```
Expected: the collection error, plus the real location of the module.

- [ ] **Step 2: Apply the fix that matches what you found**

- If the module exists in-repo but is not importable, add its directory to pytest's path. In `pytest.ini` (create beside `backend/` if absent):

```ini
[pytest]
pythonpath = backend backend/src
testpaths = backend
```

- If it is a genuine third-party/dev dependency, add it to `backend/requirements-dev.txt` and install:

```bash
~/.local/share/ai-survival/venv/bin/pip install -r backend/requirements-dev.txt
```

Do not delete the test to make the suite green.

- [ ] **Step 3: Verify collection succeeds**

```bash
~/.local/share/ai-survival/venv/bin/python -m pytest backend -q 2>&1 | tail -5
```
Expected: no collection errors; the full suite runs without `--ignore`.

- [ ] **Step 4: Close out the follow-up note**

In `AI-for-Survival/todos_changelog.md`, change the open item:

```markdown
- [ ] Follow-up: `test_guardrail_engine.py` fails collection in the prod venv
```

to:

```markdown
- [x] **`test_guardrail_engine.py` collection (FIXED 2026-07-19)** — the module was
  not on pytest's import path in the internal-disk venv; pinned via `pythonpath`
  in pytest.ini so the suite runs without `--ignore`.
```

(Adjust the wording to match whichever fix Step 2 actually applied.)

- [ ] **Step 5: Commit**

```bash
git -C /Volumes/Locker2/GitHub/AI-for-Survival add pytest.ini backend/requirements-dev.txt todos_changelog.md
git -C /Volumes/Locker2/GitHub/AI-for-Survival commit -m "test: fix test_guardrail_engine collection in the prod venv"
```

---

### Task 9: Move OpenEye's runtime fully off the external volume

**Execute immediately after Task 2** — it completes Task 2's unfinished verification.

Task 2 installed the launchd agent, but the service crash-loops with
`PermissionError: [Errno 1] Operation not permitted`. Task 1 moved the venv to a new
interpreter path (`venv/bin/python3` → symlink to CommandLineTools Python 3.9) that
macOS TCC has never granted disk access, while OpenEye's `WorkingDirectory` and all its
data still live on `/Volumes/Locker2`. Manual `./start.sh` works only because Terminal
already holds that grant; launchd has its own TCC context.

Rather than granting Full Disk Access to a shared system interpreter, remove the
dependency: run the service entirely from the internal disk. `backend/core/paths.py`
already supports `OPENEYE_DATA_DIR`, `OPENEYE_RECORDINGS_DIR`, `OPENEYE_SNAPSHOTS_DIR`,
`OPENEYE_THUMBNAILS_DIR`, and `OPENEYE_FACES_DIR`, so **no application code changes** —
only installer paths.

**Files:**
- Modify: `OpenEye-OpenCV_Home_Security/opencv_surveillance/scripts/install-local.sh`
- Modify: `OpenEye-OpenCV_Home_Security/uninstall.sh`
- Modify: `OpenEye-OpenCV_Home_Security/scripts/check-venv-location.sh` (extend to assert no `/Volumes` path in the plist)

**Interfaces:**
- Consumes: `$VENV` (Task 1), the launchd agent (Task 2).
- Produces: `APP_DIR=$HOME/.local/share/openeye/app` (code snapshot) and
  `DATA_ROOT=$HOME/.local/share/openeye` (db + media). The plist references neither `/Volumes` nor the repo.

**Precondition — verify before starting.** This is safe only while there is no user data:

```bash
cd /Volumes/Locker2/GitHub/OpenEye-OpenCV_Home_Security/opencv_surveillance
python3 -c "
import sqlite3; c=sqlite3.connect('surveillance.db'); q=c.cursor()
for t in ('users','cameras','recording_events'):
    q.execute(f'select count(*) from {t}'); print(t, q.fetchone()[0])"
find recordings faces data -type f 2>/dev/null | wc -l
```
Expected: all counts `0`. **If any count is non-zero, STOP and report** — migrating live
footage and accounts needs its own copy-and-verify step not covered here.

- [ ] **Step 1: Extend the guard to assert nothing points at /Volumes**

Append to `scripts/check-venv-location.sh`, before its final success `echo`:

```bash
PLIST="$HOME/Library/LaunchAgents/com.smartindustries.openeye.plist"
if [ -f "$PLIST" ] && grep -q '/Volumes/' "$PLIST"; then
    echo "FAIL: launchd plist still references an external volume:"
    grep -n '/Volumes/' "$PLIST"
    exit 1
fi
```

- [ ] **Step 2: Run it to verify it fails**

```bash
/Volumes/Locker2/GitHub/OpenEye-OpenCV_Home_Security/scripts/check-venv-location.sh
```
Expected: `FAIL: launchd plist still references an external volume:` plus the
`WorkingDirectory` line (exit 1).

- [ ] **Step 3: Add the internal app + data roots to the installer**

In `install-local.sh`, immediately after the existing `VENV=` line, add:

```bash
# The service must not depend on the repo volume. macOS TCC denies launchd-spawned
# binaries access to /Volumes unless individually granted, and an external volume can
# vanish mid-run. Code is snapshotted into APP_DIR; db + media live under DATA_ROOT.
DATA_ROOT="${OPENEYE_DATA_ROOT:-$HOME/.local/share/openeye}"
APP_DIR="$DATA_ROOT/app"
```

- [ ] **Step 4: Snapshot the application code into APP_DIR**

Add a function, and call it after `install_python_deps` and after the frontend build
(so `frontend/dist` exists) but before `create_launch_script`:

```bash
# Copy the runnable application to the internal disk. This is a snapshot: changes in
# the repo require re-running this installer, the same non-editable tradeoff the
# ecosystem registry already makes.
sync_app_to_internal() {
    log_info "Syncing application code to $APP_DIR (internal disk)..."
    mkdir -p "$APP_DIR"
    rsync -a --delete \
        --exclude 'venv/' --exclude '.venv/' \
        --exclude 'frontend/node_modules/' \
        --exclude '__pycache__/' --exclude '*.pyc' \
        --exclude '.git/' \
        --exclude 'recordings/' --exclude 'faces/' --exclude 'data/' \
        --exclude 'surveillance.db*' \
        "$PROJECT_DIR/" "$APP_DIR/"
    log_success "Application synced to $APP_DIR"
}
```

- [ ] **Step 5: Point the generated .env at internal absolute paths**

In `generate_secrets()`, inside the `.env` heredoc, replace the `DATABASE_URL` line and
add the path overrides (keep the existing SECRET_KEY / JWT_SECRET_KEY / PORT=8200 /
CORS lines exactly as they are):

```bash
# Absolute internal paths so the service never touches the repo volume.
DATABASE_URL=sqlite:///$DATA_ROOT/surveillance.db
OPENEYE_DATA_DIR=$DATA_ROOT/data
OPENEYE_RECORDINGS_DIR=$DATA_ROOT/recordings
OPENEYE_SNAPSHOTS_DIR=$DATA_ROOT/data/snapshots
OPENEYE_THUMBNAILS_DIR=$DATA_ROOT/data/thumbnails
OPENEYE_FACES_DIR=$DATA_ROOT/faces
```

Create the directories in the installer before first run:

```bash
mkdir -p "$DATA_ROOT/data/snapshots" "$DATA_ROOT/data/thumbnails" \
         "$DATA_ROOT/recordings" "$DATA_ROOT/faces"
```

Write `.env` into **both** `$PROJECT_DIR` (for manual `./start.sh` from the repo) and
`$APP_DIR` (what the service reads). Generate it once, then copy it to `$APP_DIR/.env`
after `sync_app_to_internal` runs.

- [ ] **Step 6: Run start.sh and the service from APP_DIR**

In the generated `start.sh`, change the working-directory line so it runs from the
internal snapshot rather than the script's own location:

```bash
cd "@@APP_DIR@@"
```

and extend the existing portable substitution to resolve it:

```bash
sed -e "s|@@VENV@@|$VENV|g" -e "s|@@APP_DIR@@|$APP_DIR|g" start.sh > start.sh.tmp \
    && mv start.sh.tmp start.sh
chmod +x start.sh
```

In `create_systemd_service()`, change the launchd plist:

```xml
  <key>WorkingDirectory</key><string>$APP_DIR</string>
```

Confirm the plist's `ProgramArguments` still uses `$VENV/bin/python3` (Task 1) — it does
not change here.

- [ ] **Step 7: Teach the uninstaller about the internal app + data**

In `uninstall.sh`, add `$APP_DIR` removal alongside the venv removal, and put the
internal data under the existing keep-data branch:

```bash
run "rm -rf \"${OPENEYE_DATA_ROOT:-$HOME/.local/share/openeye}/app\""
```

and in the full-purge (not `--keep-data`) branch:

```bash
DATA_ROOT="${OPENEYE_DATA_ROOT:-$HOME/.local/share/openeye}"
run "rm -f \"$DATA_ROOT/surveillance.db\" \"$DATA_ROOT/surveillance.db-shm\" \"$DATA_ROOT/surveillance.db-wal\""
for d in recordings faces data; do
    run "rm -rf \"$DATA_ROOT/$d\""
done
```

`--keep-data` must preserve `$DATA_ROOT`'s db and media while still removing `app/` and the venv.

- [ ] **Step 8: Reinstall and verify the guard passes**

```bash
cd /Volumes/Locker2/GitHub/OpenEye-OpenCV_Home_Security/opencv_surveillance
pkill -f 'uvicorn.*backend.main:app' 2>/dev/null; sleep 2
OPENEYE_NONINTERACTIVE=1 ECOSYSTEM_BASE_PATH=/Volumes/Locker2/GitHub bash scripts/install-local.sh
cd .. && ./scripts/check-venv-location.sh
grep -c '/Volumes/' ~/Library/LaunchAgents/com.smartindustries.openeye.plist
```
Expected: guard prints OK, and the plist `/Volumes/` count is `0`.

- [ ] **Step 9: Prove the launchd service now actually serves (the Task 2 gap)**

```bash
launchctl bootout "gui/$(id -u)/com.smartindustries.openeye" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.smartindustries.openeye.plist
sleep 35
~/.local/share/ecosystem/venv/bin/python -c "import httpx; r=httpx.get('http://127.0.0.1:8200/api/health',timeout=8); print(r.status_code, r.text[:120])"
grep -c 'Operation not permitted' ~/Library/Logs/OpenEye/stderr.log
```
Expected: `200` with `"status":"healthy"`, and `0` permission errors.
(`/health` is the SPA catch-all and returns 200 regardless — always use `/api/health`.)

- [ ] **Step 10: Prove KeepAlive restarts it**

```bash
pkill -f 'uvicorn.*backend.main:app'; sleep 35
~/.local/share/ecosystem/venv/bin/python -c "import httpx; print(httpx.get('http://127.0.0.1:8200/api/health',timeout=8).status_code)"
```
Expected: `200` — launchd restarted it unattended.

- [ ] **Step 11: Commit**

```bash
git -C /Volumes/Locker2/GitHub/OpenEye-OpenCV_Home_Security add \
  opencv_surveillance/scripts/install-local.sh uninstall.sh scripts/check-venv-location.sh
git -C /Volumes/Locker2/GitHub/OpenEye-OpenCV_Home_Security commit -m "fix(install): run entirely from the internal disk

The launchd service crash-looped with 'Operation not permitted': macOS TCC denies
launchd-spawned binaries access to /Volumes unless individually granted, and both the
WorkingDirectory and all data lived there. Code is now snapshotted to
~/.local/share/openeye/app and db+media to ~/.local/share/openeye, using the
OPENEYE_*_DIR overrides paths.py already supports — no application code changes.
Removes the external-volume dependency entirely rather than granting Full Disk Access
to a shared system interpreter."
```

---

## Final Verification

After all tasks, run a full cold-start check:

- [ ] **Reboot-equivalent: bounce every service through launchd**

```bash
for l in com.ecosystem.registry com.mikelsmart.ai-for-survival com.mikelsmart.aegissiem \
         com.smartindustries.magicmirror com.smartindustries.openeye com.smartindustries.cyber-harness; do
  launchctl kickstart -k "gui/$(id -u)/$l" 2>/dev/null && echo "bounced $l" || echo "MISSING $l"
done
sleep 40
```
Expected: all six report `bounced` (none `MISSING`).

- [ ] **All six endpoints healthy**

```bash
for u in http://127.0.0.1:8500/health http://127.0.0.1:8000/health \
         http://127.0.0.1:8200/api/health http://127.0.0.1:8089/api/status \
         http://127.0.0.1:8080 http://127.0.0.1:8088/api/status; do
  printf '%-46s %s\n' "$u" "$(curl -s -o /dev/null -w '%{http_code}' "$u" 2>/dev/null || echo ERR)"
done
```
Expected: `200` for all six.

- [ ] **No venv on the external volume**

```bash
ls -d /Volumes/Locker2/GitHub/*/venv /Volumes/Locker2/GitHub/*/*/venv 2>/dev/null || echo "OK: no venvs on the external volume"
```
Expected: `OK: no venvs on the external volume`

- [ ] **No app registers a 401 against the registry**

```bash
grep -rl '401 Unauthorized' ~/Library/Logs/*/*.log 2>/dev/null || echo "OK: no 401s"
```
Expected: `OK: no 401s` (clear the logs first if stale entries predate the fixes).

- [ ] **Every repo has both uninstall entry points**

```bash
cd /Volumes/Locker2/GitHub
for p in appEcosystem/scripts AI-for-Survival/bin LogAnalysis/scripts MagicMirror-Custom/scripts \
         CybersecurityTeam/cyber-claude-agents/scripts; do
  for f in uninstall.sh uninstall-keep-data.sh; do
    [ -x "$p/$f" ] && echo "OK  $p/$f" || echo "MISSING $p/$f"
  done
done
for f in uninstall.sh uninstall-keep-data.sh; do
  [ -x "OpenEye-OpenCV_Home_Security/$f" ] && echo "OK  OpenEye/$f" || echo "MISSING OpenEye/$f"
done
```
Expected: all `OK`.

- [ ] **Dry-run every uninstaller — no script may touch another project's paths**

```bash
bash appEcosystem/scripts/uninstall.sh --dry-run --yes | grep -E 'aegissiem|ai-survival|openeye|MagicMirror' && echo "LEAK" || echo "OK appEcosystem"
bash AI-for-Survival/bin/uninstall.sh --dry-run --yes | grep -E '\.aegissiem|ecosystem/secret' && echo "LEAK" || echo "OK AFS"
bash LogAnalysis/scripts/uninstall.sh --dry-run --yes | grep -E 'ai-survival|start-afs' && echo "LEAK" || echo "OK AegisSIEM"
```
Expected: `OK` for each (no cross-project paths).
