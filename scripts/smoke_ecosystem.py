#!/usr/bin/env python3
"""Ecosystem acceptance smoke test (Phase 4 of the install remediation).

Black-box checks of the guarantees a clean install must provide, across the
three deployment shapes the ecosystem promises:

  * single-host  — all apps on one machine (loopback)
  * subset       — only some apps installed here (no false "unhealthy")
  * networked    — apps on different devices, reached by advertised LAN IP

Runs the REAL registry ASGI app via Starlette's TestClient (exercises lifespan,
auth middleware, static pre-registration, AI-profile store) in a fully isolated
temp environment — it touches no real config, data dir, or secret file. No
external services, no network, no ports. Exits non-zero if any check fails.

Usage: scripts/smoke-ecosystem.sh   (or: python scripts/smoke_ecosystem.py)
"""
from __future__ import annotations

import logging
import os
import sys
import tempfile
from pathlib import Path

# Keep the acceptance output to the PASS/FAIL lines; the registry's own INFO
# logging is not the signal here. Quiet noisy libraries before they configure.
logging.disable(logging.WARNING)
os.environ.setdefault("ECOSYSTEM_LOG_LEVEL", "ERROR")

# --- tiny check harness -----------------------------------------------------
_PASS = 0
_FAIL = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global _PASS, _FAIL
    if ok:
        _PASS += 1
        print(f"  \033[32mPASS\033[0m  {name}")
    else:
        _FAIL += 1
        print(f"  \033[31mFAIL\033[0m  {name}" + (f"  — {detail}" if detail else ""))


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def _write_config(base: Path, projects: dict, mode: str = "local") -> Path:
    import yaml
    cfg = {"ecosystem": {"base_path": str(base)}, "mode": mode, "projects": projects}
    p = base / "ecosystem.yaml"
    p.write_text(yaml.safe_dump(cfg))
    return p


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo))
    sys.path.insert(0, str(repo / "auth" / "python"))

    tmp = Path(tempfile.mkdtemp(prefix="eco-smoke-"))
    SECRET = "f" * 64  # valid 64-hex test secret

    # Fully isolate: temp secret file, registry/profile data, config.
    os.environ["ECOSYSTEM_SECRET_FILE"] = str(tmp / "secret.env")
    os.environ["ECOSYSTEM_REGISTRY_FILE"] = str(tmp / "registry.json")
    os.environ["ECOSYSTEM_AI_PROFILE_FILE"] = str(tmp / "ai_profile.json")
    os.environ.pop("ECOSYSTEM_REGISTER_ALL_STATIC", None)
    os.environ.pop("ECOSYSTEM_MODE", None)

    print(f"Ecosystem smoke test — isolated env at {tmp}")

    # === 1. Shared secret: fail-closed, then provisioned ===
    section("1. Shared secret (fail-closed)")
    os.environ.pop("ECOSYSTEM_HMAC_SECRET", None)
    from ecosystem_auth import tokens
    try:
        tokens.get_ecosystem_secret()
        check("no secret -> raises (fail-closed)", False, "did not raise")
    except RuntimeError:
        check("no secret -> raises (fail-closed)", True)
    from ecosystem_auth.setup import apply_secret, secret_status, generate_secret
    apply_secret(SECRET)
    st = secret_status()
    check("apply_secret -> configured", st["configured"] and st["source"] == "file")
    check("status never leaks value", "secret" not in st and SECRET not in str(st))
    gen = generate_secret()
    check("generate returns a fresh 64-hex value once", len(gen.get("secret", "")) == 64)
    # restore the deterministic test secret for signed requests below
    apply_secret(SECRET, allow_overwrite=True)
    os.environ["ECOSYSTEM_HMAC_SECRET"] = SECRET

    # === 2. Topology: local vs lan ===
    section("2. Topology resolution (local | lan)")
    from ecosystem_client import topology
    os.environ.pop("ECOSYSTEM_MODE", None)
    os.environ.pop("ECOSYSTEM_BIND_HOST", None)
    os.environ.pop("ECOSYSTEM_ADVERTISE_HOST", None)
    check("local: bind+advertise loopback",
          topology.bind_host() == "127.0.0.1" and topology.advertise_host() == "127.0.0.1")
    os.environ["ECOSYSTEM_MODE"] = "lan"
    lan_advert = topology.advertise_host()
    check("lan: bind 0.0.0.0", topology.bind_host() == "0.0.0.0")
    check("lan: advertise non-loopback", not topology.is_loopback(lan_advert), lan_advert)
    os.environ.pop("ECOSYSTEM_MODE", None)

    # Build a TestClient against the real registry app + a given config.
    from fastapi.testclient import TestClient
    from ecosystem_auth.tokens import sign_request
    from ecosystem_auth import middleware

    def client_for(config_path: Path) -> TestClient:
        os.environ["ECOSYSTEM_CONFIG"] = str(config_path)
        # reset the process-wide nonce store so signed requests don't collide
        middleware._nonce_store._seen.clear()
        import importlib
        from registry import app as app_module
        importlib.reload(app_module)
        return TestClient(app_module.app)

    base_url = "http://testserver"

    # === 3. Registry boots + health ===
    section("3. Registry boots (single-host config)")
    full = _write_config(tmp, {
        "alpha": {"path": "alpha", "port": 9001, "health_endpoint": "/health"},
        "beta": {"path": "beta", "port": 9002, "health_endpoint": "/health"},
    })
    (tmp / "alpha").mkdir(exist_ok=True)
    (tmp / "beta").mkdir(exist_ok=True)
    with client_for(full) as c:
        r = c.get("/health")
        check("GET /health -> 200 healthy", r.status_code == 200 and r.json()["status"] == "healthy")
        names = {s["name"] for s in c.get("/services").json()}
        check("both present apps pre-registered", {"alpha", "beta"} <= names, str(names))

    # === 4. Subset install: absent app is NOT pre-registered ===
    section("4. Subset tolerance (one app not installed here)")
    subset = tmp / "subset.yaml"
    import yaml
    subset.write_text(yaml.safe_dump({
        "ecosystem": {"base_path": str(tmp)},
        "projects": {
            "alpha": {"path": "alpha", "port": 9001, "health_endpoint": "/health"},
            "ghost": {"path": "ghost_not_installed", "port": 9009, "health_endpoint": "/health"},
        },
    }))
    with client_for(subset) as c:
        names = {s["name"] for s in c.get("/services").json()}
        check("present app registered", "alpha" in names)
        check("absent app NOT registered (no false unhealthy)", "ghost" not in names, str(names))

    # === 5. Auth enforcement on writes ===
    section("5. Auth (HMAC signing required for writes)")
    with client_for(full) as c:
        r = c.post("/register", json={"name": "x", "port": 7000})
        check("unsigned POST /register -> 401", r.status_code == 401, str(r.status_code))
        payload = {"name": "svc-signed", "host": "127.0.0.1", "port": 7001,
                   "health_endpoint": "/health"}
        url = f"{base_url}/register"
        headers = sign_request("POST", url, SECRET, payload)
        r = c.post("/register", json=payload, headers=headers)
        check("signed POST /register -> 201", r.status_code == 201, str(r.status_code))

    # === 6. Networked: a remote device self-registers its LAN IP ===
    section("6. Networked split (remote advertise host honored)")
    with client_for(full) as c:
        payload = {"name": "remote-cam", "host": "10.0.0.50", "port": 8200,
                   "health_endpoint": "/health"}
        url = f"{base_url}/register"
        headers = sign_request("POST", url, SECRET, payload)
        c.post("/register", json=payload, headers=headers)
        svc = c.get("/services/remote-cam").json()
        check("remote service registered with its own LAN IP",
              svc.get("host") == "10.0.0.50", str(svc.get("host")))

    # === 7. AI profile sync ===
    section("7. Shared AI profile (read + signed update)")
    with client_for(full) as c:
        prof = c.get("/ai-profile").json()
        v0 = prof.get("version", 0)
        check("GET /ai-profile returns a profile", isinstance(prof, dict))
        changes = {"selected_model": "smoke-model"}
        url = f"{base_url}/ai-profile"
        headers = sign_request("PUT", url, SECRET, changes)
        r = c.put("/ai-profile", json=changes, headers=headers)
        ok = r.status_code == 200 and r.json().get("selected_model") == "smoke-model" \
            and r.json().get("version", 0) > v0
        check("signed PUT /ai-profile updates + bumps version", ok, str(r.status_code))

    # === 8. Per-device apps record ===
    section("8. Per-device apps record (ecosystem apps)")
    os.environ["ECOSYSTEM_CONFIG"] = str(subset)
    from cli import commands as cli_commands
    import importlib
    importlib.reload(cli_commands)
    cli_commands._load_config = lambda: yaml.safe_load(subset.read_text())
    apps = {a["key"]: a["present"] for a in cli_commands._device_apps()}
    check("apps record marks present/absent correctly",
          apps.get("alpha") is True and apps.get("ghost") is False, str(apps))

    # --- summary ---
    section("Summary")
    total = _PASS + _FAIL
    print(f"  {_PASS}/{total} checks passed")
    # best-effort cleanup
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    if _FAIL:
        print(f"\n\033[31mSMOKE TEST FAILED ({_FAIL} failing)\033[0m")
        return 1
    print("\n\033[32mSMOKE TEST PASSED\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
