"""Framework-agnostic helpers for the in-app 'Ecosystem setup' secret panel.

Every app exposes the same browser-based second path (beside the
``ecosystem secret`` CLI) for provisioning the shared HMAC secret — especially
on a second device joining over the network. The web framework differs per app
(FastAPI, Flask, Express…), so the *route* lives in each app, but the security-
sensitive logic — validation, overwrite protection, never echoing the value —
is centralised here so all apps behave identically.

Endpoints in each app should wrap these:
    GET  status  -> secret_status()
    POST apply   -> apply_secret(value, allow_overwrite=...)
    POST generate-> generate_secret()   (primary device only)

The secret value is NEVER returned by status; only whether one is configured.
"""
from __future__ import annotations

import os
import re
from typing import Optional

from .tokens import (
    DEFAULT_DEV_SECRET,
    generate_secure_token,
    secret_file_path,
    write_secret,
    _read_secret_file,
)

# A provisioned secret is hex (token_hex) — accept a generous hex range so a
# manually-pasted value from another device is allowed, but reject obviously
# malformed input early with a clear message.
_HEX_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")


def _current_secret() -> Optional[str]:
    """The secret currently in effect (env wins over file), or None."""
    return os.environ.get("ECOSYSTEM_HMAC_SECRET") or _read_secret_file()


def secret_status() -> dict:
    """Report whether a usable shared secret is configured — never its value.

    ``source`` is "env", "file", or None. ``path`` is where the UI tells the
    user the file lives. ``masked`` is a safe fingerprint (first 6 hex chars +
    length) so a user can confirm two devices match without exposing the key."""
    env = os.environ.get("ECOSYSTEM_HMAC_SECRET")
    file_val = _read_secret_file()
    current = env or file_val
    configured = bool(current) and current != DEFAULT_DEV_SECRET
    masked = None
    if configured and current:
        masked = f"{current[:6]}…({len(current)} chars)"
    return {
        "configured": configured,
        "source": "env" if env else ("file" if file_val else None),
        "path": str(secret_file_path()),
        "masked": masked,
    }


def apply_secret(value: str, allow_overwrite: bool = False) -> dict:
    """Validate and persist a pasted secret. Returns the new status.

    Raises ``ValueError`` for malformed input, the dev default, or an attempt to
    change an already-configured secret without ``allow_overwrite`` (overwrite
    protection — the route gates this to a confirmed, loopback request)."""
    value = (value or "").strip()
    if not value:
        raise ValueError("Secret is empty.")
    if value == DEFAULT_DEV_SECRET:
        raise ValueError(
            "That is the known development default — refused. Generate a unique "
            "value instead."
        )
    if not _HEX_RE.match(value):
        raise ValueError(
            "Secret must be 32–128 hexadecimal characters (e.g. the output of "
            "`ecosystem secret generate`)."
        )

    existing = _current_secret()
    if (
        existing
        and existing != DEFAULT_DEV_SECRET
        and existing != value
        and not allow_overwrite
    ):
        raise ValueError(
            "A different shared secret is already configured. Re-submit with "
            "overwrite confirmed to replace it (this will break auth with peers "
            "that still use the old secret)."
        )

    write_secret(value)
    return secret_status()


def generate_secret() -> dict:
    """Generate, persist, and return a fresh secret (PRIMARY device only).

    Unlike :func:`secret_status`, this returns the raw value once so the user can
    copy it to other devices. Callers must gate this to the first/primary host —
    a joining device should *paste* the existing secret, not mint a new one."""
    value = generate_secure_token(32)
    write_secret(value)
    status = secret_status()
    status["secret"] = value  # returned exactly once, for copy-to-other-devices
    return status
