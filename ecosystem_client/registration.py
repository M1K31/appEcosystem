"""Self-service registration for third-party apps joining the ecosystem.

A third-party app calls `register_app` once to obtain its own HMAC key from the
hub. The key it gets back is PENDING: it authenticates nothing until the
ecosystem owner approves the app and assigns it the service names and scopes it
may hold. After approval the app signs its requests with the returned
`key_id` + `secret` using `ecosystem_auth.tokens.sign_request(..., key_id=key_id)`.

    from ecosystem_client.registration import register_app, save_credentials, load_credentials

    creds = load_credentials(path)
    if creds is None:
        creds = register_app("https://hub.local:8500", "org.widget",
                             requested_names=["widget_sensor"],
                             requested_scopes=["commands:dispatch"])
        save_credentials(path, creds)   # keep the secret; it is shown only once
    # ... wait for the owner to approve, then sign requests with creds["key_id"]/["secret"].
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable, Optional

__all__ = ["register_app", "save_credentials", "load_credentials"]


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", ""}


def _require_secure_transport(registry_url: str, *, allow_insecure: bool) -> None:
    """Raise ValueError if the URL would send the secret in cleartext to a non-loopback host."""
    if allow_insecure:
        return
    from urllib.parse import urlsplit

    parts = urlsplit(registry_url if "://" in registry_url else f"//{registry_url}")
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    if scheme == "https":
        return
    if host in _LOOPBACK_HOSTS or host.endswith(".localhost"):
        return
    raise ValueError(
        f"refusing to register over plaintext {scheme or 'http'}:// to non-loopback host "
        f"{host!r}: the HMAC secret would be exposed on the wire. Use https://, or pass "
        f"allow_insecure=True only on a trusted private network."
    )


def register_app(
    registry_url: str,
    app_id: str,
    *,
    display_name: Optional[str] = None,
    owner: str = "",
    requested_names: Optional[list[str]] = None,
    requested_scopes: Optional[list[str]] = None,
    timeout: float = 10.0,
    allow_insecure: bool = False,
    client_factory: Optional[Callable[[], Any]] = None,
) -> dict[str, Any]:
    """Register `app_id` with the hub and return its credentials.

    Returns a dict with `app_id`, `key_id`, `secret` and `status` ("pending").
    The names and scopes are only a request for the owner to review; the key
    holds nothing until approved. Raises `httpx.HTTPStatusError` if the hub
    refuses (e.g. 409 when `app_id` already exists — it is never overwritten).

    The response carries the app's reusable HMAC `secret`, so plaintext `http://`
    to a non-loopback hub is refused (`ValueError`): on the wire the secret would
    be readable by anyone on the path. Use `https://` for a remote hub. Plain
    `http://localhost` / `127.0.0.1` / `[::1]` is allowed (the loopback never
    leaves the machine); `allow_insecure=True` overrides the check for a trusted
    private network and is not recommended.
    """
    import httpx

    _require_secure_transport(registry_url, allow_insecure=allow_insecure)
    payload = {
        "app_id": app_id,
        "display_name": display_name or app_id,
        "owner": owner,
        "requested_names": list(requested_names or []),
        "requested_scopes": list(requested_scopes or []),
    }
    url = f"{registry_url.rstrip('/')}/apps/register"
    client_cm = client_factory() if client_factory is not None else httpx.Client(timeout=timeout)
    with client_cm as client:
        resp = client.post(url, json=payload)
    resp.raise_for_status()
    return resp.json()


def save_credentials(path: str | Path, creds: dict[str, Any]) -> None:
    """Write `{app_id, key_id, secret}` to `path` as JSON, mode 0600 (it holds a secret)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    keep = {k: creds[k] for k in ("app_id", "key_id", "secret") if k in creds}
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".creds.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(keep, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def load_credentials(path: str | Path) -> Optional[dict[str, Any]]:
    """Load credentials previously saved by `save_credentials`, or None if absent/unreadable."""
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
