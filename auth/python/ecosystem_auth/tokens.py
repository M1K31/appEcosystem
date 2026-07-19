"""
HMAC-SHA256 token generation and verification.

Extracted from OpenEye's ecosystem_security.py for cross-project reuse.
All projects in the ecosystem use the same HMAC secret for inter-service auth.
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Optional

# Known insecure development default. There is intentionally NO automatic
# fallback to it — a committed shared secret is a forgeable credential. The
# constant is kept only so we can explicitly reject it if someone sets it.
DEFAULT_DEV_SECRET = "dev-ecosystem-secret-change-in-production"

# Single source of truth for the shared secret on a device. Every service
# (launchd, systemd, or shell) reads this same file at runtime, so writing it
# once provisions the whole machine — no launchctl setenv / per-plist env needed.
# Override the location with ECOSYSTEM_SECRET_FILE.
import pathlib


def secret_file_path() -> "pathlib.Path":
    return pathlib.Path(
        os.environ.get("ECOSYSTEM_SECRET_FILE", "")
        or (pathlib.Path.home() / ".config" / "ecosystem" / "secret.env")
    )


def _read_secret_file() -> Optional[str]:
    """Read ECOSYSTEM_HMAC_SECRET from the shared secret file, if present."""
    p = secret_file_path()
    try:
        if not p.exists():
            return None
        for raw in p.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            if line.startswith("ECOSYSTEM_HMAC_SECRET="):
                val = line.split("=", 1)[1].strip().strip('"').strip("'")
                return val or None
    except Exception:
        return None
    return None


def _validate_secret(secret: str) -> str:
    if secret == DEFAULT_DEV_SECRET:
        raise RuntimeError(
            "Refusing the known development default secret. "
            "Set a unique generated value (e.g. `ecosystem secret generate`)."
        )
    return secret


def get_ecosystem_secret(override: Optional[str] = None) -> str:
    """
    Resolve the shared HMAC secret. Resolution order:
        explicit override -> ECOSYSTEM_HMAC_SECRET env -> ~/.config/ecosystem/secret.env

    Fail-closed: there is no built-in default. If none is found (or it is the
    known development default), a RuntimeError is raised rather than trusting a
    guessable key. Provision one with `ecosystem secret generate` / `import`.
    """
    secret = override or os.environ.get("ECOSYSTEM_HMAC_SECRET") or _read_secret_file()
    if not secret:
        raise RuntimeError(
            "No ecosystem secret found (checked override, ECOSYSTEM_HMAC_SECRET, "
            f"and {secret_file_path()}). A shared secret is required and there is "
            "no default. Run `ecosystem secret generate` (or `ecosystem secret "
            "import <value>` on additional devices)."
        )
    return _validate_secret(secret)


def write_secret(value: str) -> "pathlib.Path":
    """Persist a secret to the shared file (chmod 600). Returns the path."""
    value = _validate_secret(value.strip())
    if not value:
        raise ValueError("Refusing to write an empty secret")
    p = secret_file_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"ECOSYSTEM_HMAC_SECRET={value}\n")
    try:
        p.chmod(0o600)
    except Exception:
        pass
    return p


def ensure_ecosystem_secret() -> str:
    """Return the existing shared secret, or generate+persist one (install-time).

    Unlike get_ecosystem_secret (read-only, runtime), this MAY create the secret
    file — use it from installers / the `ecosystem secret` CLI, never per-request.
    """
    existing = (
        os.environ.get("ECOSYSTEM_HMAC_SECRET") or _read_secret_file()
    )
    if existing and existing != DEFAULT_DEV_SECRET:
        return existing
    generated = secrets.token_hex(32)
    write_secret(generated)
    return generated


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure hex token."""
    return secrets.token_hex(length)


def hash_token(token: str) -> str:
    """Create a one-way SHA-256 hash of a token for secure storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def verify_token_hash(token: str, token_hash: str) -> bool:
    """Verify a token against its stored hash using constant-time comparison."""
    return hmac.compare_digest(hash_token(token), token_hash)


def sign_payload(payload: dict, secret: str) -> str:
    """
    Sign a payload with HMAC-SHA256.

    The payload is JSON-serialized with sorted keys for deterministic output,
    ensuring the same payload produces the same signature across Python and JS.
    """
    message = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def verify_signature(payload: dict, signature: str, secret: str) -> bool:
    """Verify the HMAC-SHA256 signature of a payload (constant-time comparison)."""
    expected = sign_payload(payload, secret)
    return hmac.compare_digest(expected, signature)


def _canonical_path(url: str) -> str:
    """Return a host-independent canonical path (path + sorted query)."""
    from urllib.parse import urlsplit, parse_qsl, urlencode

    parts = urlsplit(url)
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return parts.path + (f"?{query}" if query else "")


def canonical_body_digest(body: Optional[dict]) -> str:
    """SHA-256 of the canonical JSON form of a request body.

    Hashing the re-serialized (sorted, compact) form makes the digest
    independent of on-the-wire JSON formatting, so client and server agree.
    A missing/empty body hashes as ``{}``.
    """
    obj = body if body else {}
    message = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(message).hexdigest()


def _request_payload(method: str, url: str, ts: int, nonce: str, body: Optional[dict]) -> dict:
    """Build the canonical dict that is signed for a request."""
    return {
        "method": method.upper(),
        "path": _canonical_path(url),
        "ts": ts,
        "nonce": nonce,
        "body_sha256": canonical_body_digest(body),
    }


# Header names for the replay-resistant request signature scheme.
SIGNATURE_HEADER = "X-Ecosystem-Signature"
TIMESTAMP_HEADER = "X-Ecosystem-Timestamp"
NONCE_HEADER = "X-Ecosystem-Nonce"
KEY_ID_HEADER = "X-Ecosystem-Key-Id"


def sign_request(
    method: str,
    url: str,
    secret: str,
    body: Optional[dict] = None,
    ts: Optional[int] = None,
    nonce: Optional[str] = None,
    key_id: Optional[str] = None,
) -> dict:
    """Produce signature/timestamp/nonce headers for an authenticated request.

    The signed payload binds method, canonical path, a timestamp and a unique
    nonce, plus a digest of the body, so captured requests cannot be replayed.
    ``key_id`` (optional) is attached as a header to identify a per-app
    credential; it is NOT part of the signed payload.
    """
    ts = int(time.time()) if ts is None else ts
    nonce = nonce or secrets.token_hex(16)
    payload = _request_payload(method, url, ts, nonce, body)
    headers = {
        SIGNATURE_HEADER: sign_payload(payload, secret),
        TIMESTAMP_HEADER: str(ts),
        NONCE_HEADER: nonce,
    }
    if key_id:
        headers[KEY_ID_HEADER] = key_id
    return headers


def verify_request(
    method: str,
    url: str,
    secret: str,
    signature: Optional[str],
    timestamp: Optional[str],
    nonce: Optional[str],
    body: Optional[dict] = None,
    max_skew_seconds: int = 300,
    nonce_store: Optional["NonceStore"] = None,
) -> bool:
    """Verify a replay-resistant request signature.

    Checks the signature, that the timestamp is within ``max_skew_seconds`` of
    now, and (when a ``nonce_store`` is supplied) that the nonce has not been
    seen before within its retention window.
    """
    if not signature or not timestamp or not nonce:
        return False
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(int(time.time()) - ts) > max_skew_seconds:
        return False
    payload = _request_payload(method, url, ts, nonce, body)
    if not verify_signature(payload, signature, secret):
        return False
    if nonce_store is not None and not nonce_store.add_if_new(nonce):
        return False
    return True


class NonceStore:
    """In-memory nonce cache with time-based expiry for replay detection.

    Suitable for a single-process registry. For multi-instance deployments back
    this with a shared store (e.g. Redis) keyed by nonce with a TTL.
    """

    def __init__(self, ttl_seconds: int = 600):
        self.ttl = ttl_seconds
        self._seen: dict[str, float] = {}

    def add_if_new(self, nonce: str) -> bool:
        """Record a nonce; return False if it was already seen (a replay)."""
        now = time.time()
        self._purge(now)
        if nonce in self._seen:
            return False
        self._seen[nonce] = now
        return True

    def _purge(self, now: float) -> None:
        expired = [n for n, t in self._seen.items() if now - t > self.ttl]
        for n in expired:
            del self._seen[n]


def create_ecosystem_token(secret: str, service_name: str, ttl_seconds: int = 86400) -> dict:
    """
    Create a signed ecosystem token for inter-service communication.

    Returns a dict with token, issued_at, expires_at, and signature.
    """
    now = int(time.time())
    token = generate_secure_token()
    token_data = {
        "token": token,
        "service": service_name,
        "issued_at": now,
        "expires_at": now + ttl_seconds,
    }
    token_data["signature"] = sign_payload(
        {
            "token": token,
            "service": service_name,
            "issued_at": now,
            "expires_at": now + ttl_seconds,
        },
        secret,
    )
    return token_data


# Maximum acceptable token lifetime (issued_at -> expires_at). Even a correctly
# signed token is rejected if it claims a longer life, capping the blast radius
# of a leaked secret. Default is double the standard 24h validity.
MAX_TOKEN_LIFETIME_SECONDS = 172800  # 48h
# Tolerance for clock skew when checking issued_at is not in the future.
_CLOCK_SKEW_SECONDS = 60


def verify_ecosystem_token(token_data: dict, secret: str) -> bool:
    """
    Verify a signed ecosystem token is valid, unexpired, and sanely scoped.
    """
    now = int(time.time())

    issued_at = token_data.get("issued_at", 0)
    expires_at = token_data.get("expires_at", 0)

    # Expired, or issued in the future (beyond clock skew).
    if now > expires_at:
        return False
    if issued_at > now + _CLOCK_SKEW_SECONDS:
        return False
    # Reject implausibly long-lived tokens regardless of a valid signature.
    if expires_at - issued_at > MAX_TOKEN_LIFETIME_SECONDS:
        return False

    expected_payload = {
        "token": token_data.get("token", ""),
        "service": token_data.get("service", ""),
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    return verify_signature(expected_payload, token_data.get("signature", ""), secret)
