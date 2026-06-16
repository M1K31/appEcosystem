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

# Insecure development default. The ecosystem refuses to start with this value
# unless ECOSYSTEM_ENV is "dev" (see get_ecosystem_secret).
DEFAULT_DEV_SECRET = "dev-ecosystem-secret-change-in-production"


def get_ecosystem_secret(override: Optional[str] = None) -> str:
    """
    Resolve the shared HMAC secret from an explicit override or the environment.

    Single source of truth for every service (registry, event bus, command
    router, middleware). Fails closed: if the resolved secret is the known
    development default and ECOSYSTEM_ENV is anything other than "dev", a
    RuntimeError is raised rather than silently trusting a public key.
    """
    secret = override or os.environ.get("ECOSYSTEM_HMAC_SECRET", DEFAULT_DEV_SECRET)
    if secret == DEFAULT_DEV_SECRET and os.environ.get("ECOSYSTEM_ENV", "dev") != "dev":
        raise RuntimeError(
            "Refusing to start: ECOSYSTEM_HMAC_SECRET is unset or set to the "
            "insecure default. Generate one with "
            "`python -c \"import secrets; print(secrets.token_hex(32))\"` "
            "and export ECOSYSTEM_HMAC_SECRET."
        )
    return secret


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


def sign_request(
    method: str,
    url: str,
    secret: str,
    body: Optional[dict] = None,
    ts: Optional[int] = None,
    nonce: Optional[str] = None,
) -> dict:
    """Produce signature/timestamp/nonce headers for an authenticated request.

    The signed payload binds method, canonical path, a timestamp and a unique
    nonce, plus a digest of the body, so captured requests cannot be replayed.
    """
    ts = int(time.time()) if ts is None else ts
    nonce = nonce or secrets.token_hex(16)
    payload = _request_payload(method, url, ts, nonce, body)
    return {
        SIGNATURE_HEADER: sign_payload(payload, secret),
        TIMESTAMP_HEADER: str(ts),
        NONCE_HEADER: nonce,
    }


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


def verify_ecosystem_token(token_data: dict, secret: str) -> bool:
    """
    Verify a signed ecosystem token is valid and not expired.
    """
    now = int(time.time())
    if now > token_data.get("expires_at", 0):
        return False

    expected_payload = {
        "token": token_data.get("token", ""),
        "service": token_data.get("service", ""),
        "issued_at": token_data.get("issued_at", 0),
        "expires_at": token_data.get("expires_at", 0),
    }
    return verify_signature(expected_payload, token_data.get("signature", ""), secret)
