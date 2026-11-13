"""Zero-dependency Crockford Base32 monotonic ULID generator and device ID helper."""
from __future__ import annotations

import os
import re
import secrets
import socket
import threading
import time

CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_MAP = {ch: idx for idx, ch in enumerate(CROCKFORD_ALPHABET)}
_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_MAX_TIME_MS = (1 << 48) - 1
_MAX_ENTROPY = (1 << 80) - 1

_lock = threading.Lock()
_last_ms = -1
_last_entropy = 0


def _encode_base32(value: int, length: int) -> str:
    chars = ["0"] * length
    for idx in range(length - 1, -1, -1):
        chars[idx] = CROCKFORD_ALPHABET[value & 0x1F]
        value >>= 5
    return "".join(chars)


def generate_ulid(timestamp_ms: int | None = None) -> str:
    """Generate a 26-character lexicographically sortable Crockford Base32 ULID.

    Within the same millisecond in a process, the 80-bit random component is
    monotonically incremented under a lock so sequential IDs sort strictly in
    creation order.
    """
    global _last_ms, _last_entropy

    now_ms = int(time.time() * 1000) if timestamp_ms is None else int(timestamp_ms)
    if now_ms < 0 or now_ms > _MAX_TIME_MS:
        raise ValueError(f"ULID timestamp_ms out of 48-bit range: {now_ms}")

    with _lock:
        if timestamp_ms is None and now_ms == _last_ms:
            entropy = _last_entropy + 1
            if entropy > _MAX_ENTROPY:
                # Extremely unlikely 80-bit overflow within 1 ms: advance 1 ms.
                now_ms += 1
                entropy = int.from_bytes(secrets.token_bytes(10), "big")
        else:
            entropy = int.from_bytes(secrets.token_bytes(10), "big")
        _last_ms = now_ms
        _last_entropy = entropy

    return _encode_base32(now_ms, 10) + _encode_base32(entropy, 16)


def is_ulid(value: object) -> bool:
    """Return True if value is a canonical 26-char uppercase Crockford Base32 ULID."""
    if not isinstance(value, str) or not _ULID_RE.match(value):
        return False
    # Leading char encodes top 2 bits of 48-bit timestamp (must be <= '7').
    return _CROCKFORD_MAP[value[0]] <= 7


def ulid_timestamp_ms(ulid_str: str) -> int:
    """Extract the 48-bit Unix millisecond timestamp from a valid ULID."""
    if not is_ulid(ulid_str):
        raise ValueError(f"Invalid ULID: {ulid_str!r}")
    ts = 0
    for ch in ulid_str[:10]:
        ts = (ts << 5) | _CROCKFORD_MAP[ch]
    return ts


def resolve_device_id() -> str:
    """Resolve the local device identifier for event/command source metadata."""
    env_id = (os.environ.get("ECOSYSTEM_DEVICE_ID") or "").strip()
    if env_id:
        return env_id
    try:
        host = (socket.gethostname() or "").strip()
        if host:
            return host
    except Exception:
        pass
    return "local-device"

