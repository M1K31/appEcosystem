"""Step-up authentication (RFC 6238 TOTP 2FA + WebAuthn Passkey / Ed25519 Device Key assertions).

Used across management UIs (`appEcosystem` Hub, `OpenEye`, `AI-for-Survival`, `AegisSIEM`,
`cyber-agents`) to gate high-consequence actions:
  - Turning `Policy restrictions: Off (authorized scope)`
  - Resuming from `Freeze`
  - Approving or denying `contain` / `remediate` / `data_release` / `system_change` checkpoints

Security trade-off:
  - Adds an explicit 6-digit TOTP or hardware Passkey prompt (5-minute step-up session lease),
    introducing minor UX friction in exchange for preventing stolen browser sessions, ambient
    wall displays, prompt injections, or spoofed voice commands from escalating privileges.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


# ---- RFC 6238 TOTP (Zero external dependencies beyond Python stdlib) --------

def generate_totp_secret(num_bytes: int = 20) -> str:
    """Generate a Base32-encoded 160-bit TOTP secret compatible with Google/Apple Authenticator."""
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode("ascii").rstrip("=")


def build_otpauth_uri(secret_b32: str, account_name: str, issuer: str = "appEcosystem") -> str:
    label = quote(f"{issuer}:{account_name}")
    return f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def _decode_b32(secret_b32: str) -> bytes:
    cleaned = secret_b32.strip().replace(" ", "").upper()
    pad = "=" * ((8 - len(cleaned) % 8) % 8)
    return base64.b32decode(cleaned + pad, casefold=True)


def compute_totp(secret_b32: str, *, timestamp: float | None = None, period: int = 30, digits: int = 6) -> str:
    ts = int(time.time() if timestamp is None else timestamp)
    counter = ts // period
    key = _decode_b32(secret_b32)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


class StepUpAuthenticator:
    """Persists enrolled operator TOTP / Passkey / Device-Key credentials and issues short-lived step-up tokens."""

    def __init__(
        self,
        store_path: str | Path | None = None,
        *,
        signing_secret: str | None = None,
        token_ttl_seconds: int = 300,
    ):
        default_dir = Path(os.environ.get("ECOSYSTEM_POLICY_KEY_DIR") or (Path.home() / ".config" / "ecosystem"))
        self.store_path = Path(store_path) if store_path else (default_dir / "step_up_credentials.json")
        self._signing_secret = signing_secret
        self.token_ttl_seconds = max(30, int(token_ttl_seconds))
        self._lock = threading.RLock()
        self._used_totp_windows: dict[str, int] = {}
        self._challenges: dict[str, dict[str, Any]] = {}

    def _secret(self) -> str:
        if self._signing_secret:
            return self._signing_secret
        from ecosystem_auth.tokens import get_ecosystem_secret

        return get_ecosystem_secret()

    def _load(self) -> dict[str, Any]:
        if not self.store_path.is_file():
            return {"operators": {}}
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("operators"), dict):
                return data
        except Exception:
            pass
        return {"operators": {}}

    def _save(self, data: dict[str, Any]) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.store_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.store_path)

    # ---- TOTP Enrollment & Verification -------------------------------------

    def enroll_totp(self, operator_id: str, *, issuer: str = "appEcosystem") -> dict[str, str]:
        secret = generate_totp_secret()
        with self._lock:
            data = self._load()
            op = data["operators"].setdefault(operator_id, {"passkeys": {}, "device_keys": {}})
            op["totp_secret"] = secret
            op["totp_enrolled_at"] = time.time()
            self._save(data)
        return {
            "operator_id": operator_id,
            "secret": secret,
            "otpauth_uri": build_otpauth_uri(secret, operator_id, issuer=issuer),
        }

    def has_enrolled_factors(self, operator_id: str) -> dict[str, bool]:
        with self._lock:
            op = self._load()["operators"].get(operator_id, {})
            return {
                "totp": bool(op.get("totp_secret")),
                "passkey": bool(op.get("passkeys")),
                "device_key": bool(op.get("device_keys")),
            }

    def verify_totp_and_issue_token(
        self,
        operator_id: str,
        code: str,
        *,
        scope: str = "policy_admin",
        now: float | None = None,
        drift_windows: int = 1,
    ) -> dict[str, Any] | None:
        ts = time.time() if now is None else now
        cleaned = str(code or "").strip().replace(" ", "")
        if len(cleaned) != 6 or not cleaned.isdigit():
            return None

        with self._lock:
            op = self._load()["operators"].get(operator_id, {})
            secret = op.get("totp_secret")
            if not secret:
                return None

            base_window = int(ts) // 30
            matched_window: int | None = None
            for delta in range(-drift_windows, drift_windows + 1):
                win_ts = (base_window + delta) * 30
                if hmac.compare_digest(compute_totp(secret, timestamp=win_ts), cleaned):
                    matched_window = base_window + delta
                    break

            if matched_window is None:
                return None

            replay_key = f"{operator_id}:{matched_window}"
            if self._used_totp_windows.get(replay_key):
                return None
            self._used_totp_windows[replay_key] = matched_window

        return self.issue_step_up_token(operator_id, auth_method="totp", scope=scope, now=ts)

    # ---- WebAuthn Passkey (ES256 P-256 / Ed25519 PEM or Raw Public Key) -----

    def register_passkey(
        self,
        operator_id: str,
        credential_id: str,
        public_key_pem_or_b64: str,
        *,
        algorithm: str = "ES256",
        label: str = "Operator Passkey",
    ) -> dict[str, Any]:
        """Register a WebAuthn Passkey (ES256 P-256 PEM or Ed25519 raw b64) or iOS Shortcut device key."""
        with self._lock:
            data = self._load()
            op = data["operators"].setdefault(operator_id, {"passkeys": {}, "device_keys": {}})
            rec = {
                "credential_id": credential_id,
                "public_key": public_key_pem_or_b64.strip(),
                "algorithm": algorithm.upper(),
                "label": label,
                "registered_at": time.time(),
            }
            op.setdefault("passkeys", {})[credential_id] = rec
            self._save(data)
            return dict(rec)

    def create_challenge(self, operator_id: str, *, ttl_seconds: int = 120) -> dict[str, Any]:
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
        now = time.time()
        with self._lock:
            # Prune expired challenges
            self._challenges = {k: v for k, v in self._challenges.items() if v["expires_at"] > now}
            self._challenges[challenge] = {
                "operator_id": operator_id,
                "expires_at": now + ttl_seconds,
            }
        return {"challenge": challenge, "expires_at": now + ttl_seconds}

    def verify_passkey_assertion_and_issue_token(
        self,
        operator_id: str,
        credential_id: str,
        challenge: str,
        signature_b64: str,
        *,
        authenticator_data_b64: str | None = None,
        client_data_json_b64: str | None = None,
        scope: str = "policy_admin",
    ) -> dict[str, Any] | None:
        """Verify either a full WebAuthn assertion (`authenticatorData || SHA256(clientDataJSON)`) or direct challenge signature."""
        now = time.time()
        with self._lock:
            ch = self._challenges.pop(challenge, None)
            if not ch or ch["operator_id"] != operator_id or ch["expires_at"] < now:
                return None
            op = self._load()["operators"].get(operator_id, {})
            cred = op.get("passkeys", {}).get(credential_id)
            if not cred:
                return None

        try:
            sig = base64.urlsafe_b64decode(signature_b64.strip().encode("ascii") + b"===")
            if authenticator_data_b64 and client_data_json_b64:
                auth_data = base64.urlsafe_b64decode(authenticator_data_b64.encode("ascii") + b"===")
                client_json = base64.urlsafe_b64decode(client_data_json_b64.encode("ascii") + b"===")
                parsed_client = json.loads(client_json.decode("utf-8"))
                if parsed_client.get("challenge") != challenge:
                    return None
                signed_bytes = auth_data + hashlib.sha256(client_json).digest()
            else:
                signed_bytes = challenge.encode("ascii")

            alg = cred["algorithm"]
            pub_str = cred["public_key"]
            if alg == "ED25519":
                raw_pub = base64.urlsafe_b64decode(pub_str.encode("ascii") + b"===")
                pub = ed25519.Ed25519PublicKey.from_public_bytes(raw_pub)
                pub.verify(sig, signed_bytes)
            else:
                pub = serialization.load_pem_public_key(pub_str.encode("utf-8"))
                if not isinstance(pub, ec.EllipticCurvePublicKey):
                    return None
                pub.verify(sig, signed_bytes, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError, TypeError, KeyError):
            return None

        method = "device_key" if cred.get("algorithm") == "ED25519" and "shortcut" in cred.get("label", "").lower() else "passkey"
        return self.issue_step_up_token(operator_id, auth_method=method, scope=scope, now=now)

    # ---- Signed Step-Up Lease Tokens ----------------------------------------

    def issue_step_up_token(
        self,
        operator_id: str,
        *,
        auth_method: str,
        scope: str = "policy_admin",
        now: float | None = None,
    ) -> dict[str, Any]:
        if auth_method not in ("totp", "passkey", "device_key"):
            raise ValueError(f"Unsupported step-up auth_method: {auth_method}")
        ts = int(time.time() if now is None else now)
        exp = ts + self.token_ttl_seconds
        payload = {
            "sub": operator_id,
            "amr": auth_method,
            "scope": scope,
            "iat": ts,
            "exp": exp,
            "jti": secrets.token_hex(12),
        }
        body_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")
        sig = hmac.new(self._secret().encode("utf-8"), body_b64.encode("ascii"), hashlib.sha256).hexdigest()
        return {
            "step_up_token": f"{body_b64}.{sig}",
            "operator_id": operator_id,
            "auth_method": auth_method,
            "scope": scope,
            "expires_at": exp,
        }

    def verify_step_up_token(
        self,
        token: str,
        *,
        required_scope: str | None = None,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        if not token or "." not in token:
            return None
        body_b64, sig = token.split(".", 1)
        expected = hmac.new(self._secret().encode("utf-8"), body_b64.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        try:
            raw = base64.urlsafe_b64decode(body_b64.encode("ascii") + b"===")
            claims = json.loads(raw.decode("utf-8"))
        except Exception:
            return None
        ts = time.time() if now is None else now
        if claims.get("exp", 0) < ts:
            return None
        if claims.get("amr") not in ("totp", "passkey", "device_key"):
            return None
        if required_scope and claims.get("scope") not in (required_scope, "policy_admin", "*"):
            return None
        return claims

