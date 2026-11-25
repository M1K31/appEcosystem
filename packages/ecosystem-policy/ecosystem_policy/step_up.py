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
        max_totp_failures: int = 5,
        totp_lockout_seconds: int = 900,
    ):
        default_dir = Path(os.environ.get("ECOSYSTEM_POLICY_KEY_DIR") or (Path.home() / ".config" / "ecosystem"))
        self.store_path = Path(store_path) if store_path else (default_dir / "step_up_credentials.json")
        self._signing_secret = signing_secret
        self.token_ttl_seconds = max(30, int(token_ttl_seconds))
        # TOTP brute-force throttle: a 6-digit code is only ~1e6 combinations and
        # the drift window widens that, so unlimited attempts are brute-forceable.
        # Track recent failures per operator (in-memory, like _used_totp_windows)
        # and refuse once the threshold is hit within the lockout window.
        self.max_totp_failures = max(1, int(max_totp_failures))
        self.totp_lockout_seconds = max(1, int(totp_lockout_seconds))
        self._lock = threading.RLock()
        self._used_totp_windows: dict[str, int] = {}
        self._totp_failures: dict[str, list[float]] = {}
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

    def has_any_enrolled_operator(self) -> bool:
        """True if ANY operator has ANY enrolled factor (i.e. the store is
        bootstrapped). Lets callers gate step-up enrollment so that only the very
        first factor on an empty store is a loopback-only bootstrap, without having
        to assume a canonical operator id such as ``admin``."""
        with self._lock:
            for op in self._load()["operators"].values():
                if op.get("totp_secret") or op.get("passkeys") or op.get("device_keys"):
                    return True
            return False

    def list_operators(self) -> list[dict[str, Any]]:
        """Return non-secret summaries of enrolled operators and their factors."""
        with self._lock:
            operators = self._load()["operators"]
            result: list[dict[str, Any]] = []
            for op_id in sorted(operators):
                op = operators[op_id] or {}
                result.append(
                    {
                        "operator_id": op_id,
                        "totp": bool(op.get("totp_secret")),
                        "passkey_count": len(op.get("passkeys") or {}),
                        "device_key_count": len(op.get("device_keys") or {}),
                        "totp_enrolled_at": op.get("totp_enrolled_at"),
                    }
                )
            return result

    def reset_totp(self, operator_id: str) -> bool:
        """Local-only recovery: remove an operator's enrolled TOTP secret and clear lockouts.

        Preserves passkeys and device keys. Returns True if a TOTP secret was
        present and removed, False otherwise.
        """
        op_id = str(operator_id or "").strip()
        if not op_id:
            return False
        with self._lock:
            data = self._load()
            op = data["operators"].get(op_id)
            if not isinstance(op, dict) or not op.get("totp_secret"):
                return False
            op.pop("totp_secret", None)
            op.pop("totp_enrolled_at", None)
            self._save(data)
            prefix = f"{op_id}:"
            for key in [k for k in self._used_totp_windows if k.startswith(prefix)]:
                self._used_totp_windows.pop(key, None)
            self._totp_failures.pop(op_id, None)
            return True

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
            # Enforce the per-operator lockout before touching the secret.
            recent_failures = [
                t for t in self._totp_failures.get(operator_id, [])
                if t > ts - self.totp_lockout_seconds
            ]
            if len(recent_failures) >= self.max_totp_failures:
                self._totp_failures[operator_id] = recent_failures
                return None

            op = self._load()["operators"].get(operator_id, {})
            secret = op.get("totp_secret")
            if not secret:
                # No enrolled secret: nothing to brute-force, so don't accrue a
                # lockout (which would otherwise aid account enumeration/DoS).
                return None

            def _record_failure() -> None:
                recent_failures.append(ts)
                self._totp_failures[operator_id] = recent_failures

            base_window = int(ts) // 30
            matched_window: int | None = None
            for delta in range(-drift_windows, drift_windows + 1):
                win_ts = (base_window + delta) * 30
                if hmac.compare_digest(compute_totp(secret, timestamp=win_ts), cleaned):
                    matched_window = base_window + delta
                    break

            if matched_window is None:
                _record_failure()
                return None

            replay_key = f"{operator_id}:{matched_window}"
            if self._used_totp_windows.get(replay_key):
                _record_failure()
                return None
            self._used_totp_windows[replay_key] = matched_window
            # Successful verification clears the failure counter.
            self._totp_failures.pop(operator_id, None)

        return self.issue_step_up_token(operator_id, auth_method="totp", scope=scope, now=ts)

    # ---- WebAuthn Passkey (ES256 P-256 / Ed25519 PEM, SPKI DER, or Raw Key) -

    @staticmethod
    def _is_allowed_webauthn_origin(origin: str, expected_origin: str | None = None) -> bool:
        """WebAuthn is permitted only on expected_origin (if set) or loopback origins."""
        from urllib.parse import urlparse

        raw = str(origin or "").strip().rstrip("/")
        if not raw:
            return False
        if expected_origin:
            exp = str(expected_origin).strip().rstrip("/")
            try:
                parsed = urlparse(exp)
            except Exception:
                return False
            is_valid_scheme = parsed.scheme == "https" or (
                parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1")
            )
            return is_valid_scheme and raw == exp
        try:
            parsed = urlparse(raw)
        except Exception:
            return False
        if parsed.scheme in ("http", "https") and parsed.hostname in ("localhost", "127.0.0.1", "::1"):
            return True
        return False

    @staticmethod
    def _normalize_passkey_public_key(
        public_key_pem_or_b64: str,
        *,
        algorithm: str = "ES256",
        public_key_spki_b64: str | None = None,
    ) -> tuple[str, str]:
        """Normalize a PEM, raw Ed25519 b64, or browser SPKI DER base64url key.

        Returns ``(stored_public_key, resolved_algorithm)``.
        """
        if public_key_spki_b64:
            der = base64.urlsafe_b64decode(public_key_spki_b64.strip().encode("ascii") + b"===")
            pub = serialization.load_der_public_key(der)
            if isinstance(pub, ed25519.Ed25519PublicKey):
                raw_bytes = pub.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                return base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("="), "ED25519"
            if isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP256R1):
                pem = pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("ascii")
                return pem.strip(), "ES256"
            raise ValueError("Unsupported WebAuthn public key type (expected P-256 ES256 or Ed25519)")
        return public_key_pem_or_b64.strip(), algorithm.upper()

    def register_passkey(
        self,
        operator_id: str,
        credential_id: str,
        public_key_pem_or_b64: str = "",
        *,
        algorithm: str = "ES256",
        label: str = "Operator Passkey",
        public_key_spki_b64: str | None = None,
        rp_id: str = "localhost",
        transports: list[str] | None = None,
        registration_challenge: str | None = None,
    ) -> dict[str, Any]:
        """Register a WebAuthn Passkey (ES256 P-256 PEM/SPKI or Ed25519) or iOS Shortcut device key."""
        stored_key, resolved_alg = self._normalize_passkey_public_key(
            public_key_pem_or_b64,
            algorithm=algorithm,
            public_key_spki_b64=public_key_spki_b64,
        )
        if not stored_key:
            raise ValueError("A valid public key (PEM, raw Ed25519 b64, or SPKI DER b64url) is required")
        now = time.time()
        with self._lock:
            if registration_challenge is not None:
                ch = self._challenges.pop(registration_challenge, None)
                if (
                    not ch
                    or ch.get("operator_id") != operator_id
                    or ch.get("purpose") != "registration"
                    or ch.get("expires_at", 0) < now
                ):
                    raise ValueError("Invalid or expired registration challenge")
            data = self._load()
            op = data["operators"].setdefault(operator_id, {"passkeys": {}, "device_keys": {}})
            rec = {
                "credential_id": credential_id,
                "public_key": stored_key,
                "algorithm": resolved_alg,
                "label": label,
                "rp_id": str(rp_id or "localhost").strip(),
                "transports": list(transports or []),
                "sign_count": 0,
                "registered_at": now,
            }
            op.setdefault("passkeys", {})[credential_id] = rec
            self._save(data)
            return dict(rec)

    def list_passkeys(self, operator_id: str) -> list[dict[str, Any]]:
        """Return non-secret metadata for an operator's enrolled passkeys."""
        with self._lock:
            op = self._load()["operators"].get(operator_id, {})
            passkeys = op.get("passkeys") or {}
            return [
                {
                    "credential_id": cid,
                    "label": rec.get("label", "Operator Passkey"),
                    "algorithm": rec.get("algorithm", "ES256"),
                    "rp_id": rec.get("rp_id", "localhost"),
                    "transports": list(rec.get("transports") or []),
                    "sign_count": int(rec.get("sign_count", 0)),
                    "registered_at": rec.get("registered_at"),
                }
                for cid, rec in sorted(passkeys.items())
            ]

    def remove_passkey(self, operator_id: str, credential_id: str) -> bool:
        """Remove a single enrolled passkey by credential_id."""
        with self._lock:
            data = self._load()
            op = data["operators"].get(operator_id)
            if not isinstance(op, dict):
                return False
            removed = (op.get("passkeys") or {}).pop(credential_id, None) is not None
            if removed:
                self._save(data)
            return removed

    def create_challenge(
        self,
        operator_id: str,
        *,
        ttl_seconds: int = 120,
        purpose: str = "authentication",
        rp_id: str | None = None,
    ) -> dict[str, Any]:
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
        now = time.time()
        with self._lock:
            # Prune expired challenges
            self._challenges = {k: v for k, v in self._challenges.items() if v["expires_at"] > now}
            self._challenges[challenge] = {
                "operator_id": operator_id,
                "expires_at": now + ttl_seconds,
                "purpose": purpose,
                "rp_id": rp_id,
            }
        return {"challenge": challenge, "expires_at": now + ttl_seconds}

    def create_passkey_registration_options(
        self,
        operator_id: str,
        *,
        rp_id: str = "localhost",
        rp_name: str = "appEcosystem",
        display_name: str | None = None,
        ttl_seconds: int = 120,
    ) -> dict[str, Any]:
        """Build WebAuthn PublicKeyCredentialCreationOptions for Touch ID / Face ID / YubiKey."""
        ch = self.create_challenge(operator_id, ttl_seconds=ttl_seconds, purpose="registration", rp_id=rp_id)
        existing = self.list_passkeys(operator_id)
        user_id_b64 = base64.urlsafe_b64encode(
            hashlib.sha256(f"appecosystem:{operator_id}".encode("utf-8")).digest()
        ).decode("ascii").rstrip("=")
        return {
            "challenge": ch["challenge"],
            "expires_at": ch["expires_at"],
            "rp": {"id": rp_id, "name": rp_name},
            "user": {
                "id": user_id_b64,
                "name": operator_id,
                "displayName": display_name or operator_id,
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},   # ES256 (P-256)
                {"type": "public-key", "alg": -8},   # EdDSA (Ed25519)
            ],
            "timeout": int(ttl_seconds * 1000),
            "attestation": "none",
            "authenticatorSelection": {
                "residentKey": "preferred",
                "userVerification": "required",
            },
            "excludeCredentials": [
                {"type": "public-key", "id": p["credential_id"]}
                for p in existing
            ],
        }

    def create_passkey_authentication_options(
        self,
        operator_id: str,
        *,
        rp_id: str = "localhost",
        ttl_seconds: int = 120,
    ) -> dict[str, Any]:
        """Build WebAuthn PublicKeyCredentialRequestOptions for step-up verification."""
        ch = self.create_challenge(operator_id, ttl_seconds=ttl_seconds, purpose="authentication", rp_id=rp_id)
        existing = self.list_passkeys(operator_id)
        return {
            "challenge": ch["challenge"],
            "expires_at": ch["expires_at"],
            "rpId": rp_id,
            "timeout": int(ttl_seconds * 1000),
            "userVerification": "required",
            "allowCredentials": [
                {
                    "type": "public-key",
                    "id": p["credential_id"],
                    **({"transports": p["transports"]} if p.get("transports") else {}),
                }
                for p in existing
            ],
        }

    def verify_passkey_assertion_and_issue_token(
        self,
        operator_id: str,
        credential_id: str,
        challenge: str,
        signature_b64: str,
        *,
        authenticator_data_b64: str | None = None,
        client_data_json_b64: str | None = None,
        expected_origin: str | None = None,
        expected_rp_id: str | None = None,
        require_user_verification: bool = False,
        scope: str = "policy_admin",
    ) -> dict[str, Any] | None:
        """Verify either a full WebAuthn assertion (`authenticatorData || SHA256(clientDataJSON)`) or direct challenge signature."""
        now = time.time()
        with self._lock:
            ch = self._challenges.pop(challenge, None)
            if (
                not ch
                or ch["operator_id"] != operator_id
                or ch["expires_at"] < now
                or ch.get("purpose", "authentication") != "authentication"
            ):
                return None
            op = self._load()["operators"].get(operator_id, {})
            cred = op.get("passkeys", {}).get(credential_id)
            if not cred:
                return None

        new_sign_count: int | None = None
        try:
            sig = base64.urlsafe_b64decode(signature_b64.strip().encode("ascii") + b"===")
            has_webauthn_fields = bool(authenticator_data_b64 and client_data_json_b64)
            if not has_webauthn_fields and (
                require_user_verification
                or expected_origin is not None
                or expected_rp_id is not None
                or authenticator_data_b64
                or client_data_json_b64
            ):
                return None

            if has_webauthn_fields:
                auth_data = base64.urlsafe_b64decode(authenticator_data_b64.encode("ascii") + b"===")
                client_json = base64.urlsafe_b64decode(client_data_json_b64.encode("ascii") + b"===")
                if len(auth_data) < 37:
                    return None
                parsed_client = json.loads(client_json.decode("utf-8"))
                if parsed_client.get("challenge") != challenge:
                    return None
                if parsed_client.get("type") != "webauthn.get":
                    return None
                origin = parsed_client.get("origin")
                if not self._is_allowed_webauthn_origin(str(origin or ""), expected_origin):
                    return None

                rp_id_hash = auth_data[:32]
                flags = auth_data[32]
                sign_count = struct.unpack(">I", auth_data[33:37])[0]
                rp_to_check = expected_rp_id or ch.get("rp_id")
                if rp_to_check:
                    expected_hash = hashlib.sha256(str(rp_to_check).encode("utf-8")).digest()
                    if not hmac.compare_digest(rp_id_hash, expected_hash):
                        return None
                # User Present (UP, bit 0x01) is required on full authenticatorData
                if not (flags & 0x01):
                    return None
                # User Verified (UV, bit 0x04) when requested
                if require_user_verification and not (flags & 0x04):
                    return None
                new_sign_count = sign_count
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

        if new_sign_count is not None:
            with self._lock:
                data = self._load()
                stored = data["operators"].get(operator_id, {}).get("passkeys", {}).get(credential_id)
                if not isinstance(stored, dict):
                    return None
                latest_count = int(stored.get("sign_count", 0))
                if (latest_count > 0 or new_sign_count > 0) and new_sign_count <= latest_count:
                    return None
                if new_sign_count > latest_count:
                    stored["sign_count"] = new_sign_count
                    self._save(data)

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

