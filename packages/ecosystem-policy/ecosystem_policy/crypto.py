"""Ed25519 signing and verification for `policy.yaml` bundles and scoped override grants."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def default_policy_key_dir() -> Path:
    override = os.environ.get("ECOSYSTEM_POLICY_KEY_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".config" / "ecosystem"


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic UTF-8 JSON bytes excluding top-level `signature` fields."""
    clean = {k: v for k, v in payload.items() if k not in ("signature", "public_key")}
    return json.dumps(clean, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def public_key_fingerprint(public_key_b64: str) -> str:
    """SHA-256 hex fingerprint of a base64-encoded raw 32-byte Ed25519 public key."""
    raw = base64.urlsafe_b64decode(public_key_b64.encode("ascii") + b"===")
    return hashlib.sha256(raw).hexdigest()


class Ed25519PolicySigner:
    """Manages an Ed25519 `policy_admin` keypair for signing policy documents and override grants."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey | None = None,
        public_key: Ed25519PublicKey | None = None,
    ):
        self._priv = private_key
        self._pub = public_key or (private_key.public_key() if private_key else None)

    @classmethod
    def generate(cls) -> "Ed25519PolicySigner":
        priv = Ed25519PrivateKey.generate()
        return cls(private_key=priv, public_key=priv.public_key())

    @classmethod
    def load_or_create(cls, key_dir: str | Path | None = None) -> "Ed25519PolicySigner":
        base = Path(key_dir) if key_dir else default_policy_key_dir()
        base.mkdir(parents=True, exist_ok=True)
        priv_path = base / "policy_ed25519.key"
        pub_path = base / "policy_ed25519.pub"

        if priv_path.is_file():
            raw_priv = base64.urlsafe_b64decode(priv_path.read_text(encoding="ascii").strip() + "===")
            priv = Ed25519PrivateKey.from_private_bytes(raw_priv)
            return cls(private_key=priv, public_key=priv.public_key())

        signer = cls.generate()
        priv_path.write_text(signer.export_private_b64() + "\n", encoding="ascii")
        pub_path.write_text(signer.export_public_b64() + "\n", encoding="ascii")
        for p in (priv_path, pub_path):
            try:
                os.chmod(p, 0o600 if p == priv_path else 0o644)
            except OSError:
                pass
        return signer

    @classmethod
    def from_public_b64(cls, pub_b64: str) -> "Ed25519PolicySigner":
        raw = base64.urlsafe_b64decode(pub_b64.strip().encode("ascii") + b"===")
        return cls(private_key=None, public_key=Ed25519PublicKey.from_public_bytes(raw))

    def export_private_b64(self) -> str:
        if self._priv is None:
            raise RuntimeError("Private key is not loaded on verifier-only Ed25519PolicySigner")
        raw = self._priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    def export_public_b64(self) -> str:
        if self._pub is None:
            raise RuntimeError("Public key is not loaded")
        raw = self._pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    @property
    def fingerprint(self) -> str:
        """SHA-256 hex fingerprint of this signer's public key."""
        return public_key_fingerprint(self.export_public_b64())

    def sign_dict(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._priv is None:
            raise RuntimeError("Ed25519 private key required to sign policy or override grant")
        sig = self._priv.sign(canonical_json_bytes(payload))
        signed = dict(payload)
        signed["signature"] = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
        signed["public_key"] = self.export_public_b64()
        return signed

    def verify_dict(self, signed_payload: dict[str, Any], *, trusted_public_b64: str | None = None) -> bool:
        sig_b64 = signed_payload.get("signature")
        if not sig_b64 or not isinstance(sig_b64, str):
            return False
        pub_key = self._pub
        if trusted_public_b64:
            raw_pub = base64.urlsafe_b64decode(trusted_public_b64.strip().encode("ascii") + b"===")
            pub_key = Ed25519PublicKey.from_public_bytes(raw_pub)
        elif pub_key is None and signed_payload.get("public_key"):
            raw_pub = base64.urlsafe_b64decode(str(signed_payload["public_key"]).strip().encode("ascii") + b"===")
            pub_key = Ed25519PublicKey.from_public_bytes(raw_pub)
        if pub_key is None:
            return False
        try:
            sig = base64.urlsafe_b64decode(sig_b64.strip().encode("ascii") + b"===")
            pub_key.verify(sig, canonical_json_bytes(signed_payload))
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False

