"""ECO-02: Cryptographic Node Auto-Pairing with interactive ECDSA public key pinning.

Enables new LAN nodes discovered via mDNS to join an appEcosystem hub without
manual secret copy-paste:
  1. Hub and joining node each hold an ECDSA P-256 identity keypair.
  2. Joining node submits a pairing request containing its P-256 public key.
  3. Both sides deterministically derive the same 6-digit Short Authentication
     String (SAS) and SHA-256 public-key fingerprints so an operator can
     visually verify authenticity before pinning.
  4. Operator approves and pins the node's public key (requiring matching SAS
     or fingerprint, and refused while PolicyEngine is frozen).
  5. Hub encrypts the ecosystem secret using ECDH (P-256) + HKDF-SHA256 +
     AES-256-GCM bound to (pairing_id, node_id).
  6. Joining node proves possession of its private key via an ECDSA signature
     and claims the ciphertext once (wiped immediately after pickup).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_SAFE_NODE_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
_PAIRING_HKDF_INFO = b"appecosystem-node-pairing-v1"
_MAX_PENDING_REQUESTS = 20
_MAX_PENDING_PER_NODE = 2


def _write_private_file(path: Path, content: bytes) -> None:
    """Atomically write a sensitive file with 0o600 permissions from creation."""
    tmp = path.with_suffix(f".{secrets.token_hex(6)}.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(text: str) -> bytes:
    cleaned = str(text or "").strip()
    pad = "=" * ((4 - len(cleaned) % 4) % 4)
    return base64.urlsafe_b64decode(cleaned.encode("ascii") + pad.encode("ascii"))


def generate_ecdsa_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Generate a new ECDSA P-256 private key and return (private_key, public_key_pem)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return priv, pub_pem


def load_ecdsa_public_key(public_key_pem: str) -> ec.EllipticCurvePublicKey:
    """Parse and validate a P-256 ECDSA PEM public key."""
    pub = serialization.load_pem_public_key(public_key_pem.strip().encode("utf-8"))
    if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
        raise ValueError("Node pairing requires an ECDSA P-256 (SECP256R1) PEM public key")
    return pub


def public_key_fingerprint(public_key_pem: str) -> str:
    """Return canonical SHA-256 fingerprint (sha256:<hex>) of the SPKI DER public key."""
    pub = load_ecdsa_public_key(public_key_pem)
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(der).hexdigest()


def compute_sas_code(hub_public_key_pem: str, node_public_key_pem: str, pairing_id: str) -> str:
    """Compute a deterministic 6-digit Short Authentication String (SAS) for interactive pinning."""
    hub_der = load_ecdsa_public_key(hub_public_key_pem).public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    node_der = load_ecdsa_public_key(node_public_key_pem).public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(hub_der + b"|" + node_der + b"|" + pairing_id.encode("utf-8")).digest()
    code_int = int.from_bytes(digest[:4], "big") % 1_000_000
    return f"{code_int:06d}"


def _derive_pairing_aes_key(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey,
    pairing_id: str,
) -> bytes:
    shared = private_key.exchange(ec.ECDH(), peer_public_key)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=pairing_id.encode("utf-8"),
        info=_PAIRING_HKDF_INFO,
    )
    return hkdf.derive(shared)


def encrypt_paired_secret(
    hub_private_key: ec.EllipticCurvePrivateKey,
    node_public_key_pem: str,
    *,
    pairing_id: str,
    node_id: str,
    secret_value: str,
) -> dict[str, str]:
    """Encrypt the ecosystem secret for ``node_public_key_pem`` via ECDH + HKDF-SHA256 + AES-256-GCM."""
    node_pub = load_ecdsa_public_key(node_public_key_pem)
    aes_key = _derive_pairing_aes_key(hub_private_key, node_pub, pairing_id)
    nonce = secrets.token_bytes(12)
    aad = f"{pairing_id}:{node_id}".encode("utf-8")
    ct = AESGCM(aes_key).encrypt(nonce, secret_value.encode("utf-8"), aad)
    return {"nonce_b64": _b64u(nonce), "ciphertext_b64": _b64u(ct)}


def decrypt_paired_secret(
    node_private_key: ec.EllipticCurvePrivateKey,
    hub_public_key_pem: str,
    *,
    pairing_id: str,
    node_id: str,
    nonce_b64: str,
    ciphertext_b64: str,
) -> str:
    """Decrypt the ecosystem secret on the joining node after verifying hub identity."""
    hub_pub = load_ecdsa_public_key(hub_public_key_pem)
    aes_key = _derive_pairing_aes_key(node_private_key, hub_pub, pairing_id)
    nonce = _b64u_decode(nonce_b64)
    ct = _b64u_decode(ciphertext_b64)
    aad = f"{pairing_id}:{node_id}".encode("utf-8")
    plaintext = AESGCM(aes_key).decrypt(nonce, ct, aad)
    return plaintext.decode("utf-8")


def sign_claim_proof(node_private_key: ec.EllipticCurvePrivateKey, pairing_id: str, node_id: str) -> str:
    """Sign proof-of-possession message on the joining node to claim its encrypted secret."""
    msg = f"claim:{pairing_id}:{node_id}".encode("utf-8")
    sig = node_private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
    return _b64u(sig)


class NodePairingManager:
    """Manages hub ECDSA P-256 identity, pending pairing requests, and pinned LAN nodes."""

    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.key_path = self.data_dir / "node_pairing_key.pem"
        self.store_path = self.data_dir / "paired_nodes.json"
        self._lock = threading.RLock()
        self._private_key = self._load_or_create_key()
        self._hub_public_key_pem = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self._hub_fingerprint = public_key_fingerprint(self._hub_public_key_pem)
        self._pending: dict[str, dict[str, Any]] = {}

    @property
    def hub_public_key_pem(self) -> str:
        return self._hub_public_key_pem

    @property
    def hub_fingerprint(self) -> str:
        return self._hub_fingerprint

    def _load_or_create_key(self) -> ec.EllipticCurvePrivateKey:
        if self.key_path.is_file():
            key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
            if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1):
                return key
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        _write_private_file(self.key_path, pem)
        return key

    def _load_pinned(self) -> dict[str, dict[str, Any]]:
        if not self.store_path.is_file():
            return {}
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError(f"Pinned node store at {self.store_path} is unreadable or corrupt") from exc
        if not isinstance(data, dict) or not isinstance(data.get("nodes"), dict):
            raise RuntimeError(f"Pinned node store at {self.store_path} has invalid structure")
        return data["nodes"]

    def _save_pinned(self, nodes: dict[str, dict[str, Any]]) -> None:
        raw = json.dumps({"schema_version": 1, "nodes": nodes}, indent=2, sort_keys=True).encode("utf-8")
        _write_private_file(self.store_path, raw)

    def _prune_expired(self, now: float) -> None:
        expired = [pid for pid, rec in self._pending.items() if rec["expires_at"] <= now]
        for pid in expired:
            self._pending.pop(pid, None)

    def request_pairing(
        self,
        *,
        node_id: str,
        public_key_pem: str,
        hostname: str = "",
        roles: list[str] | None = None,
        ttl_seconds: int = 300,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Create a time-boxed pending pairing request from a LAN node."""
        nid = str(node_id or "").strip()
        if not _SAFE_NODE_ID_RE.match(nid):
            raise ValueError(f"Invalid node_id: {nid!r}")
        node_fp = public_key_fingerprint(public_key_pem)
        ts = time.time() if now is None else now
        ttl = max(30, min(900, int(ttl_seconds)))

        with self._lock:
            self._prune_expired(ts)
            node_pending = [
                pid for pid, r in self._pending.items()
                if r["node_id"] == nid and r["status"] == "pending"
            ]
            if len(node_pending) >= _MAX_PENDING_PER_NODE:
                raise RuntimeError(f"Too many pending pairing requests for node '{nid}'")
            if len(self._pending) >= _MAX_PENDING_REQUESTS:
                raise RuntimeError("Too many pending pairing requests; wait for expiry or resolve existing requests")
            pairing_id = secrets.token_urlsafe(16)
            sas = compute_sas_code(self._hub_public_key_pem, public_key_pem, pairing_id)
            rec = {
                "pairing_id": pairing_id,
                "node_id": nid,
                "hostname": str(hostname or nid).strip()[:128],
                "roles": [str(r).strip() for r in (roles or ["edge"]) if str(r).strip()][:10],
                "public_key_pem": public_key_pem.strip(),
                "node_fingerprint": node_fp,
                "hub_fingerprint": self._hub_fingerprint,
                "sas_code": sas,
                "status": "pending",
                "created_at": ts,
                "expires_at": ts + ttl,
                "encrypted_bundle": None,
                "claimed": False,
            }
            self._pending[pairing_id] = rec
            return {
                "pairing_id": pairing_id,
                "node_id": nid,
                "hub_public_key_pem": self._hub_public_key_pem,
                "hub_fingerprint": self._hub_fingerprint,
                "node_fingerprint": node_fp,
                "sas_code": sas,
                "expires_at": rec["expires_at"],
                "status": "pending",
            }

    def list_pending(self, *, now: float | None = None) -> list[dict[str, Any]]:
        ts = time.time() if now is None else now
        with self._lock:
            self._prune_expired(ts)
            return [
                {
                    "pairing_id": rec["pairing_id"],
                    "node_id": rec["node_id"],
                    "hostname": rec["hostname"],
                    "roles": list(rec["roles"]),
                    "node_fingerprint": rec["node_fingerprint"],
                    "sas_code": rec["sas_code"],
                    "status": rec["status"],
                    "created_at": rec["created_at"],
                    "expires_at": rec["expires_at"],
                }
                for rec in self._pending.values()
                if rec["status"] == "pending"
            ]

    def approve_pairing(
        self,
        pairing_id: str,
        *,
        secret_value: str,
        approved_by: str,
        expected_sas: str | None = None,
        expected_fingerprint: str | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Interactively pin the node's ECDSA public key and encrypt the shared secret for it."""
        if not secret_value:
            raise ValueError("Hub ecosystem secret is unavailable; cannot complete pairing")
        if not expected_fingerprint:
            raise ValueError("Interactive pinning requires expected_fingerprint (full SHA-256 public key fingerprint)")

        if expected_sas is not None:
            sas_str = str(expected_sas).strip()
            if not sas_str.isascii() or len(sas_str) != 6 or not sas_str.isdigit():
                raise ValueError("expected_sas must be a 6-digit ASCII string")
        else:
            sas_str = None
        fp_str = str(expected_fingerprint).strip().lower()
        if not fp_str.isascii() or not fp_str.startswith("sha256:"):
            raise ValueError("expected_fingerprint must be an ASCII sha256:... string")

        ts = time.time() if now is None else now
        with self._lock:
            self._prune_expired(ts)
            rec = self._pending.get(pairing_id)
            if not rec or rec["status"] != "pending":
                raise KeyError("Pairing request not found or no longer pending")
            if sas_str is not None and not hmac.compare_digest(sas_str, rec["sas_code"]):
                # Single-attempt SAS: invalidate immediately on mismatch to prevent brute force
                self._pending.pop(pairing_id, None)
                raise PermissionError("SAS code mismatch — pairing request invalidated (possible MITM)")
            if not hmac.compare_digest(fp_str, rec["node_fingerprint"].lower()):
                self._pending.pop(pairing_id, None)
                raise PermissionError("Public key fingerprint mismatch — pairing request invalidated (possible MITM)")

            # Encrypt the bundle FIRST so any crypto error leaves the pin store untouched
            bundle = encrypt_paired_secret(
                self._private_key,
                rec["public_key_pem"],
                pairing_id=pairing_id,
                node_id=rec["node_id"],
                secret_value=secret_value,
            )

            # Persist the pin BEFORE making the encrypted bundle claimable
            nodes = self._load_pinned()
            prev = nodes.get(rec["node_id"]) if isinstance(nodes.get(rec["node_id"]), dict) else {}
            pin_entry: dict[str, Any] = {
                "node_id": rec["node_id"],
                "hostname": rec["hostname"],
                "roles": list(rec["roles"]),
                "public_key_pem": rec["public_key_pem"],
                "fingerprint": rec["node_fingerprint"],
                "paired_by": approved_by,
                "paired_at": ts,
            }
            if prev.get("claimed_at") is not None:
                pin_entry["claimed_at"] = prev["claimed_at"]
            nodes[rec["node_id"]] = pin_entry
            self._save_pinned(nodes)

            rec["encrypted_bundle"] = bundle
            rec["status"] = "approved"
            rec["approved_by"] = approved_by
            rec["approved_at"] = ts

            return {
                "pairing_id": pairing_id,
                "node_id": rec["node_id"],
                "node_fingerprint": rec["node_fingerprint"],
                "status": "approved",
                "paired_by": approved_by,
            }

    def reject_pairing(self, pairing_id: str) -> bool:
        """Reject a pairing request only while it is still pending (never silently drop an approved pin)."""
        with self._lock:
            rec = self._pending.get(pairing_id)
            if not rec or rec.get("status") != "pending":
                return False
            self._pending.pop(pairing_id, None)
            return True

    def claim_pairing(
        self,
        pairing_id: str,
        *,
        node_id: str,
        signature_b64: str,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Verify the joining node's ECDSA proof-of-possession and return the encrypted secret ONCE."""
        ts = time.time() if now is None else now
        with self._lock:
            self._prune_expired(ts)
            rec = self._pending.get(pairing_id)
            if not rec or rec["status"] != "approved" or rec["claimed"] or not rec["encrypted_bundle"]:
                raise KeyError("Approved pairing bundle not available (pending, expired, or already claimed)")
            if rec["node_id"] != str(node_id).strip():
                raise PermissionError("node_id does not match pairing request")
            pinned = self._load_pinned().get(rec["node_id"])
            if not pinned or pinned.get("public_key_pem") != rec["public_key_pem"]:
                raise PermissionError("Pairing approval was revoked or superseded by a newer pin")

            pub = load_ecdsa_public_key(rec["public_key_pem"])
            msg = f"claim:{pairing_id}:{rec['node_id']}".encode("utf-8")
            try:
                sig = _b64u_decode(signature_b64)
                pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            except (InvalidSignature, ValueError, TypeError) as exc:
                raise PermissionError("Invalid ECDSA proof-of-possession signature") from exc

            # Persist claimed_at BEFORE consuming the approved request so a write failure
            # does not lose the one-time bundle without recording delivery.
            nodes = self._load_pinned()
            if rec["node_id"] in nodes:
                nodes[rec["node_id"]]["claimed_at"] = ts
                self._save_pinned(nodes)

            bundle = dict(rec["encrypted_bundle"])
            rec["encrypted_bundle"] = None
            rec["claimed"] = True
            rec["status"] = "claimed"
            self._pending.pop(pairing_id, None)

            return {
                "pairing_id": pairing_id,
                "node_id": rec["node_id"],
                "hub_public_key_pem": self._hub_public_key_pem,
                "hub_fingerprint": self._hub_fingerprint,
                "nonce_b64": bundle["nonce_b64"],
                "ciphertext_b64": bundle["ciphertext_b64"],
            }

    def list_paired_nodes(self) -> list[dict[str, Any]]:
        with self._lock:
            nodes = self._load_pinned()
            return [dict(nodes[nid]) for nid in sorted(nodes.keys())]

    def revoke_node_details(self, node_id: str) -> dict[str, Any] | None:
        """Revoke a pinned node, invalidate unclaimed bundles, and return the removed record (or None)."""
        nid = str(node_id).strip()
        with self._lock:
            nodes = self._load_pinned()
            removed_rec = nodes.pop(nid, None)
            if removed_rec is not None:
                self._save_pinned(nodes)
            # Invalidate any unclaimed approvals/requests for this node
            for pid in [k for k, r in self._pending.items() if r.get("node_id") == nid]:
                self._pending.pop(pid, None)
            return dict(removed_rec) if isinstance(removed_rec, dict) else None

    def revoke_node(self, node_id: str) -> bool:
        return self.revoke_node_details(node_id) is not None
