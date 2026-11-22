"""Verify and register a Model-Forge forged analyst model.

Model Forge (a separate AGPL project) produces a quantized model plus a signed
provenance manifest. This module re-implements the signed-payload bytes and
checks the Ed25519 signature with ``cryptography`` only -- it must never import
``model_forge`` (AGPL boundary).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

# Fields covered by the signature. Mirrors Model Forge's payload exactly:
# includes eval_scores; excludes signer_fingerprint and signature.
_SIGNED_FIELDS = (
    "model_id",
    "base_model",
    "tier",
    "method",
    "eval_scores",
    "gguf_file",
    "sha256",
    "created_at",
)


@dataclass
class RegisteredModel:
    model_id: str
    tier: int
    base_model: str
    manifest_sha256: str


def _payload_bytes(manifest: dict) -> bytes:
    try:
        payload = {k: manifest[k] for k in _SIGNED_FIELDS}
    except KeyError as exc:
        raise ValueError(f"manifest missing signed field: {exc.args[0]}") from exc
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def verify_forge_manifest(manifest: dict, *, public_key_b64: str) -> None:
    """Verify the manifest's Ed25519 signature. Raises ValueError on any problem."""
    if not public_key_b64 or not isinstance(public_key_b64, str):
        raise ValueError("a public key is required to verify a forged manifest")
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    signature = manifest.get("signature")
    if not signature or not isinstance(signature, str):
        raise ValueError("manifest is unsigned")
    try:
        sig = base64.b64decode(signature, validate=True)
        pub = ed25519.Ed25519PublicKey.from_public_bytes(
            base64.b64decode(public_key_b64, validate=True)
        )
    except (binascii.Error, ValueError, TypeError) as exc:
        raise ValueError(f"malformed signature or public key: {exc}") from exc
    payload = _payload_bytes(manifest)
    try:
        pub.verify(sig, payload)
    except InvalidSignature as exc:
        raise ValueError("manifest signature verification failed") from exc


def _default_ollama_create(model_id: str, modelfile_path: Path) -> None:
    try:
        subprocess.run(
            ["ollama", "create", model_id, "-f", str(modelfile_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("the 'ollama' binary was not found on PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"ollama create failed (exit {exc.returncode}): {(exc.stderr or '').strip()}"
        ) from exc


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def register_forged_model(
    output_dir: Path,
    *,
    public_key_b64: str,
    ollama_create: Callable[[str, Path], None] = _default_ollama_create,
) -> RegisteredModel:
    """Verify a forged model directory and register it with Ollama."""
    output_dir = Path(output_dir)
    manifest_path = output_dir / "manifest.json"
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read manifest: {manifest_path}") from exc
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError as exc:
        raise ValueError("manifest.json is not valid JSON") from exc

    verify_forge_manifest(manifest, public_key_b64=public_key_b64)

    gguf_name = manifest["gguf_file"]
    if not isinstance(gguf_name, str) or Path(gguf_name).name != gguf_name:
        raise ValueError("gguf_file must be a bare filename")
    try:
        actual = _sha256_file(output_dir / gguf_name)
    except OSError as exc:
        raise ValueError(f"cannot read model file: {gguf_name}") from exc
    if actual != manifest["sha256"]:
        raise ValueError("model file digest does not match the signed manifest")

    try:
        ollama_create(manifest["model_id"], output_dir / "Modelfile")
    except FileNotFoundError as exc:
        raise RuntimeError("the 'ollama' binary was not found on PATH") from exc

    return RegisteredModel(
        model_id=manifest["model_id"],
        tier=int(manifest["tier"]),
        base_model=manifest["base_model"],
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
    )
