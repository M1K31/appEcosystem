"""Ecosystem shared authentication - HMAC-SHA256 token generation and verification."""

from .tokens import (
    NonceStore,
    ensure_ecosystem_secret,
    generate_secure_token,
    get_ecosystem_secret,
    hash_token,
    secret_file_path,
    sign_request,
    verify_request,
    verify_token_hash,
    sign_payload,
    verify_signature,
    write_secret,
)
from .middleware import require_ecosystem_auth

__all__ = [
    "NonceStore",
    "ensure_ecosystem_secret",
    "generate_secure_token",
    "get_ecosystem_secret",
    "hash_token",
    "secret_file_path",
    "sign_request",
    "verify_request",
    "verify_token_hash",
    "sign_payload",
    "verify_signature",
    "write_secret",
    "require_ecosystem_auth",
]
