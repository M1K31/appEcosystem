"""Ecosystem shared authentication - HMAC-SHA256 token generation and verification."""

from .tokens import (
    NonceStore,
    generate_secure_token,
    get_ecosystem_secret,
    hash_token,
    sign_request,
    verify_request,
    verify_token_hash,
    sign_payload,
    verify_signature,
)
from .middleware import require_ecosystem_auth

__all__ = [
    "NonceStore",
    "generate_secure_token",
    "get_ecosystem_secret",
    "hash_token",
    "sign_request",
    "verify_request",
    "verify_token_hash",
    "sign_payload",
    "verify_signature",
    "require_ecosystem_auth",
]
