"""FastAPI middleware/dependency for ecosystem authentication."""

import json
from typing import Callable, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .tokens import (
    KEY_ID_HEADER,
    NONCE_HEADER,
    NonceStore,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    get_ecosystem_secret,
    verify_request,
)

security_scheme = HTTPBearer(auto_error=False)

# Process-wide nonce cache for replay detection on the signature path.
_nonce_store = NonceStore()


async def _read_body_obj(request: Request) -> dict:
    raw = await request.body()
    if request.method in ("GET", "DELETE") or not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON body"
        )


async def authenticate_request(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials],
    key_resolver: Optional[Callable[[str], Optional[dict]]] = None,
) -> dict:
    """Verify an ecosystem-authenticated request and return its principal.

    Per-app path: when an ``X-Ecosystem-Key-Id`` header is present AND a
    ``key_resolver`` is supplied, resolve the app, verify the HMAC against the
    app's secret, and return that app's principal. Owner path: otherwise verify
    against the shared secret and return the ``__owner__`` principal. Bearer
    tokens are accepted as before. Raises ``HTTPException`` on any failure.
    """
    signature = request.headers.get(SIGNATURE_HEADER)
    if signature:
        timestamp = request.headers.get(TIMESTAMP_HEADER)
        nonce = request.headers.get(NONCE_HEADER)
        body_obj = await _read_body_obj(request)

        key_id = request.headers.get(KEY_ID_HEADER)
        if key_id and key_resolver is not None:
            principal = key_resolver(key_id)
            if not principal:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Unknown or suspended ecosystem key",
                )
            secret = principal["secret"]
            if not verify_request(
                request.method, str(request.url), secret, signature,
                timestamp, nonce, body_obj, nonce_store=_nonce_store,
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid, stale, or replayed ecosystem signature",
                )
            return {
                "auth_method": "hmac",
                "app_id": principal["app_id"],
                "scopes": list(principal.get("scopes", [])),
                "owned_names": list(principal.get("owned_names", [])),
                "payload": body_obj,
            }

        # Owner path: shared secret.
        secret = get_ecosystem_secret()
        if not verify_request(
            request.method, str(request.url), secret, signature,
            timestamp, nonce, body_obj, nonce_store=_nonce_store,
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid, stale, or replayed ecosystem signature",
            )
        return {
            "auth_method": "hmac",
            "app_id": "__owner__",
            "scopes": ["*"],
            "owned_names": ["*"],
            "payload": body_obj,
        }

    if credentials:
        from .tokens import verify_ecosystem_token

        try:
            token_data = json.loads(credentials.credentials)
        except (json.JSONDecodeError, TypeError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format"
            )
        if not verify_ecosystem_token(token_data, get_ecosystem_secret()):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired ecosystem token",
            )
        return {"auth_method": "token", "service": token_data.get("service")}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing ecosystem authentication",
    )


async def require_ecosystem_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> dict:
    """FastAPI dependency: validate an ecosystem-authenticated request (shared-secret/owner)."""
    return await authenticate_request(request, credentials, key_resolver=None)
