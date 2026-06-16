"""FastAPI middleware/dependency for ecosystem authentication."""

import json
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .tokens import (
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


async def require_ecosystem_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> dict:
    """
    FastAPI dependency that validates ecosystem HMAC-signed requests.

    Checks the X-Ecosystem-Signature header against the request body or URL/method,
    or validates a Bearer token from the Authorization header.
    """
    secret = get_ecosystem_secret()

    # Check HMAC signature header (replay-resistant request scheme).
    signature = request.headers.get(SIGNATURE_HEADER)
    if signature:
        timestamp = request.headers.get(TIMESTAMP_HEADER)
        nonce = request.headers.get(NONCE_HEADER)

        raw = await request.body()
        if request.method in ("GET", "DELETE") or not raw:
            body_obj: dict = {}
        else:
            try:
                body_obj = json.loads(raw)
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid JSON body",
                )

        if not verify_request(
            request.method,
            str(request.url),
            secret,
            signature,
            timestamp,
            nonce,
            body_obj,
            nonce_store=_nonce_store,
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid, stale, or replayed ecosystem signature",
            )
        return {"auth_method": "hmac", "payload": body_obj}

    # Check Bearer token (for service-to-service calls)
    if credentials:
        from .tokens import verify_ecosystem_token

        try:
            token_data = json.loads(credentials.credentials)
        except (json.JSONDecodeError, TypeError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format",
            )
        if not verify_ecosystem_token(token_data, secret):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired ecosystem token",
            )
        return {"auth_method": "token", "service": token_data.get("service")}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing ecosystem authentication",
    )
