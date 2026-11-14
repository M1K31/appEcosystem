"""Mount a CommandReceiver on apps that are not FastAPI.

`build_command_router` (in command_receiver) covers FastAPI apps. The ecosystem
also has a Flask app (AegisSIEM) and an aiohttp app (cyber-harness); these
adapters let them expose the same `POST /ecosystem/commands` without taking on
FastAPI. aiohttp and Flask are imported inside the builders, so neither is a
dependency of this package (install the `provider-aiohttp` / `provider-flask`
extra in the app that uses one).

`build_receiver_from_env` builds a receiver wired to confirm approvals and
context claims with the hub, or returns None when no ecosystem secret is
configured (the app then mounts no command route and runs standalone).
"""
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Awaitable, Callable

from .command_receiver import CommandReceiver, HubApprovalVerifier

logger = logging.getLogger(__name__)

__all__ = ["build_aiohttp_handler", "build_flask_view", "build_receiver_from_env"]


def build_aiohttp_handler(receiver: CommandReceiver) -> Callable[[Any], Awaitable[Any]]:
    """An aiohttp POST handler for `receiver`, for `app.router.add_post(path, handler)`."""
    from aiohttp import web

    async def handler(request: "web.Request") -> "web.Response":
        try:
            envelope = await request.json()
        except Exception:
            envelope = None
        status_code, body = await receiver.handle(envelope)
        return web.json_response(body, status=status_code)

    return handler


def build_flask_view(
    receiver: CommandReceiver,
    loop: asyncio.AbstractEventLoop,
    *,
    timeout: float = 60.0,
) -> Callable[[], tuple[dict[str, Any], int]]:
    """A Flask view for `receiver`.

    Flask handles each request on a worker thread, while `receiver.handle` is a
    coroutine; it is submitted to `loop` (the app's own asyncio loop thread) and
    awaited there. A handler that does not answer within `timeout` returns a
    `failed` body with `outcome_unknown` and HTTP 504 — the command may still be
    running on the loop, so its outcome is genuinely unknown.
    """
    from flask import request

    def view() -> tuple[dict[str, Any], int]:
        envelope = request.get_json(silent=True)
        future = asyncio.run_coroutine_threadsafe(receiver.handle(envelope), loop)
        try:
            status_code, body = future.result(timeout=timeout)
        except TimeoutError:
            future.cancel()
            command_id = envelope.get("id") if isinstance(envelope, dict) else None
            return (
                {
                    "command_id": command_id if isinstance(command_id, str) else None,
                    "status": "failed",
                    "result": None,
                    "error": f"the command did not finish within {timeout:g}s",
                    "decision": None,
                    "duplicate": False,
                    "outcome_unknown": True,
                },
                504,
            )
        return body, status_code

    return view


def build_receiver_from_env(
    app_name: str,
    *,
    policy_engine: Any,
    replay_db_path: str | Path,
    registry_url: str | None = None,
    secret: str | None = None,
) -> CommandReceiver | None:
    """A CommandReceiver for `app_name`, or None when no ecosystem secret is set.

    The secret comes from `secret`, else `ECOSYSTEM_HMAC_SECRET` / the ecosystem
    secret file. Without one the app has no ecosystem identity, so it mounts no
    command route and runs standalone. With one, the receiver confirms both
    approvals and incident/profile context claims with the hub.
    """
    secret = secret or _resolve_secret()
    if not secret:
        logger.info("No ecosystem secret configured; %s mounts no command route.", app_name)
        return None

    registry_url = registry_url or os.environ.get("ECOSYSTEM_REGISTRY_URL") or "http://localhost:8500"
    verifier = HubApprovalVerifier(registry_url, secret, app_name=app_name)
    return CommandReceiver(
        app_name,
        secret=secret,
        policy_engine=policy_engine,
        replay_db_path=replay_db_path,
        approval_verifier=verifier,
        context_verifier=verifier.confirm_context,
    )


def _resolve_secret() -> str:
    try:
        from ecosystem_auth.tokens import get_ecosystem_secret

        return get_ecosystem_secret() or ""
    except Exception:
        return os.environ.get("ECOSYSTEM_HMAC_SECRET", "") or ""
