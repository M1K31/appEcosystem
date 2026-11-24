"""Stock-model security analyst wrapper.

Asks the selected analyst model for action proposals and returns its RAW text.
It never parses or executes: callers validate with
``ecosystem_client.contracts.parse_proposals`` and policy/execution live elsewhere.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from .analyst_prompt import ANALYST_SYSTEM_PROMPT
from .analyst_select import resolve_analyst_model
from .hardware import HardwareInfo
from .profile import AIProfile
from .providers.base import ChatMessage
from .router import ProviderRouter


@dataclass
class AnalystReply:
    """Raw analyst output plus provenance.

    ``model`` is the REQUESTED/resolved analyst pick. ``served_model`` and
    ``provider`` are what ACTUALLY served this reply; they may differ from
    ``model`` until WP3 forces the resolved model to run and rejects mismatches.
    """

    text: str
    model: str
    source: str  # "stock" here; "forged" for a forged model
    served_model: str = ""
    provider: str = ""


def _render_user_message(request: str, context: dict) -> str:
    if not context:
        return request
    block = json.dumps(context, indent=2, sort_keys=True, default=str)
    return f"{request}\n\nContext:\n{block}"


async def propose(
    request: str,
    context: dict,
    *,
    router: ProviderRouter,
    profile: AIProfile,
    hw: HardwareInfo,
    floor_passes: set[str] | None = None,
) -> AnalystReply:
    model = resolve_analyst_model(profile, hw, floor_passes=floor_passes)
    messages = [
        ChatMessage(role="system", content=ANALYST_SYSTEM_PROMPT),
        ChatMessage(role="user", content=_render_user_message(request, context)),
    ]
    result = await router.chat(messages, task="security_analyst", model=model)
    if result.model != model:
        raise ValueError(
            f"served model {result.model!r} does not match resolved analyst model {model!r}"
        )
    return AnalystReply(
        text=result.text,
        model=model,
        source="stock",
        served_model=result.model,
        provider=result.provider,
    )
