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
    text: str
    model: str
    source: str  # "stock" here; "forged" for a forged model


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
) -> AnalystReply:
    model = resolve_analyst_model(profile, hw)
    messages = [
        ChatMessage(role="system", content=ANALYST_SYSTEM_PROMPT),
        ChatMessage(role="user", content=_render_user_message(request, context)),
    ]
    result = await router.chat(messages, task="security_analyst")
    return AnalystReply(text=result.text, model=model, source="stock")
