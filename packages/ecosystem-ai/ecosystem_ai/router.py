"""Provider/model routing.

Resolves which provider and model serve a request from the shared profile, the
hardware tier, and the registered providers — preferring local (Ollama) by
default, with optional fallback to a cloud provider. Callers get a uniform
ChatResult regardless of what served it.
"""

from __future__ import annotations

from typing import Optional

from .hardware import CapabilityTier, recommended_model
from .profile import AIProfile
from .providers.base import AIProvider, ChatMessage, ChatResult, ProviderError


class ProviderRouter:
    def __init__(
        self,
        profile: AIProfile,
        providers: dict[str, AIProvider],
        tier: Optional[CapabilityTier] = None,
    ):
        self.profile = profile
        self.providers = providers
        self.tier = tier

    def resolve_model(self, task: str = "chat") -> str:
        """Resolve the model for a task: explicit task model → selected_model →
        hardware-tier default. 'auto' resolves to the tier's recommended model."""
        model = self.profile.task_models.get(task, "auto")
        if (not model or model == "auto") and task == "chat":
            model = self.profile.selected_model
        if not model or model == "auto":
            model = recommended_model(self.tier) if self.tier is not None else ""
        return model

    def _ordered_providers(self) -> list[str]:
        """Provider preference order based on profile.prefer."""
        default = self.profile.default_provider
        cloud = [name for name, c in self.profile.cloud.items() if c.enabled]
        if self.profile.prefer == "cloud":
            return cloud + [default]
        # local-first (default) and "quality" both start local here
        order = [default] + cloud
        return order

    async def pick(self, task: str = "chat") -> tuple[AIProvider, str]:
        """Choose an available provider + model for the task."""
        order = self._ordered_providers()
        allow_fallback = self.profile.allow_cloud_fallback
        first_choice = order[0] if order else None

        for idx, name in enumerate(order):
            provider = self.providers.get(name)
            if provider is None:
                continue
            # Only try beyond the first choice if fallback is allowed.
            if idx > 0 and not allow_fallback:
                break
            if await provider.available():
                model = self.resolve_model(task)
                if name != self.profile.default_provider:
                    # Cloud provider: use its configured model if set.
                    cfg = self.profile.cloud.get(name)
                    if cfg and cfg.model:
                        model = cfg.model
                return provider, model

        raise ProviderError(
            f"no available provider for task '{task}' "
            f"(tried: {', '.join(order) or 'none'}; first choice: {first_choice})"
        )

    async def chat(
        self,
        messages: list[ChatMessage],
        task: str = "chat",
        *,
        tools: Optional[list[dict]] = None,
    ) -> ChatResult:
        provider, model = await self.pick(task)
        return await provider.chat(messages, model=model, tools=tools)
