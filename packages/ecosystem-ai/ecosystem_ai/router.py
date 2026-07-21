"""Provider/model routing.

Resolves which provider and model serve a request from the shared profile, the
hardware tier, and the registered providers — preferring local (Ollama) by
default, with optional fallback to a cloud provider. Callers get a uniform
ChatResult regardless of what served it.
"""

from __future__ import annotations

import logging
from typing import Optional

from .hardware import CapabilityTier, recommended_model
from .profile import AIProfile
from .providers.base import AIProvider, ChatMessage, ChatResult, ProviderError

logger = logging.getLogger(__name__)


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

    async def _ensure_local_model(self, provider: AIProvider, wanted: str) -> str:
        """Return a model that is actually usable on the local provider.

        resolve_model() yields the tier's *recommended* model, which may not be
        installed — every call would then 404. Resolution order, deliberately
        conservative so it never overrides a real choice:

          1. The wanted model is installed -> use it (unchanged behaviour).
          2. Something is installed -> stay local and use what is in use:
             the profile's explicitly selected model when that is installed,
             otherwise an installed model. Never downloads.
          3. Nothing is installed at all (genuine first run) -> pull the
             recommended model and use it.

        Only case 3 downloads, so an existing setup is never surprised by a
        multi-gigabyte pull, and case 1 means a working configuration is left
        exactly as it was.
        """
        try:
            installed = [m.name for m in await provider.list_models() if m.name]
        except Exception as e:
            # Can't enumerate: don't second-guess, let the call proceed/fail.
            logger.debug("Could not list local models: %s", e.__class__.__name__)
            return wanted

        if wanted and wanted in installed:
            return wanted

        if installed:
            selected = self.profile.selected_model
            if selected and selected != "auto" and selected in installed:
                logger.info(
                    "Recommended model %r is not installed; using the selected model %r.",
                    wanted, selected,
                )
                return selected
            chosen = installed[0]
            logger.info(
                "Recommended model %r is not installed; using installed model %r "
                "(pull %r to use the recommendation).",
                wanted, chosen, wanted,
            )
            return chosen

        # Nothing installed: a genuine first run. Only download when the provider
        # actually supports pulling and we have a model to pull. Otherwise return
        # the resolved name untouched and let the call surface the provider's own
        # error — an empty model list is not conclusive proof of a first run (a
        # provider may not enumerate, or may not be Ollama), and downloading
        # gigabytes on that assumption would be far too aggressive.
        pull = getattr(provider, "pull", None)
        if not wanted or pull is None:
            return wanted
        logger.warning(
            "No local models installed (first run) — downloading the recommended "
            "model %r. This may take a while.", wanted,
        )
        await pull(wanted)
        return wanted

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
                # Local provider: the tier's recommended model may not actually
                # be installed, which would 404 on every call.
                model = await self._ensure_local_model(provider, model)
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
