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
        self._last_listed: list = []
        # Most recent capability verdict, for callers that surface it.
        self.last_capability: Optional[dict] = None

    def resolve_model(self, task: str = "chat") -> str:
        """Resolve the model for a task: explicit task model → selected_model →
        hardware-tier default. 'auto' resolves to the tier's recommended model."""
        model = self.profile.task_models.get(task, "auto")
        if (not model or model == "auto") and task == "chat":
            model = self.profile.selected_model
        if not model or model == "auto":
            model = recommended_model(self.tier) if self.tier is not None else ""
        return model

    def _ordered_providers(self, task: str = "chat") -> list[str]:
        """Provider preference order for a task.

        A per-task provider (profile.task_providers[task]) wins outright: that is
        the cost-control lever, letting a user send security analysis to a cloud
        model while chat and embeddings stay local. A blank or missing entry
        falls back to the profile-wide preference, so an untouched profile
        behaves exactly as before.
        """
        default = self.profile.default_provider
        cloud = [name for name, c in self.profile.cloud.items() if c.enabled]

        pinned = (getattr(self.profile, "task_providers", {}) or {}).get(task, "")
        if pinned:
            # Keep the rest as fallback order (used only when fallback is allowed),
            # with the pinned provider first and never duplicated.
            rest = [p for p in ([default] + cloud) if p != pinned]
            return [pinned] + rest

        if self.profile.prefer == "cloud":
            return cloud + [default]
        # local-first (default) and "quality" both start local here
        order = [default] + cloud
        return order

    # Tasks whose output a user is likely to act on as if it were expert
    # judgement. A too-small model still answers these, which is the hazard.
    _JUDGEMENT_TASKS = ("security",)

    def _warn_if_weak(self, model: str, task: str) -> str:
        """Log loudly when a fallback lands on a model too small for the task.

        The fallback is silent by design — it keeps the system working — but for
        security analysis "working" on a 1B model means confident, wrong findings.
        The user who chose a model in one app never sees that this daemon quietly
        picked something else, so the warning has to happen here.
        """
        if task not in self._JUDGEMENT_TASKS:
            return model
        try:
            from .capability import assess_for_security

            size = None
            for m in self._last_listed or []:
                if getattr(m, "name", None) == model:
                    size = getattr(m, "parameter_size", None)
                    break
            verdict = assess_for_security(model, size)
            if verdict.get("warning"):
                logger.warning("Security-analysis model check: %s", verdict["warning"])
            self.last_capability = verdict
        except Exception as e:  # never let a warning break routing
            logger.debug("Capability check skipped: %s", e.__class__.__name__)
        return model

    async def _ensure_local_model(self, provider: AIProvider, wanted: str, task: str = "chat") -> str:
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
            listed = await provider.list_models()
            self._last_listed = listed
            installed = [m.name for m in listed if m.name]
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
                return self._warn_if_weak(selected, task)
            chosen = installed[0]
            logger.info(
                "Recommended model %r is not installed; using installed model %r "
                "(pull %r to use the recommendation).",
                wanted, chosen, wanted,
            )
            return self._warn_if_weak(chosen, task)

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
        order = self._ordered_providers(task)
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
                # Classify by membership in the cloud map, NOT by "differs from
                # default_provider": with per-task pinning a user can pin the
                # local provider for one task while the default is a cloud one,
                # and the old test would then misclassify local as cloud and skip
                # the installed-model check below.
                if name in self.profile.cloud:
                    cfg = self.profile.cloud.get(name)
                    if cfg and cfg.model:
                        model = cfg.model
                    return provider, model
                # Local provider: the tier's recommended model may not actually
                # be installed, which would 404 on every call.
                model = await self._ensure_local_model(provider, model, task)
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
