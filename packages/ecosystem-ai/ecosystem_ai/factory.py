"""Build providers and a router from a shared AIProfile.

Ollama is always present (the local-first default). Cloud providers are added
only when enabled in the profile; their API keys come from the environment.
"""

from __future__ import annotations

import os
from typing import Optional

from .hardware import CapabilityTier
from .profile import AIProfile
from .providers.anthropic import AnthropicProvider
from .providers.base import AIProvider
from .providers.gemini import GeminiProvider
from .providers.ollama import OllamaProvider
from .providers.openai import OpenAIProvider
from .router import ProviderRouter

_CLOUD_CLASSES = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
}

# Env var each provider historically read, kept as the fallback so existing
# environment-based deployments keep working unchanged.
_ENV_VARS = {
    "anthropic": ("ANTHROPIC_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
}


def resolve_provider_key(provider: str) -> Optional[str]:
    """Credential store first, then the provider's env var(s).

    The store is what the UI and `ecosystem provider` CLI write, so it takes
    precedence; env vars remain a valid way to configure a service.
    """
    try:
        from registry.credential_store import ProviderCredentialStore
    except ImportError:
        # ecosystem_ai can be installed without the registry package - that,
        # and only that, means "no store available, fall through to env".
        # A store that IS present but broken (unreadable file -> PermissionError,
        # corrupt JSON -> ValueError) must propagate rather than be swallowed
        # here, or a user with an unreadable/corrupt store would silently and
        # confusingly fall back to env vars instead of seeing the real error.
        pass
    else:
        key = ProviderCredentialStore().get_key(provider)
        if key:
            return key
    for var in _ENV_VARS.get(provider, ()):
        val = os.environ.get(var)
        if val:
            return val
    return None


def build_providers(profile: AIProfile) -> dict[str, AIProvider]:
    """Construct the provider set described by the profile."""
    providers: dict[str, AIProvider] = {
        "ollama": OllamaProvider(profile.ollama_base_url),
    }
    for name, cls in _CLOUD_CLASSES.items():
        cfg = profile.cloud.get(name)
        if cfg and cfg.enabled:
            kwargs = {}
            if cfg.model:
                kwargs["default_model"] = cfg.model
            key = resolve_provider_key(name)
            if key:
                kwargs["api_key"] = key
            providers[name] = cls(**kwargs)
    return providers


def build_router(
    profile: AIProfile,
    tier: Optional[CapabilityTier] = None,
    providers: Optional[dict[str, AIProvider]] = None,
) -> ProviderRouter:
    """Convenience: build a ready-to-use router from a profile."""
    return ProviderRouter(profile, providers or build_providers(profile), tier=tier)
