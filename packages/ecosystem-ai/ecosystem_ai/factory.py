"""Build providers and a router from a shared AIProfile.

Ollama is always present (the local-first default). Cloud providers are added
only when enabled in the profile; their API keys come from the environment.
"""

from __future__ import annotations

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
            providers[name] = cls(**kwargs)  # api_key resolved from env
    return providers


def build_router(
    profile: AIProfile,
    tier: Optional[CapabilityTier] = None,
    providers: Optional[dict[str, AIProvider]] = None,
) -> ProviderRouter:
    """Convenience: build a ready-to-use router from a profile."""
    return ProviderRouter(profile, providers or build_providers(profile), tier=tier)
