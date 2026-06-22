"""ecosystem_ai — shared, hardware-adaptive, provider-pluggable AI layer.

Ollama-first by default; cloud/agentic providers (Anthropic, OpenAI, Gemini)
are opt-in behind one interface. Hardware detection picks a model size that fits
and gates features that won't run. A shared AIProfile (held by the registry)
keeps LLM selections consistent across every app.
"""

from .profile import AIProfile, CloudProvider, default_profile
from .hardware import (
    CapabilityTier,
    HardwareInfo,
    detect,
    probe,
    recommended_model,
    tier_for,
)
from .features import CapabilityManager, FeatureRequirement, FeatureStatus
from .router import ProviderRouter
from .factory import build_providers, build_router
from .sync import AIProfileClient
from .providers import (
    AIProvider,
    AnthropicProvider,
    Capability,
    ChatMessage,
    ChatResult,
    GeminiProvider,
    ModelInfo,
    OllamaProvider,
    OpenAIProvider,
    ProviderError,
)

__version__ = "0.1.0"

__all__ = [
    "AIProfile",
    "CloudProvider",
    "default_profile",
    "CapabilityTier",
    "HardwareInfo",
    "detect",
    "probe",
    "recommended_model",
    "tier_for",
    "CapabilityManager",
    "FeatureRequirement",
    "FeatureStatus",
    "ProviderRouter",
    "build_providers",
    "build_router",
    "AIProfileClient",
    "AIProvider",
    "AnthropicProvider",
    "Capability",
    "ChatMessage",
    "ChatResult",
    "GeminiProvider",
    "ModelInfo",
    "OllamaProvider",
    "OpenAIProvider",
    "ProviderError",
    "__version__",
]
