"""ecosystem_ai — shared, hardware-adaptive, provider-pluggable AI layer.

Ollama-first by default; cloud/agentic providers (Anthropic, OpenAI, Gemini)
are opt-in behind one interface. Hardware detection picks a model size that fits
and gates features that won't run. A shared AIProfile (held by the registry)
keeps LLM selections consistent across every app.
"""

from .floor_store import (
    clear_recorded_floor_passes,
    load_recorded_floor_passes,
    record_floor_pass,
)
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
from .capability import (
    assess_for_security,
    annotate_models,
    parse_parameter_size,
)
from .router import ProviderRouter
from .factory import build_providers, build_router
from .sync import AIProfileClient
from .vram_monitor import (
    QUANTIZATION_LADDER,
    MemorySample,
    QuantizationShiftEvent,
    VramQuantizationMonitor,
    extract_model_quantization,
    normalize_quantization,
    rewrite_model_quantization,
    sample_memory_headroom,
    step_down_quantization,
)
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

__version__ = "0.3.0"

__all__ = [
    "QUANTIZATION_LADDER",
    "MemorySample",
    "QuantizationShiftEvent",
    "VramQuantizationMonitor",
    "extract_model_quantization",
    "normalize_quantization",
    "rewrite_model_quantization",
    "sample_memory_headroom",
    "step_down_quantization",
    "clear_recorded_floor_passes",
    "load_recorded_floor_passes",
    "record_floor_pass",
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
