"""Select the shared security-analyst model from the one AI profile.

Order: explicit ``task_models["security_analyst"]`` -> ``selected_model`` ->
hardware-tier default. Security constraint: tinyllama is never returned, on any
path (including an unknown tier, which falls back to the T0 model).
"""
from __future__ import annotations

from .hardware import CapabilityTier, HardwareInfo, tier_for
from .profile import AIProfile

# Independent of hardware.TIER_DEFAULT_MODEL (chat defaults); analyst-specific.
TIER_ANALYST_MODELS: dict[CapabilityTier, str] = {
    CapabilityTier.T0_MINIMAL: "llama3.2:1b",
    CapabilityTier.T1_MODEST: "llama3.2:3b",
    CapabilityTier.T2_CAPABLE: "llama3.1:8b-instruct",
    CapabilityTier.T3_HIGH_END: "qwen2.5:14b",
}

_SAFE_FALLBACK = TIER_ANALYST_MODELS[CapabilityTier.T0_MINIMAL]


def _is_set(value: str | None) -> bool:
    return bool(value) and value.strip().lower() != "auto"


def resolve_analyst_model(profile: AIProfile, hw: HardwareInfo) -> str:
    explicit = profile.task_models.get("security_analyst")
    if _is_set(explicit):
        return explicit
    if _is_set(profile.selected_model):
        return profile.selected_model
    return TIER_ANALYST_MODELS.get(tier_for(hw), _SAFE_FALLBACK)
