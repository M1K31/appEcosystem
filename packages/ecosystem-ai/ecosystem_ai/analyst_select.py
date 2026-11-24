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


def can_select_as_analyst(model: str, floor_passes: set[str]) -> bool:
    """A model may serve as analyst only with a recorded floor pass."""
    return model in floor_passes


def resolve_analyst_model(
    profile: AIProfile,
    hw: HardwareInfo,
    floor_passes: set[str] | None = None,
) -> str:
    """Resolve the analyst model. ``floor_passes=None`` means no gating; when
    given, a model without a recorded floor pass is refused."""
    explicit = profile.task_models.get("security_analyst")
    if _is_set(explicit):
        model = explicit
    elif _is_set(profile.selected_model):
        model = profile.selected_model
    else:
        model = TIER_ANALYST_MODELS.get(tier_for(hw), _SAFE_FALLBACK)
    if floor_passes is not None and not can_select_as_analyst(model, floor_passes):
        raise ValueError(
            f"analyst model {model!r} has no recorded floor pass; refusing to select it"
        )
    return model
