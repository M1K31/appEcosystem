"""Hardware-aware feature gating.

Apps declare what each feature needs; the CapabilityManager enables or disables
it against the detected hardware tier and returns a human-readable reason, so
features degrade gracefully instead of crashing on unsupported hardware.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .hardware import CapabilityTier, HardwareInfo, tier_for


@dataclass
class FeatureRequirement:
    name: str
    min_tier: CapabilityTier = CapabilityTier.T0_MINIMAL
    needs_gpu: bool = False
    min_ram_gb: float = 0.0
    # If True the feature can run via a cloud provider even when local hardware
    # is too weak — i.e. it is enabled when a cloud key is configured.
    cloud_capable: bool = False


@dataclass
class FeatureStatus:
    name: str
    enabled: bool
    reason: str


@dataclass
class CapabilityManager:
    hardware: HardwareInfo
    has_cloud_provider: bool = False
    _tier: CapabilityTier = field(init=False)

    def __post_init__(self) -> None:
        self._tier = tier_for(self.hardware)

    @property
    def tier(self) -> CapabilityTier:
        return self._tier

    def evaluate(self, req: FeatureRequirement) -> FeatureStatus:
        if self.hardware.ram_gb + 1e-6 < req.min_ram_gb:
            if req.cloud_capable and self.has_cloud_provider:
                return FeatureStatus(req.name, True, "enabled via cloud provider (low RAM)")
            return FeatureStatus(
                req.name, False,
                f"needs {req.min_ram_gb}GB RAM, have {self.hardware.ram_gb}GB",
            )
        if req.needs_gpu and not self.hardware.has_gpu:
            if req.cloud_capable and self.has_cloud_provider:
                return FeatureStatus(req.name, True, "enabled via cloud provider (no GPU)")
            return FeatureStatus(req.name, False, "requires a GPU")
        if self._tier < req.min_tier:
            if req.cloud_capable and self.has_cloud_provider:
                return FeatureStatus(req.name, True, "enabled via cloud provider (low tier)")
            return FeatureStatus(
                req.name, False,
                f"requires tier {req.min_tier.name}, have {self._tier.name}",
            )
        return FeatureStatus(req.name, True, "supported")

    def evaluate_all(self, reqs: list[FeatureRequirement]) -> dict[str, FeatureStatus]:
        return {r.name: self.evaluate(r) for r in reqs}
