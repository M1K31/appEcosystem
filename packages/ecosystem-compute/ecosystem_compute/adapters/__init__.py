"""Compute adapters for ecosystem-compute."""

from .generic_openai_adapter import GenericOpenAIComputeProvider
from .lan_adapter import LanNodeComputeProvider
from .local_adapter import LocalComputeProvider
from .runpod_adapter import RunPodComputeProvider
from .skypilot_adapter import SkyPilotComputeProvider

__all__ = [
    "GenericOpenAIComputeProvider",
    "LanNodeComputeProvider",
    "LocalComputeProvider",
    "RunPodComputeProvider",
    "SkyPilotComputeProvider",
]

