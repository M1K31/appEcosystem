"""Hardware capability detection and tiering.

Detects what the current machine can do (RAM, CPU, GPU/VRAM, disk, arch) and
maps it to a capability tier. Apps use the tier to pick a local model size that
fits and to deactivate features that won't run — maximizing functionality on old
hardware while unlocking modern options on new hardware. Stdlib-only; no torch
or psutil required.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, asdict
from enum import IntEnum
from typing import Optional


class CapabilityTier(IntEnum):
    T0_MINIMAL = 0    # Pi 4 / <4GB / no GPU
    T1_MODEST = 1     # 4-8GB, weak/no GPU
    T2_CAPABLE = 2    # 16GB+, Apple Silicon / entry GPU
    T3_HIGH_END = 3   # 32GB+, discrete GPU >=12GB VRAM


@dataclass
class HardwareInfo:
    ram_gb: float
    cpu_cores: int
    arch: str
    os_name: str
    has_gpu: bool
    vram_gb: float
    free_disk_gb: float

    def to_dict(self) -> dict:
        return asdict(self)


def _total_ram_gb() -> float:
    """Best-effort total RAM in GB, stdlib-only across platforms."""
    # POSIX (Linux, most Unix)
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        if pages > 0 and page_size > 0:
            return round(pages * page_size / (1024 ** 3), 1)
    except (ValueError, OSError, AttributeError):
        pass
    # macOS
    if platform.system() == "Darwin":
        try:
            out = subprocess.run(
                ["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=3
            )
            if out.returncode == 0:
                return round(int(out.stdout.strip()) / (1024 ** 3), 1)
        except Exception:
            pass
    return 0.0


def _gpu_info() -> tuple[bool, float]:
    """Return (has_gpu, vram_gb). Detects NVIDIA via nvidia-smi; treats Apple
    Silicon as a capable integrated GPU (unified memory)."""
    # NVIDIA
    if shutil.which("nvidia-smi"):
        try:
            out = subprocess.run(
                ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=5,
            )
            if out.returncode == 0 and out.stdout.strip():
                mb = max(int(x) for x in out.stdout.split() if x.strip().isdigit())
                return True, round(mb / 1024, 1)
        except Exception:
            pass
    # Apple Silicon (unified memory acts as VRAM via Metal)
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        return True, _total_ram_gb()
    return False, 0.0


def probe() -> HardwareInfo:
    """Detect current hardware capabilities."""
    has_gpu, vram = _gpu_info()
    try:
        free_disk = round(shutil.disk_usage(os.path.expanduser("~")).free / (1024 ** 3), 1)
    except Exception:
        free_disk = 0.0
    return HardwareInfo(
        ram_gb=_total_ram_gb(),
        cpu_cores=os.cpu_count() or 1,
        arch=platform.machine() or "unknown",
        os_name=platform.system() or "unknown",
        has_gpu=has_gpu,
        vram_gb=vram,
        free_disk_gb=free_disk,
    )


def tier_for(info: HardwareInfo) -> CapabilityTier:
    """Map hardware to a capability tier (tunable thresholds)."""
    ram = info.ram_gb
    if info.has_gpu and info.vram_gb >= 12 and ram >= 32:
        return CapabilityTier.T3_HIGH_END
    if ram >= 16:
        return CapabilityTier.T2_CAPABLE
    if ram >= 4:
        return CapabilityTier.T1_MODEST
    return CapabilityTier.T0_MINIMAL


# Default local (Ollama) model per tier. "" means "no local LLM at this tier —
# use a cloud provider if a key is configured, else disable AI features."
TIER_DEFAULT_MODEL: dict[CapabilityTier, str] = {
    CapabilityTier.T0_MINIMAL: "",
    CapabilityTier.T1_MODEST: "llama3.2:3b",
    CapabilityTier.T2_CAPABLE: "llama3.1:8b",
    CapabilityTier.T3_HIGH_END: "llama3.1:8b",
}


def recommended_model(tier: CapabilityTier) -> str:
    return TIER_DEFAULT_MODEL.get(tier, "")


def detect() -> tuple[HardwareInfo, CapabilityTier]:
    """Convenience: probe hardware and resolve its tier in one call."""
    info = probe()
    return info, tier_for(info)
