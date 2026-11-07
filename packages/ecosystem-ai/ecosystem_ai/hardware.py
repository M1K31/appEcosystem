"""Hardware capability detection and tiering.

Detects what the current machine can do (total & available RAM, CPU, GPU/VRAM,
unified memory architecture, accessible execution backends, disk, arch) and
maps it to a capability tier. Apps use the tier and backend probe to pick a
local model/runtime that fits and to deactivate features that won't run —
maximizing functionality on older hardware while unlocking modern options on
new hardware. Stdlib-only; no torch or psutil required.
"""

from __future__ import annotations

import ctypes
import os
import platform
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from enum import IntEnum


class CapabilityTier(IntEnum):
    T0_MINIMAL = 0    # Pi 4 / <4GB / no GPU
    T1_MODEST = 1     # 4-8GB, weak/no GPU
    T2_CAPABLE = 2    # 16GB+, Apple Silicon / entry GPU
    T3_HIGH_END = 3   # 32GB+, discrete GPU >=12GB VRAM or unified GPU >=32GB RAM


@dataclass
class HardwareInfo:
    ram_gb: float
    cpu_cores: int
    arch: str
    os_name: str
    has_gpu: bool
    vram_gb: float
    free_disk_gb: float
    available_ram_gb: float = 0.0
    unified_memory: bool = False
    gpu_vendor: str = ""
    backends: tuple[str, ...] = ("cpu",)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["backends"] = list(self.backends)
        return d


def _in_container() -> bool:
    """Return True when running inside a standard Docker/OCI container."""
    return os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")


def _windows_memory_gb() -> tuple[float, float]:
    """Return (total_ram_gb, available_ram_gb) on Windows via Win32 stdlib ctypes."""
    if platform.system() != "Windows":
        return 0.0, 0.0
    try:
        class _MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = _MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
        windll = getattr(ctypes, "windll", None)
        if windll is not None and windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            total = round(stat.ullTotalPhys / (1024 ** 3), 1)
            avail = round(stat.ullAvailPhys / (1024 ** 3), 1)
            return total, avail
    except Exception:
        pass
    return 0.0, 0.0


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
    # Windows
    if platform.system() == "Windows":
        return _windows_memory_gb()[0]
    return 0.0


def _available_ram_gb() -> float:
    """Best-effort currently available (reclaimable + free) RAM in GB, stdlib-only."""
    sys_name = platform.system()
    # Linux /proc/meminfo MemAvailable accounts for reclaimable page cache.
    if sys_name == "Linux" and os.path.exists("/proc/meminfo"):
        try:
            with open("/proc/meminfo", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("MemAvailable:"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            return round(int(parts[1]) / (1024 ** 2), 1)
        except Exception:
            pass
    # macOS vm_stat (free + inactive + speculative + purgeable pages)
    if sys_name == "Darwin":
        try:
            out = subprocess.run(
                ["vm_stat"], capture_output=True, text=True, timeout=3
            )
            if out.returncode == 0 and out.stdout:
                page_size = 4096
                m_ps = re.search(r"page size of (\d+) bytes", out.stdout)
                if m_ps:
                    page_size = int(m_ps.group(1))
                reclaimable_keys = (
                    "Pages free",
                    "Pages inactive",
                    "Pages speculative",
                    "Pages purgeable",
                )
                pages = 0
                for line in out.stdout.splitlines():
                    if ":" not in line:
                        continue
                    key, val = line.split(":", 1)
                    if key.strip() in reclaimable_keys:
                        digits = re.sub(r"[^0-9]", "", val)
                        if digits:
                            pages += int(digits)
                if pages > 0:
                    return round(pages * page_size / (1024 ** 3), 1)
        except Exception:
            pass
    # Windows
    if sys_name == "Windows":
        return _windows_memory_gb()[1]
    # Generic POSIX fallback
    try:
        av_pages = os.sysconf("SC_AVPHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        if av_pages > 0 and page_size > 0:
            return round(av_pages * page_size / (1024 ** 3), 1)
    except (ValueError, OSError, AttributeError):
        pass
    return 0.0


def _parse_rocm_vram_gb(csv_text: str) -> float:
    """Parse dedicated VRAM in GB from `rocm-smi --showmeminfo vram --csv`."""
    lines = [ln.strip() for ln in csv_text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return 0.0
    headers = [h.strip().lower() for h in lines[0].split(",")]
    total_idx = next(
        (i for i, h in enumerate(headers) if "total" in h and "vram" in h),
        None,
    )
    best_bytes = 0
    for row in lines[1:]:
        if "no amd gpus" in row.lower():
            return -1.0
        cols = [c.strip() for c in row.split(",")]
        if total_idx is not None and total_idx < len(cols) and cols[total_idx].isdigit():
            best_bytes = max(best_bytes, int(cols[total_idx]))
        else:
            for col in cols:
                if col.isdigit() and int(col) >= 1024 * 1024:
                    best_bytes = max(best_bytes, int(col))
    return round(best_bytes / (1024 ** 3), 1) if best_bytes > 0 else 0.0


def _parse_xpu_vram_gb(csv_text: str) -> float:
    """Parse physical memory in GB from `xpu-smi discovery --dump 1,18`."""
    lines = [ln.strip() for ln in csv_text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return 0.0
    best_gb = 0.0
    for row in lines[1:]:
        cols = [c.strip() for c in row.split(",")]
        if len(cols) < 2:
            continue
        raw = cols[1]
        m = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*(mib|mb|gib|gb|b)?", raw, re.IGNORECASE)
        if not m:
            continue
        val = float(m.group(1))
        unit = (m.group(2) or "mib").lower()
        if unit in ("gib", "gb"):
            gb = val
        elif unit == "b":
            gb = val / (1024 ** 3)
        else:
            gb = val / 1024.0
        best_gb = max(best_gb, round(gb, 1))
    return best_gb


def _gpu_and_backends() -> tuple[bool, float, bool, str, tuple[str, ...]]:
    """Return (has_gpu, vram_gb, unified_memory, gpu_vendor, backends).

    Distinguishes installed hardware from accessible runtime execution backends,
    never labels unified memory as dedicated VRAM, and always preserves CPU
    fallback.
    """
    # 1. NVIDIA CUDA
    if shutil.which("nvidia-smi"):
        try:
            out = subprocess.run(
                ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=5,
            )
            if out.returncode == 0 and out.stdout.strip():
                digits = [int(x) for x in out.stdout.split() if x.strip().isdigit()]
                if digits:
                    return True, round(max(digits) / 1024, 1), False, "nvidia", ("cuda", "cpu")
        except Exception:
            pass

    # 2. Apple Silicon (unified memory; dedicated VRAM is 0.0; Metal requires host access)
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        if _in_container():
            return False, 0.0, True, "apple", ("cpu",)
        return True, 0.0, True, "apple", ("metal", "cpu")

    # 3. AMD ROCm
    if shutil.which("rocm-smi"):
        if platform.system() != "Linux" or os.path.exists("/dev/kfd") or not _in_container():
            try:
                out = subprocess.run(
                    ["rocm-smi", "--showmeminfo", "vram", "--csv"],
                    capture_output=True, text=True, timeout=5,
                )
                if out.returncode == 0 and out.stdout.strip():
                    vram_gb = _parse_rocm_vram_gb(out.stdout)
                    if vram_gb >= 0.0 and "no amd gpus" not in out.stdout.lower():
                        return True, vram_gb, False, "amd", ("rocm", "cpu")
            except Exception:
                pass

    # 4. Intel XPU
    if shutil.which("xpu-smi"):
        try:
            out = subprocess.run(
                ["xpu-smi", "discovery", "--dump", "1,18"],
                capture_output=True, text=True, timeout=5,
            )
            if out.returncode == 0 and len(out.stdout.strip().splitlines()) >= 2:
                vram_gb = _parse_xpu_vram_gb(out.stdout)
                return True, vram_gb, False, "intel", ("xpu", "cpu")
        except Exception:
            pass

    return False, 0.0, False, "", ("cpu",)


def _gpu_info() -> tuple[bool, float]:
    """Backward-compatible helper returning (has_gpu, dedicated_vram_gb)."""
    has_gpu, vram_gb, _, _, _ = _gpu_and_backends()
    return has_gpu, vram_gb


def probe() -> HardwareInfo:
    """Detect current hardware capabilities, available memory, and backends."""
    has_gpu, vram, unified, vendor, backends = _gpu_and_backends()
    try:
        free_disk = round(shutil.disk_usage(os.path.expanduser("~")).free / (1024 ** 3), 1)
    except Exception:
        free_disk = 0.0
    total_ram = _total_ram_gb()
    avail_ram = _available_ram_gb()
    return HardwareInfo(
        ram_gb=total_ram,
        cpu_cores=os.cpu_count() or 1,
        arch=platform.machine() or "unknown",
        os_name=platform.system() or "unknown",
        has_gpu=has_gpu,
        vram_gb=vram,
        free_disk_gb=free_disk,
        available_ram_gb=min(avail_ram, total_ram) if total_ram > 0 and avail_ram > 0 else avail_ram,
        unified_memory=unified,
        gpu_vendor=vendor,
        backends=backends,
    )


def tier_for(info: HardwareInfo) -> CapabilityTier:
    """Map hardware to a capability tier (tunable thresholds)."""
    ram = info.ram_gb
    discrete_high_end = info.has_gpu and info.vram_gb >= 12 and ram >= 32
    unified_high_end = (
        info.has_gpu
        and info.unified_memory
        and any(b != "cpu" for b in info.backends)
        and ram >= 32
    )
    if discrete_high_end or unified_high_end:
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
