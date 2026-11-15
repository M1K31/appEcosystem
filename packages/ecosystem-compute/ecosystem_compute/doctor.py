"""GPU diagnostics and container passthrough analyzer (ecosystem doctor gpu)."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class GpuDiagnostic:
    os_name: str
    arch: str
    in_container: bool
    is_docker_desktop_mac: bool
    hardware_accelerator: str  # metal | cuda | rocm | cpu
    gpu_devices_found: list[str] = field(default_factory=list)
    vram_gb: float = 0.0
    unified_memory: bool = False
    recommendations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    status: str = "ok"  # ok | warning | error

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def is_running_in_container() -> bool:
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        return True
    try:
        cgroup = Path("/proc/1/cgroup")
        if cgroup.is_file() and ("docker" in cgroup.read_text() or "containerd" in cgroup.read_text()):
            return True
    except Exception:
        pass
    return False


def is_docker_desktop_mac_vm() -> bool:
    if not is_running_in_container():
        return False
    # Docker Desktop for Mac VM kernel frequently has 'linuxkit' in uname
    kernel = platform.uname().release.lower()
    if "linuxkit" in kernel:
        return True
    try:
        version_text = Path("/proc/version").read_text().lower()
        if "linuxkit" in version_text or "docker-desktop" in version_text:
            return True
    except Exception:
        pass
    return False


def diagnose_gpu() -> GpuDiagnostic:
    in_container = is_running_in_container()
    is_mac_docker = is_docker_desktop_mac_vm()
    os_name = sys.platform
    arch = platform.machine().lower()

    gpu_devices = []
    warnings = []
    recommendations = []
    status = "ok"
    accelerator = "cpu"
    unified = False
    vram = 0.0

    # 1. Check macOS Docker VM limitation (F6 / Implementation Plan)
    if is_mac_docker:
        status = "warning"
        accelerator = "cpu"
        warnings.append(
            "macOS Docker VM detected: Apple Virtualization Framework does not support "
            "Metal GPU passthrough to Linux guest containers."
        )
        recommendations.append(
            "Run Ollama natively on macOS host: 'brew install ollama && ollama serve'"
        )
        recommendations.append(
            "Set OLLAMA_HOST='http://host.docker.internal:11434' in container environment"
        )
        return GpuDiagnostic(
            os_name="linux (docker on macos)",
            arch=arch,
            in_container=True,
            is_docker_desktop_mac=True,
            hardware_accelerator="cpu",
            gpu_devices_found=[],
            vram_gb=0.0,
            unified_memory=False,
            recommendations=recommendations,
            warnings=warnings,
            status=status,
        )

    # 2. Check native macOS
    if os_name == "darwin":
        if "arm" in arch or "aarch64" in arch:
            accelerator = "metal"
            unified = True
            gpu_devices.append("Apple Silicon GPU (Metal / Unified Memory)")
            # Try to query RAM as unified VRAM
            try:
                res = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, check=False)
                if res.returncode == 0:
                    bytes_ram = int(res.stdout.strip())
                    vram = round(bytes_ram / (1024**3), 1)
            except Exception:
                vram = 16.0
            recommendations.append("Native Metal acceleration available. Use native Ollama or llama.cpp Metal build.")
        else:
            accelerator = "cpu"
            recommendations.append("Intel Mac: Consider local CPU quantized models or LAN GPU peer.")

    # 3. Check Linux NVIDIA / AMD
    elif os_name.startswith("linux"):
        has_nvidia_dev = any(os.path.exists(f"/dev/nvidia{i}") for i in range(8))
        nvidia_smi = shutil.which("nvidia-smi")

        if nvidia_smi:
            try:
                res = subprocess.run(
                    [nvidia_smi, "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if res.returncode == 0:
                    accelerator = "cuda"
                    for line in res.stdout.strip().splitlines():
                        if line.strip():
                            parts = line.split(",")
                            gpu_devices.append(parts[0].strip())
                            if len(parts) > 1:
                                try:
                                    vram += round(float(parts[1].strip()) / 1024.0, 1)
                                except ValueError:
                                    pass
            except Exception:
                pass

        if has_nvidia_dev and not nvidia_smi:
            warnings.append("NVIDIA device nodes found in /dev but 'nvidia-smi' is missing from PATH.")
            recommendations.append("Install NVIDIA CUDA toolkit and drivers: 'sudo apt-get install -y nvidia-cuda-toolkit'")

        if in_container and not has_nvidia_dev:
            warnings.append("Container running on Linux without GPU passthrough.")
            recommendations.append("Install NVIDIA Container Toolkit and run Docker with '--gpus all'")

    return GpuDiagnostic(
        os_name=os_name,
        arch=arch,
        in_container=in_container,
        is_docker_desktop_mac=is_mac_docker,
        hardware_accelerator=accelerator,
        gpu_devices_found=gpu_devices,
        vram_gb=vram,
        unified_memory=unified,
        recommendations=recommendations,
        warnings=warnings,
        status=status,
    )

