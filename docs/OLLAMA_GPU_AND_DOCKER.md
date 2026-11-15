# Ollama, Docker, and GPU Acceleration Guide

This guide details platform-specific GPU acceleration, container passthrough limitations, and configuration best practices across the `appEcosystem` mesh.

## Platform Compatibility Matrix

| Platform | Runtime Environment | GPU Acceleration Support | Recommended Configuration |
|---|---|---|---|
| **macOS (Apple Silicon)** | **Native Host** | **YES (Metal / Unified Memory)** | Run native Ollama (`brew install ollama && ollama serve`). Fast inference utilizing unified memory. |
| **macOS (Apple Silicon)** | **Docker Container** | **NO (Virtualization Limitation)** | Apple Virtualization Framework does not support Metal GPU passthrough to Linux guest VMs. **Do NOT run Ollama inside Docker on macOS.** Run Ollama on macOS host and connect containers to `host.docker.internal:11434`. |
| **Linux (x86_64 / arm64)** | **NVIDIA Host / Container** | **YES (CUDA)** | Install `nvidia-container-toolkit`. Run container with `--gpus all`. |
| **Linux (x86_64)** | **AMD ROCm Container** | **YES (ROCm)** | Run official `ollama/ollama:rocm` container with `/dev/kfd` and `/dev/dri` mapped. |
| **Windows 10 / 11** | **WSL2** | **YES (CUDA / DirectML)** | WSL2 supports direct NVIDIA GPU virtualization through the Windows host driver. |

---

## 1. The macOS Docker Pitfall

### The Issue
On macOS, Docker runs inside a lightweight Linux virtual machine managed by HyperKit or Apple's Virtualization framework. Because Apple Silicon GPUs rely on Metal (which is proprietary to macOS and iOS), there is no Linux kernel driver that can virtualize Metal into the Linux guest VM.

If you run Ollama inside a Docker container on macOS:
- Ollama detects only CPU cores.
- Quantized LLMs run slowly on CPU threads, causing high thermals and battery drain.
- Hardware-tier auto-detection downgrades the node to `T0_MINIMAL` or `T1_MODEST`.

### The Solution: Native Host Ollama + Host Networking
1. Install and start native Ollama on your Mac:
   ```bash
   brew install ollama
   brew services start ollama
   ```
2. For containers running on your Mac (e.g. OpenEye, AegisSIEM, or Cyber-Agents):
   - Set environment variable:
     ```bash
     OLLAMA_HOST=http://host.docker.internal:11434
     ```
   - In `ecosystem.yaml`:
     ```yaml
     ai:
       ollama_base_url: "http://host.docker.internal:11434"
     ```

---

## 2. Network GPU (Using a Peer Node's GPU)

You can share a high-end GPU workstation with other ecosystem devices across your local network:

1. **On the GPU Host (e.g. Mac Studio M2 Ultra or Linux RTX 4090)**:
   - Configure Ollama to listen on all interfaces:
     - On macOS:
       ```bash
       launchctl setenv OLLAMA_HOST "0.0.0.0:11434"
       # Or launch directly:
       OLLAMA_HOST="0.0.0.0:11434" ollama serve
       ```
     - On Linux (systemd):
       ```ini
       [Service]
       Environment="OLLAMA_HOST=0.0.0.0:11434"
       ```
2. **Security Precaution**:
   > [!WARNING]
   > The Ollama API does not provide built-in authentication. Never expose port 11434 to untrusted public networks or the open internet. Restrict access using private subnets, WireGuard / Tailscale, or the ecosystem reverse proxy with HMAC verification.

3. **On Client Devices**:
   Point `ollama_base_url` to the GPU host's LAN IP:
   ```yaml
   ai:
     ollama_base_url: "http://192.168.1.100:11434"
     prefer: "local"
   ```

---

## 3. Diagnostic Tool: `ecosystem doctor gpu`

Run the built-in diagnostic tool to verify your accelerator configuration:

```bash
ecosystem doctor gpu
```

Example Output:
```
============================================================
  Ecosystem Hardware & GPU Doctor
============================================================
Platform:       darwin (arm64)
Containerized:  False
Accelerator:    METAL
Devices:        Apple Silicon GPU (Metal / Unified Memory)
VRAM / Unified: 32.0 GB
Status:         OK

Recommendations:
  [*] Native Metal acceleration available. Use native Ollama or llama.cpp Metal build.
============================================================
```

