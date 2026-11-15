"""Local compute provider adapter (CUDA / Metal / CPU)."""

from __future__ import annotations

import asyncio
import os
import sys
import time
from typing import Any

from ..protocol import BatchJob, ComputeProvider, Endpoint, EndpointSpec, JobHandle, ProviderCaps


class LocalComputeProvider:
    name: str = "local"

    def __init__(self, ollama_url: str = "http://localhost:11434"):
        self.ollama_url = os.environ.get("OLLAMA_HOST", ollama_url)
        self._jobs: dict[str, JobHandle] = {}

    def capabilities(self) -> ProviderCaps:
        has_metal = sys.platform == "darwin"
        gpus = ["Apple Silicon Metal"] if has_metal else []
        return ProviderCaps(
            gpus=gpus,
            regions=["local"],
            price_per_hour_usd=0.0,
            serverless=False,
            is_cloud=False,
            max_vram_gb=16.0 if has_metal else 0.0,
        )

    async def ensure_endpoint(self, spec: EndpointSpec) -> Endpoint:
        base = self.ollama_url.rstrip("/")
        url = f"{base}/v1" if not base.endswith("/v1") else base
        return Endpoint(
            endpoint_id="local-ollama",
            provider_name=self.name,
            base_url=url,
            api_key="ollama",
            model=spec.model,
            is_cloud=False,
            cost_per_token_in=0.0,
            cost_per_token_out=0.0,
        )

    async def run_batch(self, job: BatchJob) -> JobHandle:
        handle = JobHandle(
            job_id=job.job_id,
            provider_name=self.name,
            status="running",
            started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        self._jobs[job.job_id] = handle

        try:
            proc = await asyncio.create_subprocess_exec(
                *job.command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, **job.env},
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=job.max_runtime_seconds)
            handle.status = "completed" if proc.returncode == 0 else "failed"
            handle.output = stdout.decode("utf-8", errors="replace")
            handle.error = stderr.decode("utf-8", errors="replace")
        except Exception as exc:
            handle.status = "failed"
            handle.error = str(exc)

        handle.completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return handle

    async def stop(self, handle: JobHandle | Endpoint) -> None:
        if isinstance(handle, JobHandle) and handle.job_id in self._jobs:
            self._jobs[handle.job_id].status = "stopped"

    async def cost_so_far(self, handle: JobHandle | Endpoint) -> float:
        return 0.0

