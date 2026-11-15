"""RunPod compute provider adapter (serverless vLLM and dedicated GPU pods)."""

from __future__ import annotations

import logging
import time
from typing import Any

from ..protocol import BatchJob, ComputeProvider, Endpoint, EndpointSpec, JobHandle, ProviderCaps

logger = logging.getLogger("ecosystem.compute.runpod")


class RunPodComputeProvider:
    name: str = "runpod"

    def __init__(self, api_key: str = "", base_url: str = "https://api.runpod.ai/v2"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._jobs: dict[str, dict[str, Any]] = {}

    def capabilities(self) -> ProviderCaps:
        return ProviderCaps(
            gpus=["NVIDIA A100", "NVIDIA L40S", "NVIDIA RTX 4090", "NVIDIA H100"],
            regions=["us-east", "us-west", "eu-central"],
            price_per_hour_usd=0.74,
            serverless=True,
            is_cloud=True,
            max_vram_gb=80.0,
        )

    async def ensure_endpoint(self, spec: EndpointSpec) -> Endpoint:
        # In real execution, calls RunPod serverless API to ensure worker pool is ready
        pod_endpoint = f"https://api.runpod.ai/v2/{spec.model.replace(':', '-')}/openai/v1"
        return Endpoint(
            endpoint_id=f"runpod-{spec.model}",
            provider_name=self.name,
            base_url=pod_endpoint,
            api_key=self.api_key,
            model=spec.model,
            is_cloud=True,
            cost_per_token_in=0.0000008,
            cost_per_token_out=0.0000024,
        )

    async def run_batch(self, job: BatchJob) -> JobHandle:
        handle = JobHandle(
            job_id=job.job_id,
            provider_name=self.name,
            status="running",
            started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            cost_usd=job.estimated_cost_usd or 0.50,
        )
        self._jobs[job.job_id] = {"handle": handle, "start_time": time.time()}
        return handle

    async def stop(self, handle: JobHandle | Endpoint) -> None:
        if isinstance(handle, JobHandle) and handle.job_id in self._jobs:
            self._jobs[handle.job_id]["handle"].status = "stopped"

    async def cost_so_far(self, handle: JobHandle | Endpoint) -> float:
        if isinstance(handle, JobHandle) and handle.job_id in self._jobs:
            rec = self._jobs[handle.job_id]
            elapsed_hrs = (time.time() - rec["start_time"]) / 3600.0
            return round(elapsed_hrs * self.capabilities().price_per_hour_usd, 4)
        return 0.0

