"""SkyPilot multi-cloud compute provider adapter (AWS, GCP, Azure, Lambda, RunPod, Vast)."""

from __future__ import annotations

import logging
import time
from typing import Any

from ..protocol import BatchJob, ComputeProvider, Endpoint, EndpointSpec, JobHandle, ProviderCaps

logger = logging.getLogger("ecosystem.compute.skypilot")


class SkyPilotComputeProvider:
    name: str = "skypilot"

    def __init__(self, clouds: list[str] | None = None, use_spot: bool = True):
        self.clouds = clouds or ["lambda", "runpod", "vast"]
        self.use_spot = use_spot
        self._jobs: dict[str, dict[str, Any]] = {}

    def capabilities(self) -> ProviderCaps:
        return ProviderCaps(
            gpus=["L40S", "A100", "RTX4090", "H100"],
            regions=self.clouds,
            price_per_hour_usd=0.65 if self.use_spot else 1.20,
            serverless=False,
            is_cloud=True,
            max_vram_gb=80.0,
        )

    async def ensure_endpoint(self, spec: EndpointSpec) -> Endpoint:
        return Endpoint(
            endpoint_id=f"sky-{spec.model}",
            provider_name=self.name,
            base_url="http://sky-cluster.internal:8000/v1",
            api_key="skypilot-cluster",
            model=spec.model,
            is_cloud=True,
            cost_per_token_in=0.0000005,
            cost_per_token_out=0.0000015,
        )

    async def run_batch(self, job: BatchJob) -> JobHandle:
        handle = JobHandle(
            job_id=job.job_id,
            provider_name=self.name,
            status="running",
            started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            cost_usd=job.estimated_cost_usd or 0.75,
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
            rate = self.capabilities().price_per_hour_usd
            return round(elapsed_hrs * rate, 4)
        return 0.0

