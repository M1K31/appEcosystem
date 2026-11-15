"""Generic OpenAI-compatible compute provider adapter (vLLM, Ollama, self-hosted)."""

from __future__ import annotations

from typing import Any

from ..protocol import BatchJob, ComputeProvider, Endpoint, EndpointSpec, JobHandle, ProviderCaps


class GenericOpenAIComputeProvider:
    name: str = "generic_openai"

    def __init__(self, base_url: str = "", api_key: str = "", is_cloud: bool = False):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.is_cloud = is_cloud

    def capabilities(self) -> ProviderCaps:
        return ProviderCaps(
            gpus=["OpenAI-Compatible Backend"],
            regions=["external"],
            price_per_hour_usd=0.0,
            serverless=True,
            is_cloud=self.is_cloud,
        )

    async def ensure_endpoint(self, spec: EndpointSpec) -> Endpoint:
        url = self.base_url
        if not url.endswith("/v1") and not url.endswith("/api"):
            url = f"{url}/v1"
        return Endpoint(
            endpoint_id=f"openai-compat-{spec.model}",
            provider_name=self.name,
            base_url=url,
            api_key=self.api_key,
            model=spec.model,
            is_cloud=self.is_cloud,
            cost_per_token_in=0.0,
            cost_per_token_out=0.0,
        )

    async def run_batch(self, job: BatchJob) -> JobHandle:
        return JobHandle(
            job_id=job.job_id,
            provider_name=self.name,
            status="failed",
            error="Generic OpenAI endpoint does not support raw shell batch jobs",
        )

    async def stop(self, handle: JobHandle | Endpoint) -> None:
        pass

    async def cost_so_far(self, handle: JobHandle | Endpoint) -> float:
        return 0.0

