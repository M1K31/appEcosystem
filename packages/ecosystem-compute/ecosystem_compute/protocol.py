"""Unified ComputeProvider Protocol and workload dataclasses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class ProviderCaps:
    gpus: list[str] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    price_per_hour_usd: float = 0.0
    serverless: bool = False
    is_cloud: bool = False
    max_vram_gb: float = 0.0


@dataclass
class BatchJob:
    job_id: str
    command: list[str]
    image: str = ""
    env: dict[str, str] = field(default_factory=dict)
    classification: str = "internal"  # public | internal | sensitive
    accelerators: list[str] = field(default_factory=list)
    max_runtime_seconds: int = 14400
    estimated_cost_usd: float = 0.0


@dataclass
class JobHandle:
    job_id: str
    provider_name: str
    status: str  # pending | running | completed | failed | stopped
    started_at: str = ""
    completed_at: str = ""
    cost_usd: float = 0.0
    output: str = ""
    error: str = ""


@dataclass
class EndpointSpec:
    model: str
    min_vram_gb: float = 0.0
    classification: str = "internal"
    context_length: int = 4096


@dataclass
class Endpoint:
    endpoint_id: str
    provider_name: str
    base_url: str
    api_key: str = ""
    model: str = ""
    is_cloud: bool = False
    cost_per_token_in: float = 0.0
    cost_per_token_out: float = 0.0


@runtime_checkable
class ComputeProvider(Protocol):
    name: str

    def capabilities(self) -> ProviderCaps:
        """Query supported GPUs, regions, hourly rate, and serverless options."""
        ...

    async def run_batch(self, job: BatchJob) -> JobHandle:
        """Run batch job (e.g. model fine-tuning, embeddings generation, Heretic)."""
        ...

    async def ensure_endpoint(self, spec: EndpointSpec) -> Endpoint:
        """Ensure an OpenAI-compatible URL is ready for inference."""
        ...

    async def stop(self, handle: JobHandle | Endpoint) -> None:
        """Stop running job or tear down provisioned endpoint."""
        ...

    async def cost_so_far(self, handle: JobHandle | Endpoint) -> float:
        """Compute accumulated USD cost for this handle."""
        ...

