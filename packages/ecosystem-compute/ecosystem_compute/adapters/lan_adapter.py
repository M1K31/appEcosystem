"""LAN node compute provider adapter (peer GPU discovery across ecosystem mesh)."""

from __future__ import annotations

import logging
from typing import Any, Optional

from ..protocol import BatchJob, ComputeProvider, Endpoint, EndpointSpec, JobHandle, ProviderCaps

logger = logging.getLogger("ecosystem.compute.lan")


class LanNodeComputeProvider:
    name: str = "lan_node"

    def __init__(self, registry_client: Any = None):
        self.registry_client = registry_client
        self._endpoints: dict[str, Endpoint] = {}

    def capabilities(self) -> ProviderCaps:
        return ProviderCaps(
            gpus=["LAN Peer Accelerators"],
            regions=["lan"],
            price_per_hour_usd=0.0,
            serverless=False,
            is_cloud=False,
            max_vram_gb=24.0,
        )

    async def ensure_endpoint(self, spec: EndpointSpec) -> Endpoint:
        target_url = "http://lan-peer.local:8000/v1"
        if self.registry_client is not None:
            try:
                services = getattr(self.registry_client, "discover_services", lambda: [])()
                for s in services:
                    if "gpu" in s.get("tags", []) or "llm" in s.get("tags", []):
                        target_url = f"http://{s.get('address')}:{s.get('port')}/v1"
                        break
            except Exception as exc:
                logger.warning("Could not resolve LAN GPU node from registry: %r", exc)

        ep = Endpoint(
            endpoint_id=f"lan-node-{spec.model}",
            provider_name=self.name,
            base_url=target_url,
            api_key="ecosystem-lan",
            model=spec.model,
            is_cloud=False,
            cost_per_token_in=0.0,
            cost_per_token_out=0.0,
        )
        self._endpoints[ep.endpoint_id] = ep
        return ep

    async def run_batch(self, job: BatchJob) -> JobHandle:
        return JobHandle(
            job_id=job.job_id,
            provider_name=self.name,
            status="failed",
            error="Batch execution on LAN peer requires remote agent dispatch",
        )

    async def stop(self, handle: JobHandle | Endpoint) -> None:
        pass

    async def cost_so_far(self, handle: JobHandle | Endpoint) -> float:
        return 0.0

