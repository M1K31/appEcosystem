"""Multi-provider GPU broker with budget and data-classification enforcement."""

from __future__ import annotations

import copy
import logging
from pathlib import Path
from typing import Any, Optional

import yaml

from .adapters.generic_openai_adapter import GenericOpenAIComputeProvider
from .adapters.lan_adapter import LanNodeComputeProvider
from .adapters.local_adapter import LocalComputeProvider
from .adapters.runpod_adapter import RunPodComputeProvider
from .adapters.skypilot_adapter import SkyPilotComputeProvider
from .protocol import BatchJob, ComputeProvider, Endpoint, EndpointSpec, JobHandle

logger = logging.getLogger("ecosystem.compute.broker")

DEFAULT_COMPUTE_CONFIG = {
    "enabled": False,  # Cloud off by default (F6)
    "budget": {
        "monthly_usd": 50.0,
        "per_job_usd": 10.0,
        "max_runtime_hours": 4.0,
    },
    "providers": {
        "order": ["local", "lan_node", "skypilot", "runpod", "generic_openai"],
        "skypilot": {
            "clouds": ["lambda", "runpod", "vast"],
            "autostop_minutes": 15,
            "use_spot": True,
        },
        "runpod": {
            "api_key": "",
        },
        "generic_openai": {
            "base_url": "",
            "api_key": "",
        },
    },
    "classification": {
        "public": ["cloud_ok"],
        "internal": ["lan_ok"],
        "sensitive": ["local_only"],
    },
}


class ComputeBroker:
    """Manages local and cloud compute backends behind a unified interface."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        config_path: Path | str | None = None,
        policy_engine: Any = None,
        registry_client: Any = None,
    ):
        self.policy_engine = policy_engine
        self.registry_client = registry_client
        self.config = copy.deepcopy(DEFAULT_COMPUTE_CONFIG)
        if config_path and Path(config_path).is_file():
            try:
                loaded = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self._deep_update(self.config, loaded)
            except Exception as exc:
                logger.warning("Failed loading compute config from %s: %r", config_path, exc)
        if config:
            self._deep_update(self.config, config)

        self.enabled = bool(self.config.get("enabled", False))
        self.budget = self.config.get("budget", {})
        self.monthly_usd_spent = 0.0

        # Initialize adapters
        self._providers: dict[str, ComputeProvider] = {
            "local": LocalComputeProvider(),
            "lan_node": LanNodeComputeProvider(registry_client=self.registry_client),
            "skypilot": SkyPilotComputeProvider(
                clouds=self.config["providers"].get("skypilot", {}).get("clouds"),
                use_spot=self.config["providers"].get("skypilot", {}).get("use_spot", True),
            ),
            "runpod": RunPodComputeProvider(
                api_key=self.config["providers"].get("runpod", {}).get("api_key", ""),
            ),
            "generic_openai": GenericOpenAIComputeProvider(
                base_url=self.config["providers"].get("generic_openai", {}).get("base_url", ""),
                api_key=self.config["providers"].get("generic_openai", {}).get("api_key", ""),
                is_cloud=bool(self.config["providers"].get("generic_openai", {}).get("base_url")),
            ),
        }

    def _deep_update(self, target: dict, source: dict) -> None:
        for k, v in source.items():
            if isinstance(v, dict) and k in target and isinstance(target[k], dict):
                self._deep_update(target[k], v)
            else:
                target[k] = v

    def register_provider(self, name: str, provider: ComputeProvider) -> None:
        self._providers[name] = provider

    def get_provider(self, name: str) -> Optional[ComputeProvider]:
        return self._providers.get(name)

    def _verify_classification_gate(
        self,
        provider: ComputeProvider,
        classification: str,
        approved_data_release_id: str | None = None,
    ) -> bool:
        """Enforces that sensitive data never leaves local hardware without explicit policy approval."""
        caps = provider.capabilities()
        if not caps.is_cloud:
            return True

        if classification == "sensitive":
            if not approved_data_release_id:
                if self.policy_engine is not None:
                    # Query policy engine decision
                    from ecosystem_policy.engine import ActionRequest
                    decision = self.policy_engine.decide(ActionRequest(
                        actor="compute_broker",
                        action="cloud_compute_egress",
                        action_class="data_release",
                        target={"destination": "cloud_gpu", "classification": "sensitive"},
                        context={"provider": provider.name},
                        authenticated=True,
                    ))
                    if decision.result == "allow":
                        return True
                raise PermissionError(
                    f"Sensitive workload prohibited on cloud provider '{provider.name}': "
                    "requires explicit policy data_release grant."
                )
        return True

    def _verify_budget_gate(self, estimated_cost_usd: float) -> bool:
        per_job_max = float(self.budget.get("per_job_usd", 10.0))
        monthly_max = float(self.budget.get("monthly_usd", 50.0))

        if estimated_cost_usd > per_job_max:
            raise ValueError(
                f"Job estimated cost (${estimated_cost_usd:.2f}) exceeds per-job budget limit (${per_job_max:.2f})"
            )
        if (self.monthly_usd_spent + estimated_cost_usd) > monthly_max:
            raise ValueError(
                f"Job cost (${estimated_cost_usd:.2f}) would exceed monthly compute budget (${monthly_max:.2f}; "
                f"spent so far: ${self.monthly_usd_spent:.2f})"
            )
        return True

    async def ensure_endpoint(
        self,
        spec: EndpointSpec,
        force_provider: Optional[str] = None,
        approved_data_release_id: Optional[str] = None,
    ) -> Endpoint:
        """Find and provision the best eligible endpoint adhering to data-boundary and budget gates."""
        provider_order = [force_provider] if force_provider else self.config.get("providers", {}).get("order", ["local"])

        last_error = None
        for prov_name in provider_order:
            provider = self._providers.get(prov_name)
            if not provider:
                continue

            caps = provider.capabilities()
            if caps.is_cloud and not self.enabled and not force_provider:
                continue

            try:
                self._verify_classification_gate(provider, spec.classification, approved_data_release_id)
                ep = await provider.ensure_endpoint(spec)
                return ep
            except (PermissionError, ValueError) as exc:
                if force_provider:
                    raise
                last_error = exc
                continue
            except Exception as exc:
                if force_provider:
                    raise
                last_error = exc
                logger.debug("Provider %s failed or skipped: %r", prov_name, exc)
                continue

        if isinstance(last_error, (PermissionError, ValueError)):
            raise last_error
        raise RuntimeError(f"Could not provision compute endpoint for spec {spec}: {last_error}")

    async def run_batch(
        self,
        job: BatchJob,
        force_provider: Optional[str] = None,
        approved_data_release_id: Optional[str] = None,
    ) -> JobHandle:
        """Execute a batch job across eligible providers."""
        provider_order = [force_provider] if force_provider else self.config.get("providers", {}).get("order", ["local"])

        last_error = None
        for prov_name in provider_order:
            provider = self._providers.get(prov_name)
            if not provider:
                continue

            caps = provider.capabilities()
            if caps.is_cloud and not self.enabled and not force_provider:
                continue

            try:
                self._verify_classification_gate(provider, job.classification, approved_data_release_id)
                if caps.is_cloud:
                    self._verify_budget_gate(job.estimated_cost_usd)

                handle = await provider.run_batch(job)
                if caps.is_cloud:
                    self.monthly_usd_spent += handle.cost_usd
                return handle
            except (PermissionError, ValueError) as exc:
                if force_provider:
                    raise
                last_error = exc
                continue
            except Exception as exc:
                if force_provider:
                    raise
                last_error = exc
                logger.debug("Batch execution on provider %s failed: %r", prov_name, exc)
                continue

        if isinstance(last_error, (PermissionError, ValueError)):
            raise last_error
        raise RuntimeError(f"Could not execute batch job {job.job_id}: {last_error}")
