"""Unit tests for Phase 5 Compute Broker, Cloud GPU adapters, budget gates, and doctor gpu."""

from __future__ import annotations

import pytest

from ecosystem_compute import (
    BatchJob,
    ComputeBroker,
    EndpointSpec,
    diagnose_gpu,
)
from ecosystem_compute.adapters.runpod_adapter import RunPodComputeProvider
from ecosystem_policy.crypto import Ed25519PolicySigner
from ecosystem_policy.engine import PolicyEngine


def test_broker_default_is_local_only():
    broker = ComputeBroker()
    assert broker.enabled is False
    caps = broker.get_provider("local").capabilities()
    assert caps.is_cloud is False


@pytest.mark.asyncio
async def test_broker_sensitive_classification_blocks_cloud(tmp_path):
    signer = Ed25519PolicySigner.generate()
    policy = PolicyEngine({}, signer=signer, persistence_path=tmp_path / "p.json")

    # Cloud enabled in config
    broker = ComputeBroker(
        config={"enabled": True},
        policy_engine=policy,
    )

    spec_sensitive = EndpointSpec(model="llama3.1:8b", classification="sensitive")

    # Local handles sensitive fine
    ep_local = await broker.ensure_endpoint(spec_sensitive, force_provider="local")
    assert ep_local.provider_name == "local"
    assert ep_local.is_cloud is False

    # Cloud provider without policy approval is rejected
    with pytest.raises(PermissionError) as exc_info:
        await broker.ensure_endpoint(spec_sensitive, force_provider="runpod")
    assert "Sensitive workload prohibited on cloud provider" in str(exc_info.value)


@pytest.mark.asyncio
async def test_broker_budget_enforcement():
    broker = ComputeBroker(
        config={
            "enabled": True,
            "budget": {"monthly_usd": 10.0, "per_job_usd": 2.0},
        }
    )

    # 1. Job exceeding per_job_usd limit
    big_job = BatchJob(
        job_id="job-1",
        command=["python3", "train.py"],
        classification="internal",
        estimated_cost_usd=5.0,
    )
    with pytest.raises(ValueError) as exc:
        await broker.run_batch(big_job, force_provider="runpod")
    assert "exceeds per-job budget limit" in str(exc.value)

    # 2. Cumulative spend exceeding monthly budget
    broker.monthly_usd_spent = 9.50
    ok_job = BatchJob(
        job_id="job-2",
        command=["python3", "infer.py"],
        classification="internal",
        estimated_cost_usd=1.0,
    )
    with pytest.raises(ValueError) as exc:
        await broker.run_batch(ok_job, force_provider="runpod")
    assert "would exceed monthly compute budget" in str(exc.value)


@pytest.mark.asyncio
async def test_broker_failover_to_local_when_cloud_disabled():
    broker = ComputeBroker(
        config={
            "enabled": False,  # Cloud disabled
            "providers": {"order": ["runpod", "local"]},
        }
    )
    spec = EndpointSpec(model="llama3.1:8b")
    ep = await broker.ensure_endpoint(spec)
    # Even though runpod was first in order, it fell back to local because cloud is disabled
    assert ep.provider_name == "local"


def test_doctor_gpu_diagnostics():
    diag = diagnose_gpu()
    assert diag.os_name in ("darwin", "linux", "win32")
    assert diag.status in ("ok", "warning")
    assert isinstance(diag.recommendations, list)

