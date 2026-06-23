"""Tests for LLM workload placement (Phase F)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from registry.models import HealthStatus, ServiceRecord
from registry.placement import rank_hosts, recommend_llm_host


def _rec(name, tier=None, ram=0, vram=0, gpu=False, status=HealthStatus.HEALTHY, report=True):
    resources = {}
    if report:
        resources = {"tier": tier, "ram_gb": ram, "vram_gb": vram, "has_gpu": gpu}
    return ServiceRecord(
        name=name, host="h", port=8000, health_endpoint="/h",
        base_url=f"http://{name}:8000", status=status, resources=resources,
    )


def test_no_resources_reported_returns_none():
    recs = [_rec("a", report=False), _rec("b", report=False)]
    assert recommend_llm_host(recs) is None


def test_highest_tier_wins():
    recs = [
        _rec("pi", tier=0, ram=4),
        _rec("workstation", tier=3, ram=32, vram=16, gpu=True),
        _rec("laptop", tier=2, ram=16),
    ]
    best = recommend_llm_host(recs)
    assert best["name"] == "workstation"
    assert best["ranked"][0] == "workstation"
    assert best["ranked"][-1] == "pi"


def test_healthy_preferred_over_unhealthy_higher_tier():
    recs = [
        _rec("down-beast", tier=3, ram=64, vram=24, gpu=True, status=HealthStatus.UNHEALTHY),
        _rec("up-modest", tier=1, ram=8),
    ]
    best = recommend_llm_host(recs)
    assert best["name"] == "up-modest"  # healthy beats a downed higher-tier host


def test_vram_breaks_tier_ties():
    recs = [
        _rec("gpu8", tier=2, ram=16, vram=8, gpu=True),
        _rec("gpu16", tier=2, ram=16, vram=16, gpu=True),
    ]
    assert recommend_llm_host(recs)["name"] == "gpu16"


def test_only_reporting_hosts_are_candidates():
    recs = [_rec("silent", report=False), _rec("reporter", tier=1, ram=8)]
    ranked = rank_hosts(recs)
    assert [r.name for r in ranked] == ["reporter"]
