"""LLM workload placement (facilitator role, Phase F).

Given the registered services and the hardware they reported (`resources`), the
registry recommends the best host to run LLM workloads on — so heavy inference
lands on the most capable, healthy node instead of oversubscribing a weak one.
Reporting resources is optional; hosts that don't report are ranked lowest.
"""

from __future__ import annotations

from typing import Any, Optional

from .models import HealthStatus, ServiceRecord


def _capability_key(record: ServiceRecord) -> tuple:
    """Sort key: prefer healthy, then higher tier, VRAM, RAM, GPU, priority."""
    r = record.resources or {}
    healthy = 1 if record.status == HealthStatus.HEALTHY else 0
    try:
        tier = int(r.get("tier", -1))
    except (TypeError, ValueError):
        tier = -1
    return (
        healthy,
        tier,
        float(r.get("vram_gb", 0) or 0),
        float(r.get("ram_gb", 0) or 0),
        1 if r.get("has_gpu") else 0,
        record.priority,
    )


def rank_hosts(records: list[ServiceRecord]) -> list[ServiceRecord]:
    """Rank services by LLM-hosting capability (best first).

    Only services that reported `resources` are considered candidates."""
    candidates = [r for r in records if r.resources]
    return sorted(candidates, key=_capability_key, reverse=True)


def recommend_llm_host(records: list[ServiceRecord]) -> Optional[dict[str, Any]]:
    """Return the recommended LLM host, or None if no service reported resources."""
    ranked = rank_hosts(records)
    if not ranked:
        return None
    best = ranked[0]
    return {
        "name": best.name,
        "base_url": best.base_url,
        "status": best.status.value,
        "resources": best.resources,
        "ranked": [r.name for r in ranked],
    }
