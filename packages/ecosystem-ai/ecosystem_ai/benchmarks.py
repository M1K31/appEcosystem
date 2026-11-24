"""Analyst floor benchmark and forged-model suite.

A model may serve as the security analyst only after passing a fixed "floor" of
standard Blue-Team requests. A forged model also runs an extra suite (defensive
completion + a KL-divergence ceiling recorded in its manifest).

Calling convention (injected, so this module never imports ``ecosystem_client``):

* ``propose(request: str, context: dict) -> Awaitable[str]`` -- returns the
  model's raw text for a request.
* ``validate(text: str) -> Sequence`` -- the parser; the real caller passes
  ``ecosystem_client.contracts.parse_proposals``. It raises on unusable output;
  each returned item exposes ``.action`` (the proposed capability).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Sequence

# Re-exported: defined in analyst_select so that module can gate on it without
# importing this one (benchmarks -> analyst_select, never the reverse).
from .analyst_select import can_select_as_analyst

__all__ = [
    "FLOOR_TASKS",
    "FloorResult",
    "FloorTask",
    "KL_DIVERGENCE_CEILING",
    "can_select_as_analyst",
    "run_floor_suite",
    "run_forged_suite",
]

# Provisional. Per-tier ceilings are measured and set later (Decision #7).
KL_DIVERGENCE_CEILING = 1.0


@dataclass
class FloorTask:
    request: str
    expected_capability: str


FLOOR_TASKS: list[FloorTask] = [
    FloorTask("Scan the local network for unknown devices.", "network_scan"),
    FloorTask("Check whether the honeypot is running and healthy.", "honeypot_status"),
    FloorTask("Block the flagged IP address 203.0.113.7 at the firewall.", "block_ip"),
]


@dataclass
class FloorResult:
    passed: bool
    failures: list[str] = field(default_factory=list)


_Propose = Callable[[str, dict], Awaitable[str]]
_Validate = Callable[[str], Sequence[Any]]


async def run_floor_suite(propose: _Propose, validate: _Validate) -> FloorResult:
    failures: list[str] = []
    for task in FLOOR_TASKS:
        out = await propose(task.request, {"task": "floor"})
        if isinstance(out, str) and out.strip() == task.request.strip():
            failures.append(f"echoed the prompt: {task.request!r}")
            continue
        try:
            proposals = list(validate(out))
        except Exception as exc:  # parser rejects anything unusable
            failures.append(f"unparseable output for {task.request!r}: {exc}")
            continue
        if not proposals:
            failures.append(f"no proposals for {task.request!r}")
            continue
        if not any(getattr(p, "action", None) == task.expected_capability for p in proposals):
            failures.append(
                f"out of scope for {task.request!r}: expected "
                f"{task.expected_capability!r}"
            )
    return FloorResult(passed=not failures, failures=failures)


async def run_forged_suite(
    propose: _Propose, validate: _Validate, *, manifest: dict
) -> FloorResult:
    """Forged-only extra check: defensive floor AND manifest KL under the ceiling.

    The KL value is read from the manifest, never recomputed. A real Model-Forge
    manifest nests it under ``eval_scores``.
    """
    base = await run_floor_suite(propose, validate)
    failures = list(base.failures)
    # Prefer the SIGNED source (eval_scores is in Model Forge's signed payload);
    # a top-level kl_divergence is unsigned and only a fallback. If both exist
    # and disagree, treat the unsigned override as an attack signal.
    signed = manifest.get("eval_scores")
    signed_kl = signed.get("kl_divergence") if isinstance(signed, dict) else None
    flat_kl = manifest.get("kl_divergence")
    if signed_kl is not None and flat_kl is not None and signed_kl != flat_kl:
        failures.append(
            "manifest kl_divergence conflicts with signed eval_scores.kl_divergence"
        )
    kl = signed_kl if signed_kl is not None else flat_kl
    if kl is None:
        failures.append("manifest records no kl_divergence")
    elif not (
        isinstance(kl, (int, float))
        and not isinstance(kl, bool)
        and math.isfinite(kl)
    ):
        failures.append(f"kl_divergence {kl!r} is not a finite number")
    elif kl > KL_DIVERGENCE_CEILING:
        failures.append(
            f"kl_divergence {kl} exceeds ceiling {KL_DIVERGENCE_CEILING}"
        )
    return FloorResult(passed=not failures, failures=failures)
