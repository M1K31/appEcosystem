import json
from types import SimpleNamespace

import pytest

from ecosystem_ai.analyst_select import resolve_analyst_model
from ecosystem_ai.benchmarks import (
    FLOOR_TASKS,
    KL_DIVERGENCE_CEILING,
    can_select_as_analyst,
    run_floor_suite,
    run_forged_suite,
)
from ecosystem_ai.hardware import HardwareInfo
from ecosystem_ai.profile import AIProfile

_BY_REQUEST = {t.request: t.expected_capability for t in FLOOR_TASKS}


async def _propose_valid(request, context):
    return json.dumps({"proposals": [{"action": _BY_REQUEST[request]}]})


async def _propose_echoes_prompt(request, context):
    return request


async def _propose_prose(request, context):
    return "I'm sorry, I cannot help with that."


def _parse(text):
    """Stand-in for ecosystem_client.contracts.parse_proposals."""
    items = json.loads(text)["proposals"]
    return [SimpleNamespace(action=i["action"]) for i in items]


@pytest.mark.asyncio
async def test_valid_analyst_passes_the_floor():
    res = await run_floor_suite(_propose_valid, _parse)
    assert res.passed and not res.failures


@pytest.mark.asyncio
async def test_prompt_echo_fails_the_floor():
    res = await run_floor_suite(_propose_echoes_prompt, _parse)
    assert not res.passed


@pytest.mark.asyncio
async def test_non_json_fails_the_floor():
    res = await run_floor_suite(_propose_prose, _parse)
    assert not res.passed


@pytest.mark.asyncio
async def test_out_of_scope_proposal_fails_the_floor():
    async def wrong(request, context):
        return json.dumps({"proposals": [{"action": "rm_rf_everything"}]})

    res = await run_floor_suite(wrong, _parse)
    assert not res.passed and res.failures


def test_selection_refuses_a_model_without_a_floor_pass():
    assert can_select_as_analyst("m", floor_passes=set()) is False
    assert can_select_as_analyst("m", floor_passes={"m"}) is True


@pytest.mark.asyncio
async def test_forged_suite_requires_defensive_completion_and_kl_bound():
    ok = await run_forged_suite(_propose_valid, _parse, manifest={"kl_divergence": 0.4})
    assert ok.passed
    bad = await run_forged_suite(_propose_valid, _parse, manifest={"kl_divergence": 2.0})
    assert not bad.passed  # KL over the ceiling fails even with good proposals


@pytest.mark.asyncio
async def test_forged_suite_reads_nested_kl_and_fails_when_missing():
    nested = {"eval_scores": {"kl_divergence": 0.4}}
    assert (await run_forged_suite(_propose_valid, _parse, manifest=nested)).passed
    assert not (await run_forged_suite(_propose_valid, _parse, manifest={})).passed
    assert 0.4 < KL_DIVERGENCE_CEILING < 2.0


def _hw():
    return HardwareInfo(ram_gb=8, cpu_cores=8, arch="x86_64", os_name="linux",
                        has_gpu=False, vram_gb=0.0, free_disk_gb=100.0)


def test_resolve_defaults_to_floor_store_and_fails_closed(monkeypatch):
    profile = AIProfile(selected_model="qwen2.5:7b")
    # Missing/empty store refuses selection by default (fail-closed)
    monkeypatch.setenv("ECOSYSTEM_FLOOR_PASSES_PATH", "/nonexistent/floor_passes.json")
    with pytest.raises(ValueError, match="qwen2.5:7b"):
        resolve_analyst_model(profile, _hw())
    # Explicit pass succeeds
    assert resolve_analyst_model(profile, _hw(), floor_passes={"qwen2.5:7b"}) == "qwen2.5:7b"
    with pytest.raises(ValueError, match="qwen2.5:7b"):
        resolve_analyst_model(profile, _hw(), floor_passes=set())


@pytest.mark.asyncio
async def test_forged_suite_prefers_signed_kl_and_flags_conflicting_override():
    # Unsigned top-level 0.0 must not spoof the signed 0.4: conflict => fail.
    spoof = {"eval_scores": {"kl_divergence": 0.4}, "kl_divergence": 0.0}
    res = await run_forged_suite(_propose_valid, _parse, manifest=spoof)
    assert not res.passed
    assert any("conflicts" in f for f in res.failures)
    # Agreeing values are fine.
    same = {"eval_scores": {"kl_divergence": 0.4}, "kl_divergence": 0.4}
    assert (await run_forged_suite(_propose_valid, _parse, manifest=same)).passed


@pytest.mark.asyncio
async def test_forged_suite_signed_kl_over_ceiling_fails():
    m = {"eval_scores": {"kl_divergence": 2.0}}
    assert not (await run_forged_suite(_propose_valid, _parse, manifest=m)).passed
    # An unsigned 0.0 cannot rescue a signed 2.0.
    m2 = {"eval_scores": {"kl_divergence": 2.0}, "kl_divergence": 0.0}
    assert not (await run_forged_suite(_propose_valid, _parse, manifest=m2)).passed


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [float("nan"), float("inf"), "0.4", True])
async def test_forged_suite_rejects_non_finite_or_non_numeric_kl(bad):
    nested = {"eval_scores": {"kl_divergence": bad}}
    assert not (await run_forged_suite(_propose_valid, _parse, manifest=nested)).passed
    flat = {"kl_divergence": bad}
    assert not (await run_forged_suite(_propose_valid, _parse, manifest=flat)).passed
