"""ECO-05 tests: Dynamic VRAM Model Quantization Down-Shifting."""
from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from ecosystem_ai.vram_monitor import (
    MemorySample,
    VramQuantizationMonitor,
    extract_model_quantization,
    rewrite_model_quantization,
    step_down_quantization,
)


def test_quantization_step_down_and_model_tag_rewriting():
    assert step_down_quantization("Q8", min_quant="Q4_K_M", direct_to_target="Q4_K_M") == "Q4_K_M"
    assert step_down_quantization("Q8_0", min_quant="Q4_K_M") == "Q6_K"
    assert step_down_quantization("Q4_K_M", min_quant="Q4_K_M") is None

    assert rewrite_model_quantization("llama3.1:8b-instruct-q8_0", "Q4_K_M") == "llama3.1:8b-instruct-q4_k_m"
    assert rewrite_model_quantization("qwen2.5:14b", "Q4_K_M") == "qwen2.5:14b-q4_k_m"
    assert rewrite_model_quantization("model-Q8_0.gguf", "Q4_K_M") == "model-q4_k_m.gguf"
    assert rewrite_model_quantization("model.Q8_0.gguf", "Q4_K_M") == "model.q4_k_m.gguf"
    assert rewrite_model_quantization("model-Q8_1.gguf", "Q4_K_M") == "model-Q8_1.gguf:q4_k_m"
    assert rewrite_model_quantization("auto", "Q4_K_M") == "auto"

    assert extract_model_quantization("llama3.1:8b-instruct-q4_k_m") == "Q4_K_M"
    assert extract_model_quantization("model-Q8_0.gguf") == "Q8_0"
    assert extract_model_quantization("model.Q8_0.gguf") == "Q8_0"
    assert extract_model_quantization("auto", default="Q8_0") == "Q8_0"
    assert extract_model_quantization("qwen2.5:14b", default="Q8_0") == "Q8_0"


def test_vram_monitor_hysteresis_downshift_cooldown_and_restore():
    events = []
    mon = VramQuantizationMonitor(
        baseline_quant="Q8_0",
        downshift_target_quant="Q4_K_M",
        min_quant="Q4_K_M",
        low_headroom_gb=2.0,
        restore_headroom_gb=3.5,
        consecutive_low_samples=2,
        consecutive_restore_samples=3,
        cooldown_seconds=60.0,
        model_name="llama3.1:8b-instruct-q8_0",
        on_shift=lambda ev: events.append(ev),
    )

    # Single transient dip below 2 GB does NOT trigger down-shift
    assert mon.evaluate_sample(MemorySample(1.4, 16.0, "macos_vm_stat", True), now=1000.0) is None
    assert mon.status()["active_quant"] == "Q8_0"

    # Recovery resets low streak
    assert mon.evaluate_sample(MemorySample(2.5, 16.0, "macos_vm_stat", True), now=1010.0) is None
    assert mon.evaluate_sample(MemorySample(1.5, 16.0, "macos_vm_stat", True), now=1020.0) is None
    assert mon.status()["active_quant"] == "Q8_0"

    # Second consecutive dip below 2 GB triggers down-shift Q8_0 -> Q4_K_M
    ev_down = mon.evaluate_sample(MemorySample(1.2, 16.0, "macos_vm_stat", True), now=1030.0)
    assert ev_down is not None
    assert ev_down.action == "downshift"
    assert ev_down.from_quant == "Q8_0"
    assert ev_down.to_quant == "Q4_K_M"
    assert ev_down.recommended_model == "llama3.1:8b-instruct-q4_k_m"
    assert mon.status()["downshifted"] is True

    # Mid-band headroom (2.5 GB < 3.5 GB restore threshold) stays down-shifted
    assert mon.evaluate_sample(MemorySample(2.5, 16.0, "macos_vm_stat", True), now=1100.0) is None
    assert mon.status()["active_quant"] == "Q4_K_M"

    # Cooldown prevents immediate restore even above 3.5 GB
    assert mon.evaluate_sample(MemorySample(5.0, 16.0, "macos_vm_stat", True), now=1040.0) is None
    assert mon.evaluate_sample(MemorySample(5.0, 16.0, "macos_vm_stat", True), now=1050.0) is None
    assert mon.evaluate_sample(MemorySample(5.0, 16.0, "macos_vm_stat", True), now=1060.0) is None
    assert mon.status()["active_quant"] == "Q4_K_M"

    # After cooldown expires, restore triggers cleanly back to Q8_0
    ev_up = mon.evaluate_sample(MemorySample(5.0, 16.0, "macos_vm_stat", True), now=1105.0)
    assert ev_up is not None
    assert ev_up.action == "restore"
    assert ev_up.to_quant == "Q8_0"
    assert mon.status()["downshifted"] is False


def test_vram_monitor_poll_once_invokes_async_callback():
    received = []
    samples = iter([
        MemorySample(1.1, 16.0, "nvidia_smi", False),
        MemorySample(1.0, 16.0, "nvidia_smi", False),
    ])

    async def _cb(ev):
        received.append(ev)

    mon = VramQuantizationMonitor(
        consecutive_low_samples=2,
        probe_fn=lambda: next(samples),
        on_shift=_cb,
    )
    assert asyncio.run(mon.poll_once()) is None
    ev = asyncio.run(mon.poll_once())
    assert ev is not None and len(received) == 1
    assert received[0].to_quant == "Q4_K_M"


def test_registry_memory_pressure_endpoint(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", "v" * 64)
    monkeypatch.setenv("ECOSYSTEM_REGISTRY_FILE", str(tmp_path / "registry.json"))
    monkeypatch.setenv("ECOSYSTEM_CAPABILITIES_FILE", str(tmp_path / "caps.json"))
    monkeypatch.setenv("ECOSYSTEM_NOTIFICATIONS_DB", str(tmp_path / "notify.db"))
    monkeypatch.setenv("ECOSYSTEM_AI_PROFILE_FILE", str(tmp_path / "ai_profile.json"))
    monkeypatch.setenv("ECOSYSTEM_POLICY_KEY_DIR", str(tmp_path / "pkeys"))
    monkeypatch.setenv("ECOSYSTEM_POLICY_STATE_FILE", str(tmp_path / "pstate.json"))
    monkeypatch.setenv("ECOSYSTEM_STEP_UP_FILE", str(tmp_path / "step_up.json"))
    monkeypatch.setenv("ECOSYSTEM_APPROVALS_DB", str(tmp_path / "approvals.db"))
    monkeypatch.setenv("ECOSYSTEM_PAIRING_DIR", str(tmp_path / "pairing"))

    from registry.app import app

    with TestClient(app) as client:
        r = client.get("/ai-profile/memory-pressure")
        assert r.status_code == 200
        body = r.json()
        assert body["baseline_quant"] == "Q8_0"
        assert body["low_headroom_gb"] == 2.0
        assert body["downshifted"] is False

        # Verify _on_vram_shift rolls back when no subscriber received the event
        async def _undelivered_publish(envelope):
            return {"delivered": 0, "failed": 1, "subscribers": ["ollama"]}

        monkeypatch.setattr(app.state.event_bus, "publish", _undelivered_publish)
        mon = app.state.vram_monitor
        low_samples = iter([
            MemorySample(1.1, 16.0, "nvidia_smi", False),
            MemorySample(1.0, 16.0, "nvidia_smi", False),
        ])
        mon._probe_fn = lambda: next(low_samples)
        assert asyncio.run(mon.poll_once()) is None
        assert asyncio.run(mon.poll_once()) is None
        assert mon.status()["active_quant"] == "Q8_0"
        assert mon.status()["downshifted"] is False

        # Verify _on_vram_shift commits when a subscriber receives the EventEnvelope
        published = []

        async def _capture_publish(envelope):
            published.append(envelope)
            return {"delivered": 1, "failed": 0, "subscribers": ["ollama"]}

        monkeypatch.setattr(app.state.event_bus, "publish", _capture_publish)
        mon._probe_fn = lambda: MemorySample(1.0, 16.0, "nvidia_smi", False)
        ev = asyncio.run(mon.poll_once())
        assert ev is not None
        assert len(published) == 1
        assert published[0].type == "ai.quantization.downshift"
        assert published[0].source == "ecosystem_registry"
        assert published[0].data["to_quant"] == "Q4_K_M"
        assert mon.status()["downshifted"] is True

        # Verify configure_model synchronizes baseline and resets downshift state
        mon.configure_model("llama3.1:8b-instruct-q4_k_m")
        st = mon.status()
        assert st["model_name"] == "llama3.1:8b-instruct-q4_k_m"
        assert st["baseline_quant"] == "Q4_K_M"
        assert st["active_quant"] == "Q4_K_M"
        assert st["downshifted"] is False
