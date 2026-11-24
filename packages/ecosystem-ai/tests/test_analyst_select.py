from ecosystem_ai.analyst_select import TIER_ANALYST_MODELS, resolve_analyst_model
from ecosystem_ai.hardware import CapabilityTier, HardwareInfo
from ecosystem_ai.profile import AIProfile


def _hw(ram_gb=8, has_gpu=False, vram_gb=0.0, cpu_cores=8, arch="x86_64",
        os_name="linux", free_disk_gb=100.0):
    return HardwareInfo(
        ram_gb=ram_gb, cpu_cores=cpu_cores, arch=arch, os_name=os_name,
        has_gpu=has_gpu, vram_gb=vram_gb, free_disk_gb=free_disk_gb,
    )


def test_explicit_task_model_wins():
    p = AIProfile(task_models={"security_analyst": "my-forged:latest"})
    assert resolve_analyst_model(p, _hw(ram_gb=8)) == "my-forged:latest"


def test_falls_back_to_tier_when_auto():
    p = AIProfile(task_models={"security_analyst": "auto"}, selected_model="auto")
    assert resolve_analyst_model(p, _hw(ram_gb=64, has_gpu=True, vram_gb=24)) == TIER_ANALYST_MODELS[CapabilityTier.T3_HIGH_END]


def test_never_tinyllama_for_any_tier():
    for tier_hw in (_hw(ram_gb=2), _hw(ram_gb=8), _hw(ram_gb=16), _hw(ram_gb=64, has_gpu=True, vram_gb=24)):
        assert "tinyllama" not in resolve_analyst_model(AIProfile(), tier_hw).lower()


def test_selected_model_used_when_task_is_auto():
    p = AIProfile(task_models={"security_analyst": "auto"}, selected_model="mistral:7b")
    assert resolve_analyst_model(p, _hw(ram_gb=8)) == "mistral:7b"


def test_default_profile_has_security_analyst_auto():
    assert AIProfile().task_models["security_analyst"] == "auto"


def test_tier_mapping_per_hardware():
    p = AIProfile()
    assert resolve_analyst_model(p, _hw(ram_gb=2)) == "llama3.2:1b"
    assert resolve_analyst_model(p, _hw(ram_gb=8)) == "llama3.2:3b"
    assert resolve_analyst_model(p, _hw(ram_gb=16)) == "llama3.1:8b-instruct"


def test_no_tinyllama_in_map_and_unknown_tier_safe(monkeypatch):
    assert all("tinyllama" not in m.lower() for m in TIER_ANALYST_MODELS.values())
    import ecosystem_ai.analyst_select as a
    monkeypatch.setattr(a, "tier_for", lambda hw: None)
    assert resolve_analyst_model(AIProfile(), _hw()) == "llama3.2:1b"
