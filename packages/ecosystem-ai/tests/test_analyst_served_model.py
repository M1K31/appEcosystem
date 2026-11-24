from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ecosystem_ai.analyst import propose
from ecosystem_ai.hardware import HardwareInfo
from ecosystem_ai.profile import AIProfile


def _hw():
    return HardwareInfo(
        ram_gb=8, cpu_cores=8, arch="x86_64", os_name="linux",
        has_gpu=False, vram_gb=0.0, free_disk_gb=100.0,
    )


@pytest.mark.asyncio
async def test_propose_succeeds_when_served_matches_resolved():
    profile = AIProfile(selected_model="test-analyst:7b")
    router = SimpleNamespace()
    router.chat = AsyncMock(return_value=SimpleNamespace(
        text='{"proposals": []}',
        model="test-analyst:7b",
        provider="ollama",
    ))

    reply = await propose(
        "Check honeypot",
        {},
        router=router,
        profile=profile,
        hw=_hw(),
        floor_passes={"test-analyst:7b"},
    )

    assert reply.model == "test-analyst:7b"
    assert reply.served_model == "test-analyst:7b"
    assert reply.provider == "ollama"
    router.chat.assert_awaited_once()
    call_kwargs = router.chat.await_args[1]
    assert call_kwargs.get("model") == "test-analyst:7b"


@pytest.mark.asyncio
async def test_propose_rejects_served_model_mismatch():
    profile = AIProfile(selected_model="test-analyst:7b")
    router = SimpleNamespace()
    # Router quietly served a fallback model instead
    router.chat = AsyncMock(return_value=SimpleNamespace(
        text='{"proposals": []}',
        model="tinyllama:1.1b",
        provider="ollama",
    ))

    with pytest.raises(ValueError, match="does not match resolved analyst model"):
        await propose(
            "Check honeypot",
            {},
            router=router,
            profile=profile,
            hw=_hw(),
            floor_passes={"test-analyst:7b"},
        )
