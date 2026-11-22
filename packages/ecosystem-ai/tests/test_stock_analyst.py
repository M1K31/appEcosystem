import pytest

from ecosystem_ai.analyst import AnalystReply, propose
from ecosystem_ai.analyst_prompt import ANALYST_SYSTEM_PROMPT
from ecosystem_ai.hardware import HardwareInfo
from ecosystem_ai.profile import AIProfile
from ecosystem_ai.providers.base import ChatResult


def _hw(ram_gb=8, has_gpu=False, vram_gb=0.0, cpu_cores=8, arch="x86_64",
        os_name="linux", free_disk_gb=100.0):
    return HardwareInfo(
        ram_gb=ram_gb, cpu_cores=cpu_cores, arch=arch, os_name=os_name,
        has_gpu=has_gpu, vram_gb=vram_gb, free_disk_gb=free_disk_gb,
    )


class _FakeRouter:
    """Mirrors ProviderRouter.chat(messages, task="chat", *, tools=None)."""

    def __init__(self, reply: str):
        self.reply = reply
        self.last_system = None
        self.last_user = None
        self.last_task = None

    async def chat(self, messages, task="chat", *, tools=None):
        self.last_system = next(m.content for m in messages if m.role == "system")
        self.last_user = next(m.content for m in messages if m.role == "user")
        self.last_task = task
        return ChatResult(text=self.reply, model="fake-model", provider="fake")


@pytest.mark.asyncio
async def test_propose_uses_the_analyst_prompt_and_resolved_model():
    router = _FakeRouter(reply='{"proposals": []}')
    out = await propose("block 10.0.0.5", {"source": "afs"}, router=router,
                        profile=AIProfile(selected_model="mistral:7b"), hw=_hw(ram_gb=8))
    assert isinstance(out, AnalystReply)
    assert out.model == "mistral:7b" and out.source == "stock"
    assert router.last_system == ANALYST_SYSTEM_PROMPT
    assert router.last_task == "security_analyst"
    assert "block 10.0.0.5" in router.last_user and "afs" in router.last_user


@pytest.mark.asyncio
async def test_propose_output_round_trips_through_parse_proposals():
    valid = '{"proposals": [{"action":"containment.block_ip","action_class":"contain","target":"10.0.0.5","parameters":{},"rationale":"r","confidence":0.7}]}'
    router = _FakeRouter(reply=valid)
    out = await propose("x", {}, router=router, profile=AIProfile(selected_model="m"), hw=_hw(ram_gb=8))
    from ecosystem_client.contracts import parse_proposals
    assert len(parse_proposals(out.text)) == 1
