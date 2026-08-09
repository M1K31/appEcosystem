# appecosystem-ai

Shared, hardware-adaptive, provider-pluggable AI layer for
[appEcosystem](https://github.com/M1K31/appEcosystem).

Local models are the default. The router probes the machine's capability tier,
picks a model that will actually run on it, and falls back gracefully when the
preferred one is unavailable. Cloud providers are opt-in, configured per task —
so you can send security analysis to a frontier model while keeping
high-volume chat local and free.

## Install

```bash
pip install appecosystem-ai
```

Requires Python 3.9+. Local inference talks to [Ollama](https://ollama.com) over
HTTP and needs no extra Python packages.

Cloud providers are optional extras — install only what you use:

```bash
pip install "appecosystem-ai[anthropic]"
pip install "appecosystem-ai[openai]"
pip install "appecosystem-ai[gemini]"
```

## Ask a local model

```python
import asyncio
from ecosystem_ai import AIProfile, build_router
from ecosystem_ai.providers import ChatMessage

async def main():
    router = build_router(AIProfile())      # detects this machine's tier
    result = await router.chat(
        [ChatMessage(role="user", content="Summarize today's alerts.")]
    )
    print(result.content)

asyncio.run(main())
```

`build_router()` detects the hardware tier when you do not pass one. Skipping
that detection leaves the stock `selected_model="auto"` profile with no model to
resolve, so let it detect unless you have a specific tier in mind.

## Route a task to the cloud

`task` selects which provider handles the call, per the profile's routing table:

```python
result = await router.chat(messages, task="security")
```

With `task_providers={"security": "anthropic", "chat": "ollama"}`, security
analysis goes to Claude while chat stays local. Tasks that need judgement warn
when the selected model is too small to be trusted with them.

## Check what this machine can run

```python
from ecosystem_ai import detect

info, tier = detect()
print(f"{info.ram_gb} GB RAM, {info.cpu_cores} cores, GPU={info.has_gpu} — tier {tier}")
```

## License

MIT — see [LICENSE](https://github.com/M1K31/appEcosystem/blob/main/LICENSE).
