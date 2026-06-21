# Ecosystem AI/LLM & Hardware-Adaptivity Plan (Revised)

**Prepared for:** Smart Industries LLC
**Date:** 2026-06-20
**Supersedes:** the LLM sections of [ECOSYSTEM_AUDIT.md](ECOSYSTEM_AUDIT.md) Phase B.

## Guiding requirements (from product direction)

1. **Ollama is the default LLM** everywhere (local-first: private, offline, free).
2. **Every project can integrate cloud/agentic providers** — Anthropic (Claude),
   OpenAI, GitHub Copilot, Gemini, etc. — as opt-in, pluggable backends.
3. **Compatibility & scalability are core tenets.** Apps must **detect hardware
   capability and deactivate features that cannot run**, degrading gracefully.
4. **AI features behave the same** regardless of provider or hardware — identical
   API/behavior; only *quality/speed* scales. No AI implementation may compromise
   compatibility, scalability, or security.
5. **Maximize functionality on old hardware; unlock modern capability on new
   hardware.**

These turn "consistent LLM config" (original Phase B) into a larger goal: a
**shared, hardware-adaptive, provider-pluggable AI layer** used by all apps.

---

## 1. Architecture

### 1.1 Shared `ecosystem_ai` library (new, single versioned package)
One implementation, consumed by AFS, LogAnalysis, OpenEye, MagicMirror (and
usable by appEcosystem). Replaces today's per-app, divergent LLM code. Modules:

- **`providers/`** — a uniform `AIProvider` interface so callers never branch on
  vendor:
  ```
  class AIProvider(Protocol):
      name: str
      async def available() -> bool
      async def list_models() -> list[ModelInfo]
      async def chat(messages, model=None, *, tools=None, stream=False) -> ChatResult
      async def embed(text) -> list[float]            # optional capability
      def capabilities() -> set[Capability]            # {chat, tools, vision, embed}
  ```
  Implementations: `OllamaProvider` (default), `AnthropicProvider`,
  `OpenAIProvider`, `CopilotProvider`, `GeminiProvider`. New providers are drop-in.
  All return the **same `ChatResult` schema** ⇒ "works the same."

- **`router.py` — `ProviderRouter`.** Resolves which provider/model handles a
  request using precedence: **explicit call arg → app config → ecosystem LLM
  profile (when registry present) → Ollama default**. Supports per-task routing
  (e.g. embeddings local even when chat is cloud) and automatic fallback
  (cloud → local, or large → small) on error/unavailability.

- **`hardware.py` — `HardwareProbe` + capability tiers** (see §1.2).

- **`features.py` — `CapabilityManager`.** Maps declared feature requirements to
  the detected tier and toggles features on/off with a human-readable reason.

- **`profile.py`** — load/merge the ecosystem AI profile (from `ecosystem.yaml`
  / registry `GET /ai-profile`) with local overrides.

### 1.2 Hardware capability detection & tiers

`HardwareProbe` (cross-platform, stdlib + `psutil`; GPU via `nvidia-smi`,
`torch.cuda` if present, Apple Metal via `platform`/`sysctl`) reports:
RAM, CPU cores, arch (arm64/x86_64), GPU + VRAM, free disk for models, OS.

It resolves a **capability tier**; AI features and default model size key off it:

| Tier | Example hardware | Local LLM default | Posture |
|------|------------------|-------------------|---------|
| **T0 Minimal** | Pi 4 / <4 GB / no GPU | none or `llama3.2:1b` if RAM allows | Local AI mostly off; use cloud **iff** a key is set; core non-AI features only |
| **T1 Modest** | 4–8 GB, no/weak GPU, Pi 5 | `llama3.2:3b` (quantized) | Basic local AI; heavy features off |
| **T2 Capable** | 16 GB+, Apple Silicon / entry GPU | `llama3.1:8b` | Full local chat + tools; vision optional |
| **T3 High-end** | 32 GB+, discrete GPU ≥12 GB VRAM | `llama3.1:8b`→`70b`, vision models | Everything, largest models |

Rules:
- **Default provider is always Ollama**; the **tier picks the model size** that
  fits, so the same feature runs everywhere at hardware-appropriate quality.
- If a feature's minimum tier isn't met **and** no suitable cloud key is set,
  the feature is **deactivated with a reason** (API returns a typed
  "feature unavailable"; UI shows it greyed with an explanation) — never a crash.
- Cloud providers can **lift** a low-tier host (e.g. T0 with an Anthropic key
  still gets strong chat) — preserving functionality where the user opts in.

### 1.3 Ecosystem AI profile
Add an `ai:`/`llm:` block to `appEcosystem/ecosystem.yaml` and serve it at
`GET /ai-profile`:
```yaml
ai:
  default_provider: ollama
  ollama_base_url: http://localhost:11434
  models_dir: ""            # one shared store; blank = ollama default
  task_models:             # per task-class, resolved against the tier
    chat: auto             # "auto" => tier default
    embed: nomic-embed-text
    vision: llava
  cloud:
    anthropic: { enabled: false, model: claude-... }
    openai:    { enabled: false, model: gpt-... }
    copilot:   { enabled: false }
  routing:
    prefer: local          # local | cloud | quality
    allow_cloud_fallback: true
```
Members fetch this on startup (when the registry is present) and merge it under
their local overrides — **set once, applies everywhere**; standalone keeps local
defaults.

### 1.4 Security & resource constraints (non-negotiable)
- Cloud keys come only from env/secret store, never the registry payload; the
  profile carries *which* provider/model, never secrets.
- One shared Ollama instance + one `models_dir` ⇒ a single model store (no
  multi-GB duplication). The facilitator may place LLM load on the most capable
  host via resource-budget signals (event bus), without oversubscribing.
- All AI calls keep the existing replay-resistant ecosystem auth.

---

## 2. Revised Phased Plan

> Phase A (ports) from the original audit is unchanged and remains the
> prerequisite for trustworthy facilitated mode.

- **Phase A — Port reconciliation** *(prerequisite, unchanged)*: one resolved
  port var for bind＝register; fix OpenEye bind≠register; correct
  `ecosystem.yaml`; collision-free defaults; preflight + tests.

- **Phase B0 — `ecosystem_ai` foundation**: build the provider interface,
  `OllamaProvider`, `ProviderRouter`, `HardwareProbe` + tiers, and
  `CapabilityManager`, with full unit tests. Package as one versioned library.

- **Phase B1 — Provider plug-ins**: `Anthropic`, `OpenAI`, `Copilot`, `Gemini`
  providers behind the same interface; opt-in via keys; fallback routing.

- **Phase B2 — Ecosystem AI profile**: `ai:` in `ecosystem.yaml`,
  `GET /ai-profile`, `EcosystemConfig` extension + precedence resolution.

- **Phase B3 — Adopt in each app**: replace AFS/LogAnalysis/OpenEye/MagicMirror
  LLM code with `ecosystem_ai`; **OpenEye gains an Ollama path** (Claude stays an
  option); confirm Ollama is the default in all four.

- **Phase C — Hardware-adaptive feature gating**: each app declares feature
  requirements; `CapabilityManager` enables/disables per tier; graceful
  "feature unavailable" responses + UI affordances; documented degradation
  matrix per app.

- **Phase D — AFS↔LogAnalysis synergy** *(unchanged)*: first-class log/network
  agent tools + event-bus correlation, now over the shared AI layer.

- **Phase E — Hardening parity** *(unchanged)*: re-sync v0.3.0 auth into every
  embedded client.

- **Phase F — Facilitator placement** *(new, scalability)*: resource-budget
  signals on the event bus; appEcosystem recommends/places LLM workloads on the
  most capable reachable host.

---

## 3. Per-app impact summary

| App | Today | After |
|-----|-------|-------|
| AFS | Hub: Ollama+OpenAI+Anthropic, own config | Uses `ecosystem_ai`; stays hub; tier-aware model selection |
| LogAnalysis | Ollama + `models_dir` | Uses `ecosystem_ai`; shares Ollama/profile |
| OpenEye | **Anthropic-only** | **Gains Ollama default** + pluggable cloud; tier-gated vision |
| MagicMirror | Multi-provider, light | Uses `ecosystem_ai`; tier-gated HUD AI widgets |
| appEcosystem | No AI profile | Serves `GET /ai-profile`, placement signals |

---

## 4. Open decisions for sign-off
1. **Shared library delivery**: publish `ecosystem_ai` (and `ecosystem_client`)
   as installable packages vs. keep vendored copies synced by CI. *(Recommend:
   one package — kills drift and security-fix lag.)*
2. **Tier thresholds**: confirm the RAM/VRAM cutoffs and the default model per
   tier (above are proposed starting points).
3. **Copilot integration**: confirm target (GitHub Copilot API / Copilot-style
   endpoint) — access model differs from OpenAI/Anthropic.

*Plan by Smart Industries LLC.*
