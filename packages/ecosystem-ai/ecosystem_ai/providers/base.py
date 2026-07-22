"""Provider-agnostic AI interface.

Every backend (Ollama, Anthropic, OpenAI, Gemini, ...) implements the same
`AIProvider` interface and returns the same `ChatResult` shape, so callers never
branch on vendor — AI "works the same" regardless of provider or hardware.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable


class Capability(str, Enum):
    CHAT = "chat"
    TOOLS = "tools"          # function/tool calling
    VISION = "vision"        # image input
    EMBED = "embed"          # text embeddings
    STREAM = "stream"        # streaming responses


@dataclass
class ChatMessage:
    role: str                # "system" | "user" | "assistant" | "tool"
    content: str


@dataclass
class ModelInfo:
    name: str
    family: str = ""
    size_bytes: Optional[int] = None
    # Ollama reports this ("1.1B", "7.2B"); used to judge whether a model is
    # strong enough for judgement-heavy tasks like security analysis.
    parameter_size: Optional[str] = None
    capabilities: set[Capability] = field(default_factory=set)


@dataclass
class ChatResult:
    """Uniform chat response across all providers."""
    text: str
    model: str
    provider: str
    usage: dict[str, Any] = field(default_factory=dict)
    raw: Any = None


class ProviderError(RuntimeError):
    """Raised when a provider call fails (network, auth, model missing)."""


@runtime_checkable
class AIProvider(Protocol):
    """The interface every provider implements."""

    name: str

    async def available(self) -> bool:
        """True if the provider is reachable/usable right now."""
        ...

    async def list_models(self) -> list[ModelInfo]:
        """Models this provider can serve."""
        ...

    async def chat(
        self,
        messages: list[ChatMessage],
        model: Optional[str] = None,
        *,
        tools: Optional[list[dict]] = None,
        stream: bool = False,
    ) -> ChatResult:
        """Run a chat completion and return a uniform ChatResult."""
        ...

    async def embed(self, text: str, model: Optional[str] = None) -> list[float]:
        """Return an embedding vector (providers without embeddings may raise)."""
        ...

    def capabilities(self) -> set[Capability]:
        """Static capability set for this provider."""
        ...
