"""Event envelope schema for the ecosystem event bus."""

import time
import uuid
from typing import Any, Optional

from pydantic import BaseModel, Field


class EventEnvelope(BaseModel):
    """
    Standard event envelope wrapping all ecosystem events.

    Every event published through the bus is wrapped in this envelope
    to provide consistent metadata, tracing, and signature verification.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: str = Field(..., description="Event type from EventType enum (e.g., 'security.alert')")
    source: str = Field(..., description="Service name that published the event")
    timestamp: float = Field(default_factory=time.time)
    data: dict[str, Any] = Field(default_factory=dict, description="Event payload")
    correlation_id: Optional[str] = Field(
        default=None,
        description="Optional ID linking related events across services",
    )
    signature: Optional[str] = Field(
        default=None,
        description="HMAC-SHA256 signature of the data payload",
    )

    def signable_dict(self) -> dict:
        """Return the dict that should be signed (excludes the signature itself)."""
        return {
            "id": self.id,
            "type": self.type,
            "source": self.source,
            "timestamp": self.timestamp,
            "data": self.data,
        }
