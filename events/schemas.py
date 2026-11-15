"""Event, command, and notification envelope schemas for the ecosystem event bus."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, Field, PrivateAttr, field_validator, model_validator

from ecosystem_client.contracts import canonical_signable_command, canonical_signable_event
from ecosystem_client.ulid import generate_ulid, resolve_device_id


class EventSource(BaseModel):
    """Structured event origin carrying both app/service name and device_id.

    Compares equal to a plain string matching `app` and stringifies to `app` so
    existing v1 callers (`event.source == "openeye"`, HTTP headers) remain
    100% source-compatible while v2 consumers access `event.source.device_id`.
    """

    app: str = Field(..., min_length=1, description="Publishing application or service name")
    device_id: str = Field(
        default_factory=resolve_device_id,
        min_length=1,
        description="Originating device identifier",
    )

    def __str__(self) -> str:
        return self.app

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.app == other
        return super().__eq__(other)


class EventEnvelope(BaseModel):
    """
    Standard v2 event envelope wrapping all ecosystem events.

    Includes `schema_version` (2), a monotonic 26-char Crockford Base32 ULID `id`,
    `source.device_id`, and HMAC-SHA256 `signature`. Transparently accepts and
    verifies legacy v1 wire payloads (`source` as plain string without
    `schema_version`) during rolling upgrades.
    """

    schema_version: int = Field(default=2, ge=1)
    id: str = Field(default_factory=generate_ulid)
    type: str = Field(..., description="Event type from EventType enum (e.g., 'security.alert')")
    source: EventSource = Field(..., description="Structured service + device_id origin")
    timestamp: float = Field(default_factory=time.time)
    data: dict[str, Any] = Field(default_factory=dict, description="Event payload")
    correlation_id: Optional[str] = Field(
        default=None,
        description="Optional ID linking related events across services",
    )
    signature: Optional[str] = Field(
        default=None,
        description="HMAC-SHA256 signature of the canonical signable envelope",
    )

    _legacy_v1_wire: bool = PrivateAttr(default=False)

    @model_validator(mode="before")
    @classmethod
    def _detect_legacy_v1_wire(cls, values: Any) -> Any:
        if isinstance(values, dict):
            # When deserializing a signed v1 wire dict (no schema_version, has wire id +
            # timestamp + signature, and string source), preserve schema_version=1 so
            # signable_dict() matches the original v1 HMAC.
            if (
                "schema_version" not in values
                and "id" in values
                and "timestamp" in values
                and values.get("signature") is not None
                and isinstance(values.get("source"), str)
            ):
                patched = dict(values)
                patched["schema_version"] = 1
                return patched
        return values

    @field_validator("source", mode="before")
    @classmethod
    def _coerce_source(cls, v: Union[str, dict[str, Any], EventSource]) -> EventSource:
        if isinstance(v, EventSource):
            return v
        if isinstance(v, str):
            return EventSource(app=v, device_id=resolve_device_id())
        if isinstance(v, dict):
            return EventSource(
                app=str(v.get("app", "")),
                device_id=str(v.get("device_id") or resolve_device_id()),
            )
        raise TypeError(f"Unsupported event source type: {type(v)!r}")

    def model_post_init(self, __context: Any) -> None:
        if self.schema_version == 1:
            self._legacy_v1_wire = True

    def signable_dict(self) -> dict[str, Any]:
        """Return the canonical dict signed by HMAC-SHA256 (excludes signature)."""
        if self._legacy_v1_wire or self.schema_version == 1:
            return {
                "id": self.id,
                "type": self.type,
                "source": self.source.app,
                "timestamp": self.timestamp,
                "data": self.data,
            }
        return canonical_signable_event(
            {
                "schema_version": self.schema_version,
                "id": self.id,
                "type": self.type,
                "source": {"app": self.source.app, "device_id": self.source.device_id},
                "timestamp": self.timestamp,
                "data": self.data,
                "correlation_id": self.correlation_id,
            }
        )


ActionClass = Literal[
    "observe",
    "investigate",
    "contain",
    "remediate",
    "data_release",
    "system_change",
]


class CommandActor(BaseModel):
    id: str = Field(..., min_length=1)
    type: Literal["operator", "service", "automation", "voice_intent", "ai_proposal"]
    app: str = Field(..., min_length=1)
    device_id: str = Field(default_factory=resolve_device_id, min_length=1)
    auth_method: Optional[str] = None


class CommandTarget(BaseModel):
    scope: Literal["local", "device", "group", "ecosystem", "external"]
    device_id: Optional[str] = None
    service: Optional[str] = None
    identifier: Optional[str] = None


class CommandEnvelope(BaseModel):
    """Authenticated command request requiring actor, target, expiry, idempotency, and auth ref."""

    schema_version: int = Field(default=1)
    id: str = Field(default_factory=generate_ulid)
    command: str = Field(..., min_length=3)
    action_class: ActionClass
    actor: CommandActor
    target: CommandTarget
    parameters: dict[str, Any] = Field(default_factory=dict)
    issued_at: float = Field(default_factory=time.time)
    expires_at: float = Field(default_factory=lambda: time.time() + 60.0)
    correlation_id: str = Field(default_factory=generate_ulid)
    idempotency_key: str = Field(default_factory=generate_ulid)
    authorization_ref: Optional[str] = None
    rationale: Optional[str] = None
    ack_required: bool = True
    signature: Optional[str] = None

    @field_validator("authorization_ref")
    @classmethod
    def _reject_notification_as_auth(cls, v: Optional[str]) -> Optional[str]:
        if v and v.startswith(("notify:", "notify.")):
            raise ValueError("A notification reference is never a valid authorization_ref")
        return v

    def signable_dict(self) -> dict[str, Any]:
        return canonical_signable_command(self.model_dump())


class CommandAck(BaseModel):
    """Execution acknowledgment returned by a capability provider."""

    command_id: str
    responder: EventSource
    status: Literal["accepted", "completed", "denied", "deferred", "failed", "cancelled"]
    reason: str = ""
    policy_decision_id: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)
    signature: Optional[str] = None


class NotificationAction(BaseModel):
    id: str = Field(..., min_length=1)
    label: Optional[str] = None
    requires: Literal["none", "freeze_grant", "approver_auth", "policy_admin"] = "none"


class NotificationEnvelope(BaseModel):
    """Deduplicated, privacy-redacted cross-device notification envelope."""

    schema_version: int = Field(default=1)
    type: str = Field(..., pattern=r"^notify\.[a-z][a-z0-9_]*$")
    id: str = Field(default_factory=generate_ulid)
    dedupe_key: str = Field(..., min_length=1)
    source: EventSource
    severity: Literal["low", "medium", "high", "critical"]
    title: str = Field(..., min_length=1)
    body: str = ""
    actions: list[NotificationAction] = Field(default_factory=list)
    privacy: Literal["redacted", "public", "local_only"] = "redacted"
    ttl: str = Field(default="24h", pattern=r"^[0-9]+(s|m|h|d)$")
    deep_link: Optional[str] = None
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    signature: Optional[str] = None
