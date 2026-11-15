"""Data structures and constants for `ecosystem_policy`."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ACTION_CLASSES = (
    "observe",
    "investigate",
    "contain",
    "remediate",
    "data_release",
    "system_change",
)

POLICY_MODES = ("normal", "incident", "survival", "freeze", "maintenance")

ALWAYS_ENFORCED_INVARIANTS = [
    "command_authentication",
    "target_authorization_and_consent",
    "input_validation",
    "audit",
    "freeze",
    "cloud_budget_and_data_boundary",
]


@dataclass
class ActionRequest:
    """Canonical policy evaluation input across every ecosystem project."""

    actor: str
    action: str
    action_class: str
    target: dict[str, Any] = field(default_factory=dict)
    model: str | None = None
    context: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    authenticated: bool = True

    @property
    def app_name(self) -> str:
        return self.actor.split("/", 1)[0].strip()


@dataclass
class PolicyDecision:
    """Result returned by `PolicyEngine.decide(req)`."""

    result: str  # "allow" | "allow_and_notify" | "require_approval" | "deny"
    reason: str
    policy_version: int
    mode: str
    restrictions: str  # "on" | "off_scoped"
    frozen: bool
    async_approval: bool = False
    ttl_seconds: int | None = None
    on_deny: str = "abort"
    revert_plan: dict[str, Any] | None = None
    grant_id: str | None = None
    notice: str | None = None
    deadline: str | None = None
    audit_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "mode": self.mode,
            "restrictions": self.restrictions,
            "frozen": self.frozen,
            "async_approval": self.async_approval,
            "ttl_seconds": self.ttl_seconds,
            "on_deny": self.on_deny,
            "revert_plan": self.revert_plan,
            "grant_id": self.grant_id,
            "notice": self.notice,
            "deadline": self.deadline,
            "audit_hash": self.audit_hash,
        }


@dataclass
class DeviceEnrollment:
    """Cryptographic device identity + AUP consent record (immune to DHCP IP reuse)."""

    device_id: str
    public_key_fingerprint: str
    owner: str
    aup_version: str = "1.0"
    scopes: list[str] = field(default_factory=lambda: ["system_info"])
    enrolled_at: float = 0.0
    revoked: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "public_key_fingerprint": self.public_key_fingerprint,
            "owner": self.owner,
            "aup_version": self.aup_version,
            "scopes": list(self.scopes),
            "enrolled_at": self.enrolled_at,
            "revoked": self.revoked,
        }


@dataclass
class AutoScanGrant:
    """Explicit owner grant authorizing automatic defensive scans for a specific enrolled device."""

    device_id: str
    public_key_fingerprint: str
    profiles: list[str] = field(default_factory=lambda: ["quick"])
    scopes: list[str] = field(default_factory=lambda: ["system_info", "zbt_scan"])
    initiators: list[str] = field(default_factory=lambda: ["*"])
    authorization_ref: str = "owner-explicit-designation"
    expires_at: str | None = None
    revoked: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "public_key_fingerprint": self.public_key_fingerprint,
            "profiles": list(self.profiles),
            "scopes": list(self.scopes),
            "initiators": list(self.initiators),
            "authorization_ref": self.authorization_ref,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
        }

