"""Phase 1 ecosystem event/command/notification/capability contracts and JSON Schema validation."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from .ulid import generate_ulid, resolve_device_id

_SCHEMAS_DIR = Path(__file__).resolve().parent / "schemas"
_SCHEMA_CACHE: dict[str, dict[str, Any]] = {}


class SchemaValidationError(ValueError):
    """Raised when an envelope or manifest fails JSON Schema validation."""


class EventType(str, Enum):
    """Canonical dot-delimited event types across the appEcosystem mesh."""

    # Security events (OpenEye, AegisSIEM, cyber-agents)
    SECURITY_ALERT = "security.alert"
    SECURITY_MOTION_DETECTED = "security.motion_detected"
    SECURITY_PERSON_DETECTED = "security.person_detected"
    SECURITY_INTRUSION = "security.intrusion"
    SECURITY_THREAT_BLOCKED = "security.threat_blocked"
    SECURITY_IOC_MATCH = "security.ioc_match"

    # System events (any project)
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_HEALTH_CHANGED = "system.health_changed"
    SYSTEM_ERROR = "system.error"
    SYSTEM_CONFIG_CHANGED = "system.config_changed"

    # Network events (AegisSIEM)
    NETWORK_DEVICE_CONNECTED = "network.device_connected"
    NETWORK_DEVICE_DISCONNECTED = "network.device_disconnected"
    NETWORK_ANOMALY = "network.anomaly"
    NETWORK_BANDWIDTH_ALERT = "network.bandwidth_alert"

    # Display events (MagicMirror)
    DISPLAY_UPDATE = "display.update"
    DISPLAY_ALERT = "display.alert"
    DISPLAY_WIDGET_CHANGED = "display.widget_changed"

    # AI events (AI_For_Survival, ecosystem-ai)
    AI_ANALYSIS_COMPLETE = "ai.analysis_complete"
    AI_RECOMMENDATION = "ai.recommendation"
    AI_PLAYBOOK_TRIGGERED = "ai.playbook_triggered"

    # Ecosystem service & freeze lifecycle (registry / hub)
    ECOSYSTEM_SERVICE_REGISTERED = "ecosystem.service_registered"
    ECOSYSTEM_SERVICE_DEREGISTERED = "ecosystem.service_deregistered"
    ECOSYSTEM_SERVICE_UNHEALTHY = "ecosystem.service_unhealthy"
    ECOSYSTEM_AI_PROFILE_CHANGED = "ecosystem.ai_profile_changed"
    ECOSYSTEM_FREEZE_REQUESTED = "ecosystem.freeze_requested"
    ECOSYSTEM_FREEZE_APPLIED = "ecosystem.freeze_applied"
    ECOSYSTEM_RESUME_REQUESTED = "ecosystem.resume_requested"

    # Scanning lifecycle (Zero-Breach-Toolkit / scan_agent)
    SCAN_REQUESTED = "scan.requested"
    SCAN_STARTED = "scan.started"
    SCAN_PROGRESS = "scan.progress"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FINDING = "scan.finding"
    SCAN_AUTHORIZATION_CHANGED = "scan.authorization_changed"

    # Policy, approvals & containment (ecosystem-policy / hub)
    POLICY_DECISION = "policy.decision"
    POLICY_MODE_CHANGED = "policy.mode_changed"
    POLICY_RESTRICTIONS_CHANGED = "policy.restrictions_changed"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_DECIDED = "approval.decided"
    CONTAINMENT_APPLIED = "containment.applied"
    CONTAINMENT_REVERTED = "containment.reverted"

    # Capabilities & automations
    CAPABILITY_REGISTERED = "capability.registered"
    CAPABILITY_WITHDRAWN = "capability.withdrawn"
    AUTOMATION_REQUESTED = "automation.requested"
    AUTOMATION_COMPLETED = "automation.completed"
    AUTOMATION_FAILED = "automation.failed"

    # Cross-device notifications (notify.*)
    NOTIFY_SECURITY = "notify.security"
    NOTIFY_SYSTEM = "notify.system"
    NOTIFY_SCAN = "notify.scan"
    NOTIFY_POLICY = "notify.policy"
    NOTIFY_APPROVAL = "notify.approval"
    NOTIFY_AUTOMATION = "notify.automation"

    # Compute broker & Model Forge
    COMPUTE_JOB_STARTED = "compute.job.started"
    COMPUTE_JOB_COMPLETED = "compute.job.completed"
    COMPUTE_JOB_FAILED = "compute.job.failed"
    MODEL_PUBLISHED = "model.published"

    # Device enrollment
    DEVICE_ENROLLED = "device.enrolled"
    DEVICE_UNENROLLED = "device.unenrolled"


def list_schemas() -> list[str]:
    """Return available contract schema base names (e.g. 'event-envelope.v2')."""
    if not _SCHEMAS_DIR.is_dir():
        return []
    return sorted(
        p.name[: -len(".schema.json")]
        for p in _SCHEMAS_DIR.glob("*.schema.json")
    )


def load_schema(name: str) -> dict[str, Any]:
    """Load a published JSON Schema by name (with or without '.schema.json')."""
    key = name[: -len(".schema.json")] if name.endswith(".schema.json") else name
    if key in _SCHEMA_CACHE:
        return _SCHEMA_CACHE[key]
    path = _SCHEMAS_DIR / f"{key}.schema.json"
    if not path.is_file():
        raise FileNotFoundError(f"Unknown ecosystem contract schema: {name!r}")
    schema = json.loads(path.read_text(encoding="utf-8"))
    _SCHEMA_CACHE[key] = schema
    return schema


def _matches_json_type(value: Any, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "string":
        return isinstance(value, str)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    return True


def _validate_node(value: Any, schema: dict[str, Any], path: str, errors: list[str]) -> None:
    expected_type = schema.get("type")
    if expected_type is not None:
        allowed_types = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(_matches_json_type(value, t) for t in allowed_types):
            errors.append(f"{path}: expected type {allowed_types}, got {type(value).__name__}")
            return

    if value is None:
        return

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {value!r}")

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value {value!r} not in {schema['enum']}")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            errors.append(f"{path}: string shorter than minLength {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: {value!r} does not match pattern {schema['pattern']!r}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: {value} < minimum {schema['minimum']}")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            errors.append(f"{path}: array has fewer than {schema['minItems']} items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for idx, item in enumerate(value):
                _validate_node(item, item_schema, f"{path}[{idx}]", errors)

    if isinstance(value, dict):
        for req_key in schema.get("required", []):
            if req_key not in value:
                errors.append(f"{path}: missing required property {req_key!r}")
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False and props:
            for key in value:
                if key not in props:
                    errors.append(f"{path}: unexpected property {key!r}")
        for key, subschema in props.items():
            if key in value and isinstance(subschema, dict):
                _validate_node(value[key], subschema, f"{path}.{key}", errors)


def validate_against_schema(
    instance: Any, schema: str | dict[str, Any]
) -> list[str]:
    """Validate an instance against a named or inline JSON Schema. Returns errors."""
    schema_dict = load_schema(schema) if isinstance(schema, str) else schema
    errors: list[str] = []
    _validate_node(instance, schema_dict, "$", errors)
    return errors


def assert_valid_schema(instance: Any, schema: str | dict[str, Any]) -> None:
    """Raise SchemaValidationError if instance violates schema."""
    errors = validate_against_schema(instance, schema)
    if errors:
        raise SchemaValidationError("; ".join(errors))


def _norm_ts(value: Any) -> Any:
    """Normalize whole-number floats to int so Python json.dumps matches JS JSON.stringify."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def canonical_signable_event(envelope: dict[str, Any]) -> dict[str, Any]:
    """Produce the canonical dict signed by HMAC-SHA256 for v2 or legacy v1 events."""
    version = envelope.get("schema_version")
    if isinstance(version, int) and version >= 2:
        src = envelope.get("source")
        if isinstance(src, str):
            src_obj = {"app": src, "device_id": resolve_device_id()}
        elif isinstance(src, dict):
            src_obj = {"app": str(src.get("app", "")), "device_id": str(src.get("device_id", ""))}
        else:
            src_obj = {
                "app": str(getattr(src, "app", "")),
                "device_id": str(getattr(src, "device_id", "")),
            }
        signable: dict[str, Any] = {
            "schema_version": version,
            "id": envelope.get("id", ""),
            "type": envelope.get("type", ""),
            "source": src_obj,
            "timestamp": _norm_ts(envelope.get("timestamp", 0)),
            "data": envelope.get("data", {}),
        }
        if envelope.get("correlation_id") is not None:
            signable["correlation_id"] = envelope["correlation_id"]
        return signable

    # Legacy v1 envelope (5-field layout; coerce EventSource/dict back to app string)
    raw_src = envelope.get("source", "")
    if isinstance(raw_src, dict):
        v1_source = str(raw_src.get("app", ""))
    elif isinstance(raw_src, str):
        v1_source = raw_src
    else:
        v1_source = str(getattr(raw_src, "app", raw_src))
    return {
        "id": envelope.get("id", ""),
        "type": envelope.get("type", ""),
        "source": v1_source,
        "timestamp": envelope.get("timestamp", 0),
        "data": envelope.get("data", {}),
    }


def build_event_envelope_v2(
    event_type: str,
    source_app: str,
    data: dict[str, Any] | None = None,
    secret: str = "",
    *,
    device_id: str | None = None,
    correlation_id: str | None = None,
    event_id: str | None = None,
    timestamp: float | None = None,
) -> dict[str, Any]:
    """Construct and HMAC-sign a v2 event envelope."""
    from ecosystem_auth.tokens import sign_payload

    envelope: dict[str, Any] = {
        "schema_version": 2,
        "id": event_id or generate_ulid(),
        "type": event_type,
        "source": {
            "app": source_app,
            "device_id": device_id or resolve_device_id(),
        },
        "timestamp": _norm_ts(time.time() if timestamp is None else float(timestamp)),
        "data": dict(data or {}),
    }
    if correlation_id is not None:
        envelope["correlation_id"] = correlation_id

    envelope["signature"] = sign_payload(canonical_signable_event(envelope), secret)
    return envelope


def verify_event_envelope(envelope: dict[str, Any], secret: str) -> bool:
    """Verify HMAC-SHA256 signature on either a v2 or legacy v1 event envelope."""
    from ecosystem_auth.tokens import verify_signature

    signature = envelope.get("signature")
    if not signature or not isinstance(signature, str):
        return False
    return verify_signature(canonical_signable_event(envelope), signature, secret)


def canonical_signable_command(envelope: dict[str, Any]) -> dict[str, Any]:
    """Return the canonical dict signed for a v1 CommandEnvelope."""
    out: dict[str, Any] = {}
    for k, v in envelope.items():
        if k == "signature":
            continue
        if k in ("issued_at", "expires_at"):
            out[k] = _norm_ts(v)
        else:
            out[k] = v
    return out


def build_command_envelope(
    command: str,
    action_class: str,
    actor: dict[str, Any],
    target: dict[str, Any],
    secret: str,
    *,
    parameters: dict[str, Any] | None = None,
    ttl_seconds: float = 60.0,
    correlation_id: str | None = None,
    idempotency_key: str | None = None,
    authorization_ref: str | None = None,
    rationale: str | None = None,
    ack_required: bool = True,
    issued_at: float | None = None,
    command_id: str | None = None,
) -> dict[str, Any]:
    """Build and sign a v1 CommandEnvelope enforcing actor, target, expiry, and idempotency."""
    from ecosystem_auth.tokens import sign_payload

    if authorization_ref and str(authorization_ref).startswith(("notify:", "notify.")):
        raise ValueError("A notification identifier is never a valid command authorization_ref")

    cid = command_id or generate_ulid()
    now_ts = time.time() if issued_at is None else float(issued_at)
    envelope: dict[str, Any] = {
        "schema_version": 1,
        "id": cid,
        "command": command,
        "action_class": action_class,
        "actor": dict(actor),
        "target": dict(target),
        "parameters": dict(parameters or {}),
        "issued_at": _norm_ts(now_ts),
        "expires_at": _norm_ts(now_ts + float(ttl_seconds)),
        "correlation_id": correlation_id or cid,
        "idempotency_key": idempotency_key or cid,
        "authorization_ref": authorization_ref,
        "rationale": rationale,
        "ack_required": bool(ack_required),
    }
    envelope["signature"] = sign_payload(canonical_signable_command(envelope), secret)
    assert_valid_schema(envelope, "command-envelope.v1")
    return envelope


def verify_command_envelope(
    envelope: dict[str, Any],
    secret: str,
    *,
    now: float | None = None,
) -> tuple[bool, str]:
    """Verify schema, authorization_ref safety, expiry, and HMAC signature of a CommandEnvelope."""
    from ecosystem_auth.tokens import verify_signature

    errors = validate_against_schema(envelope, "command-envelope.v1")
    if errors:
        return False, f"schema invalid: {errors[0]}"

    auth_ref = envelope.get("authorization_ref")
    if auth_ref and str(auth_ref).startswith(("notify:", "notify.")):
        return False, "notification reference cannot authorize a command"

    current = time.time() if now is None else float(now)
    issued_at = float(envelope["issued_at"])
    expires_at = float(envelope["expires_at"])
    if expires_at <= issued_at:
        return False, "expires_at must be greater than issued_at"
    if current > expires_at:
        return False, "command expired"

    sig = envelope.get("signature", "")
    if not verify_signature(canonical_signable_command(envelope), sig, secret):
        return False, "invalid command signature"

    return True, "ok"


def build_notification_envelope(
    notify_type: str,
    source_app: str,
    severity: str,
    title: str,
    body: str,
    *,
    dedupe_key: str,
    device_id: str | None = None,
    actions: list[dict[str, Any]] | None = None,
    privacy: str = "redacted",
    ttl: str = "24h",
    deep_link: str | None = None,
    secret: str | None = None,
    notification_id: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Build (and optionally sign) a v1 NotificationEnvelope."""
    from ecosystem_auth.tokens import sign_payload

    envelope: dict[str, Any] = {
        "schema_version": 1,
        "type": notify_type,
        "id": notification_id or generate_ulid(),
        "dedupe_key": dedupe_key,
        "source": {
            "app": source_app,
            "device_id": device_id or resolve_device_id(),
        },
        "severity": severity,
        "title": title,
        "body": body,
        "actions": list(actions or []),
        "privacy": privacy,
        "ttl": ttl,
        "deep_link": deep_link,
        "created_at": created_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if secret:
        signable = {k: v for k, v in envelope.items() if k != "signature"}
        envelope["signature"] = sign_payload(signable, secret)
    assert_valid_schema(envelope, "notification-envelope.v1")
    return envelope
