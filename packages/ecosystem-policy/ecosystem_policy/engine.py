"""Blue-team PolicyEngine with Ed25519 verification, Freeze preemption, and device-key scan grants."""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from ecosystem_client.contracts import assert_valid_schema
from ecosystem_client.ulid import generate_ulid

from .crypto import Ed25519PolicySigner
from .models import (
    ACTION_CLASSES,
    ALWAYS_ENFORCED_INVARIANTS,
    POLICY_MODES,
    ActionRequest,
    AutoScanGrant,
    DeviceEnrollment,
    PolicyDecision,
)

logger = logging.getLogger(__name__)


def _iso_utc(ts: float | None = None) -> str:
    dt = datetime.fromtimestamp(time.time() if ts is None else ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso_ts(iso_str: str | None) -> float | None:
    if not iso_str:
        return None
    s = iso_str.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _parse_duration_seconds(raw: str | int | float | None, default: int = 1800) -> int:
    if raw is None:
        return default
    if isinstance(raw, (int, float)):
        return max(1, int(raw))
    s = str(raw).strip().lower()
    if s.endswith("s") and s[:-1].isdigit():
        return int(s[:-1])
    if s.endswith("m") and s[:-1].isdigit():
        return int(s[:-1]) * 60
    if s.endswith("h") and s[:-1].isdigit():
        return int(s[:-1]) * 3600
    if s.endswith("d") and s[:-1].isdigit():
        return int(s[:-1]) * 86400
    if s.isdigit():
        return int(s)
    return default


DEFAULT_POLICY_DICT: dict[str, Any] = {
    "version": 3,
    "defaults": {
        "posture": "blue_team",
        "observe": "allow",
        "investigate": "require_approval",
        "contain": {
            "decision": "allow_and_notify",
            "approval": "async",
            "ttl": "24h",
            "on_deny": "revert",
        },
        "remediate": "require_approval",
        "data_release": "require_approval",
        "system_change": "require_approval",
    },
    "overrides": [
        {
            "name": "incident-remediation",
            "enabled": False,
            "when": {"mode": "incident", "verified_incident": True, "target_authorization_valid": True},
            "allow": ["remediate"],
            "only_actions": ["stop_confirmed_malicious_process"],
            "decision": "allow_and_notify",
            "expires_after": "6h",
        },
        {
            "name": "survival-local-autonomy",
            "enabled": False,
            "when": {"mode": "survival", "target_is_local_device": True},
            "allow": ["system_change"],
            "only_actions": ["switch_model_tier", "enable_power_saver", "start_offline_mesh"],
            "decision": "allow_and_notify",
            "expires_after": "72h",
        },
    ],
    "targets": {
        "external_ip": {
            "passive_actions": ["whois", "passive_dns", "reputation", "lookup_ioc"],
            "active_recon": "deny",
        },
        "unenrolled_lan_device": {
            "investigate": "require_approval",
            "contain": "allow_and_notify",
        },
    },
    "restrictions": {
        "default": "on",
        "active_override": None,
        "always_enforced": list(ALWAYS_ENFORCED_INVARIANTS),
    },
    "kill_switch": {
        "initiators": ["authorized_operator", "enrolled_freeze_controller"],
        "resume_requires": "authenticated_operator",
    },
}


class PolicyEngine:
    """Authoritative policy engine shared across the Hub and standalone ecosystem applications."""

    def __init__(
        self,
        policy: dict[str, Any] | None = None,
        *,
        signer: Ed25519PolicySigner | None = None,
        authority: str = "standalone_local",
        persistence_path: str | Path | None = None,
    ):
        self._lock = threading.RLock()
        self.signer = signer or Ed25519PolicySigner.generate()
        self._persistence_path = Path(persistence_path) if persistence_path else None
        self._policy = copy.deepcopy(policy or DEFAULT_POLICY_DICT)
        self._policy_version = int(self._policy.get("version", 3))
        self._mode = "normal"
        self._pre_freeze_mode = "normal"
        self._frozen = False
        self._freeze_info: dict[str, Any] | None = None
        self._active_override: dict[str, Any] | None = None
        self._authority = authority if authority in ("hub_synced", "standalone_local", "lease_expired") else "standalone_local"
        self._updated_at = _iso_utc()

        self._enrolled_devices: dict[str, DeviceEnrollment] = {}
        self._auto_scan_grants: dict[str, AutoScanGrant] = {}
        self._authorized_external_targets: set[str] = set()
        self._verified_incidents: set[str] = set()
        self._audit_chain: list[dict[str, Any]] = []
        self._last_audit_hash = "0" * 64

        if self._persistence_path and self._persistence_path.is_file():
            self._load_persisted_state()

    @classmethod
    def load(
        cls,
        policy_path: str | Path | None = None,
        *,
        signer: Ed25519PolicySigner | None = None,
        trusted_public_b64: str | None = None,
        authority: str = "standalone_local",
        state_path: str | Path | None = None,
    ) -> "PolicyEngine":
        """Load a signed or local `policy.yaml`; fail-closed to conservative defaults if tampered."""
        sig_mgr = signer or Ed25519PolicySigner.load_or_create()
        doc = copy.deepcopy(DEFAULT_POLICY_DICT)
        if policy_path and Path(policy_path).is_file():
            try:
                loaded = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    if "signature" in loaded:
                        if sig_mgr.verify_dict(loaded, trusted_public_b64=trusted_public_b64):
                            doc = loaded
                        else:
                            logger.error("Tampered policy.yaml signature at %s — failing closed to blue-team defaults", policy_path)
                    else:
                        doc = loaded
            except Exception as exc:
                logger.error("Failed reading %s (%r) — failing closed to blue-team defaults", policy_path, exc)
        return cls(doc, signer=sig_mgr, authority=authority, persistence_path=state_path)

    # ---- Persistence --------------------------------------------------------

    def _persist_state(self) -> None:
        if not self._persistence_path:
            return
        self._persistence_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "policy_version": self._policy_version,
            "mode": self._mode,
            "pre_freeze_mode": self._pre_freeze_mode,
            "frozen": self._frozen,
            "freeze_info": self._freeze_info,
            "active_override": self._active_override,
            "authority": self._authority,
            "updated_at": self._updated_at,
            "enrolled_devices": {k: v.to_dict() for k, v in self._enrolled_devices.items()},
            "auto_scan_grants": {k: v.to_dict() for k, v in self._auto_scan_grants.items()},
            "authorized_external_targets": sorted(self._authorized_external_targets),
            "verified_incidents": sorted(self._verified_incidents),
        }
        tmp = self._persistence_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self._persistence_path)

    def _load_persisted_state(self) -> None:
        if not self._persistence_path or not self._persistence_path.is_file():
            return
        try:
            data = json.loads(self._persistence_path.read_text(encoding="utf-8"))
            self._policy_version = int(data.get("policy_version", self._policy_version))
            self._mode = data.get("mode", "normal")
            self._pre_freeze_mode = data.get("pre_freeze_mode", "normal")
            self._frozen = bool(data.get("frozen", False))
            self._freeze_info = data.get("freeze_info")
            # Fail-closed on restart for active_override unless signature is valid and unexpired
            raw_ov = data.get("active_override")
            if isinstance(raw_ov, dict) and self.signer.verify_dict(raw_ov):
                self._active_override = raw_ov
            self._enrolled_devices = {
                k: DeviceEnrollment(**v) for k, v in (data.get("enrolled_devices") or {}).items()
            }
            self._auto_scan_grants = {
                k: AutoScanGrant(**v) for k, v in (data.get("auto_scan_grants") or {}).items()
            }
            self._authorized_external_targets = set(data.get("authorized_external_targets") or [])
            self._verified_incidents = set(data.get("verified_incidents") or [])
        except Exception as exc:
            logger.warning("Could not restore policy state from %s (%r); using conservative defaults", self._persistence_path, exc)

    # ---- Properties & Audit -------------------------------------------------

    @property
    def policy_version(self) -> int:
        return self._policy_version

    @property
    def mode(self) -> str:
        return "freeze" if self._frozen else self._mode

    @property
    def frozen(self) -> bool:
        return self._frozen

    @property
    def authority(self) -> str:
        return self._authority

    def set_authority(self, authority: str) -> None:
        if authority not in ("hub_synced", "standalone_local", "lease_expired"):
            raise ValueError(f"Invalid policy authority: {authority}")
        with self._lock:
            self._authority = authority
            self._updated_at = _iso_utc()
            self._persist_state()

    def _record_audit(self, event: str, details: dict[str, Any]) -> str:
        ts = _iso_utc()
        entry = {
            "ts": ts,
            "event": event,
            "policy_version": self._policy_version,
            "prev_hash": self._last_audit_hash,
            "details": details,
        }
        digest = hashlib.sha256(
            json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
        entry["hash"] = digest
        self._last_audit_hash = digest
        self._audit_chain.append(entry)
        if len(self._audit_chain) > 1000:
            self._audit_chain = self._audit_chain[-1000:]
        return digest

    def audit_log(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._audit_chain[-limit:])

    # ---- Enrollment & Auto-Scan Grants --------------------------------------

    def enroll_device(
        self,
        device_id: str,
        public_key_fingerprint: str,
        *,
        owner: str,
        aup_version: str = "1.0",
        scopes: list[str] | None = None,
        now: float | None = None,
    ) -> DeviceEnrollment:
        with self._lock:
            rec = DeviceEnrollment(
                device_id=device_id,
                public_key_fingerprint=public_key_fingerprint,
                owner=owner,
                aup_version=aup_version,
                scopes=list(scopes or ["system_info", "zbt_scan"]),
                enrolled_at=time.time() if now is None else now,
                revoked=False,
            )
            self._enrolled_devices[device_id] = rec
            self._record_audit("device.enrolled", rec.to_dict())
            self._persist_state()
            return rec

    def get_enrolled_device(self, device_id: str) -> DeviceEnrollment | None:
        with self._lock:
            return self._enrolled_devices.get(device_id)

    def list_enrolled_devices(self) -> list[dict[str, Any]]:
        with self._lock:
            return [d.to_dict() for d in self._enrolled_devices.values()]

    def designate_auto_scan(
        self,
        device_id: str,
        *,
        profiles: list[str] | None = None,
        scopes: list[str] | None = None,
        initiators: list[str] | None = None,
        authorization_ref: str = "owner-explicit-designation",
        expires_at: str | None = None,
    ) -> AutoScanGrant:
        """Bind an `auto_scan` grant to an enrolled device's cryptographic fingerprint."""
        with self._lock:
            enrolled = self._enrolled_devices.get(device_id)
            if enrolled is None or enrolled.revoked:
                raise PermissionError(
                    f"Device '{device_id}' must complete AUP enrollment before automatic scan designation"
                )
            grant = AutoScanGrant(
                device_id=device_id,
                public_key_fingerprint=enrolled.public_key_fingerprint,
                profiles=list(profiles or ["quick"]),
                scopes=list(scopes or ["system_info", "zbt_scan"]),
                initiators=list(initiators or ["*"]),
                authorization_ref=authorization_ref,
                expires_at=expires_at,
                revoked=False,
            )
            self._auto_scan_grants[device_id] = grant
            self._policy_version += 1
            self._updated_at = _iso_utc()
            self._record_audit("auto_scan.designated", grant.to_dict())
            self._persist_state()
            return grant

    def revoke_auto_scan(self, device_id: str, *, reason: str = "owner_revoked") -> bool:
        with self._lock:
            grant = self._auto_scan_grants.get(device_id)
            if grant is None or grant.revoked:
                return False
            grant.revoked = True
            self._policy_version += 1
            self._updated_at = _iso_utc()
            self._record_audit("auto_scan.revoked", {"device_id": device_id, "reason": reason})
            self._persist_state()
            return True

    def list_auto_scan_grants(self) -> list[dict[str, Any]]:
        with self._lock:
            return [g.to_dict() for g in self._auto_scan_grants.values()]

    def has_valid_auto_scan_grant(
        self,
        device_id: str,
        *,
        profile: str = "quick",
        initiator: str = "*",
        public_key_fingerprint: str | None = None,
        now: float | None = None,
    ) -> tuple[bool, str]:
        ts = time.time() if now is None else now
        with self._lock:
            enrolled = self._enrolled_devices.get(device_id)
            if enrolled is None or enrolled.revoked:
                return False, f"Device '{device_id}' is not enrolled or AUP consent was revoked"
            # Fail closed on the cryptographic binding: a device-key fingerprint
            # MUST be presented and match the enrolled key. Omitting it previously
            # skipped this check entirely, so a caller could claim an auto_scan
            # grant by device_id alone — which is spoofable via DHCP / IP reuse,
            # exactly what the binding exists to prevent. No fingerprint → no grant.
            if not public_key_fingerprint:
                return False, (
                    f"Device '{device_id}' auto_scan requires a cryptographic device-key "
                    "fingerprint; none was supplied"
                )
            if public_key_fingerprint != enrolled.public_key_fingerprint:
                return False, "Device cryptographic key mismatch (DHCP/IP reuse cannot transfer scan permission)"
            grant = self._auto_scan_grants.get(device_id)
            if grant is None:
                return False, f"Device '{device_id}' has no automatic-scan designation"
            if grant.revoked:
                return False, f"Automatic-scan grant for '{device_id}' was revoked"
            if grant.public_key_fingerprint != enrolled.public_key_fingerprint:
                return False, "Grant key fingerprint mismatch"
            exp_ts = _parse_iso_ts(grant.expires_at)
            if exp_ts is not None and ts >= exp_ts:
                return False, f"Automatic-scan grant for '{device_id}' expired at {grant.expires_at}"
            if profile not in grant.profiles:
                return False, f"Scan profile '{profile}' is not permitted by grant (allowed: {grant.profiles})"
            app_name = initiator.split("/", 1)[0]
            if "*" not in grant.initiators and initiator not in grant.initiators and app_name not in grant.initiators:
                return False, f"Initiator '{initiator}' is not permitted by grant"
            return True, f"Valid auto_scan grant ({grant.authorization_ref})"

    # ---- Freeze, Mode & Signed Restrictions: Off Overrides ------------------

    def freeze(
        self,
        *,
        initiated_by: str,
        reason: str = "Operator requested emergency freeze",
        channel: str | None = None,
        acknowledged_devices: list[str] | None = None,
        pending_devices: list[str] | None = None,
        unreachable_devices: list[str] | None = None,
    ) -> dict[str, Any]:
        """Engage emergency Freeze immediately. Preempts `Restrictions: Off`."""
        with self._lock:
            if not self._frozen:
                self._pre_freeze_mode = self._mode
            self._frozen = True
            self._policy_version += 1
            now_iso = _iso_utc()
            self._updated_at = now_iso
            self._freeze_info = {
                "initiated_by": initiated_by,
                "channel": channel,
                "reason": reason,
                "since": now_iso,
                "acknowledged_devices": list(acknowledged_devices or []),
                "pending_devices": list(pending_devices or []),
                "unreachable_devices": list(unreachable_devices or []),
            }
            self._record_audit("policy.freeze", dict(self._freeze_info))
            self._persist_state()
            return self.export_state()

    def resume(self, *, operator_id: str, auth_method: str, reason: str = "Operator resumed normal operation") -> dict[str, Any]:
        """Clear Freeze; requires authenticated step-up operator (`totp` | `passkey` | `device_key`)."""
        if auth_method not in ("totp", "passkey", "device_key"):
            raise PermissionError("Resuming from Freeze requires authenticated operator step-up (totp/passkey/device_key)")
        with self._lock:
            self._frozen = False
            self._mode = self._pre_freeze_mode if self._pre_freeze_mode != "freeze" else "normal"
            self._freeze_info = None
            self._policy_version += 1
            self._updated_at = _iso_utc()
            self._record_audit(
                "policy.resume",
                {"operator_id": operator_id, "auth_method": auth_method, "reason": reason},
            )
            self._persist_state()
            return self.export_state()

    def set_mode(
        self,
        mode: str,
        *,
        operator_id: str,
        auth_method: str,
        verified_incident_id: str | None = None,
    ) -> dict[str, Any]:
        if mode not in POLICY_MODES:
            raise ValueError(f"Unsupported policy mode: {mode}")
        if mode == "freeze":
            return self.freeze(initiated_by=operator_id, reason="Mode switched to freeze")
        if auth_method not in ("totp", "passkey", "device_key"):
            raise PermissionError("Changing policy mode requires operator step-up authentication")
        with self._lock:
            self._mode = mode
            if verified_incident_id:
                self._verified_incidents.add(verified_incident_id)
            self._policy_version += 1
            self._updated_at = _iso_utc()
            self._record_audit(
                "policy.mode_changed",
                {"mode": mode, "operator_id": operator_id, "auth_method": auth_method},
            )
            self._persist_state()
            return self.export_state()

    def enable_named_override(self, name: str, *, enabled: bool, operator_id: str, auth_method: str) -> bool:
        if auth_method not in ("totp", "passkey", "device_key"):
            raise PermissionError("Enabling situational playbook overrides requires step-up authentication")
        with self._lock:
            for ov in self._policy.get("overrides", []):
                if ov.get("name") == name:
                    ov["enabled"] = bool(enabled)
                    self._policy_version += 1
                    self._updated_at = _iso_utc()
                    self._record_audit(
                        "policy.named_override_updated",
                        {"name": name, "enabled": bool(enabled), "operator_id": operator_id},
                    )
                    self._persist_state()
                    return True
            return False

    def activate_restrictions_off(
        self,
        *,
        issued_by: str,
        auth_method: str,
        reason: str,
        apps: list[str],
        devices: list[str],
        action_classes: list[str],
        duration_seconds: int | None = 1800,
        until_revoked: bool = False,
        applied_devices: list[str] | None = None,
        pending_devices: list[str] | None = None,
        unreachable_devices: list[str] | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Create and Ed25519-sign a timed, scoped `Restrictions: Off` override grant."""
        if auth_method not in ("totp", "passkey", "device_key"):
            raise PermissionError("Turning policy restrictions Off requires step-up authentication")
        if not reason or not reason.strip():
            raise ValueError("An explicit operator reason is required for Restrictions: Off")
        if not apps or not devices or not action_classes:
            raise ValueError("Explicit apps, devices, and action_classes scope is required")
        invalid_classes = [c for c in action_classes if c not in ACTION_CLASSES and c != "*"]
        if invalid_classes:
            raise ValueError(f"Invalid action_classes in override scope: {invalid_classes}")

        ts = time.time() if now is None else now
        issued_iso = _iso_utc(ts)
        if until_revoked:
            expires_iso = None
        else:
            dur = max(60, int(duration_seconds or 1800))
            expires_iso = _iso_utc(ts + dur)

        grant_unsigned = {
            "grant_id": generate_ulid(int(ts * 1000)),
            "issued_by": issued_by,
            "reason": reason.strip(),
            "scope": {
                "apps": list(apps),
                "devices": list(devices),
                "action_classes": list(action_classes),
            },
            "bypassed": [
                "configurable_action_denies",
                "per_action_approval_gates",
            ],
            "issued_at": issued_iso,
            "issued_ts": ts,
            "expires_at": expires_iso,
            "applied_devices": list(applied_devices or []),
            "pending_devices": list(pending_devices or []),
            "unreachable_devices": list(unreachable_devices or []),
        }
        signed_grant = self.signer.sign_dict(grant_unsigned)
        with self._lock:
            self._active_override = signed_grant
            self._policy_version += 1
            self._updated_at = issued_iso
            self._record_audit("policy.restrictions_off_activated", grant_unsigned)
            self._persist_state()
            return self.export_state(now=ts)

    def restore_restrictions_on(self, *, actor: str = "operator", reason: str = "Restored conservative policy") -> dict[str, Any]:
        with self._lock:
            prev_id = self._active_override.get("grant_id") if self._active_override else None
            self._active_override = None
            self._policy_version += 1
            self._updated_at = _iso_utc()
            self._record_audit("policy.restrictions_on_restored", {"actor": actor, "prev_grant_id": prev_id, "reason": reason})
            self._persist_state()
            return self.export_state()

    def _effective_override(self, now: float | None = None) -> dict[str, Any] | None:
        ts = time.time() if now is None else now
        ov = self._active_override
        if ov is None:
            return None
        if self._authority == "lease_expired":
            return None
        if not self.signer.verify_dict(ov):
            logger.error("Active override grant failed Ed25519 verification — revoking immediately")
            self._active_override = None
            return None
        exp_ts = _parse_iso_ts(ov.get("expires_at"))
        if exp_ts is not None and ts >= exp_ts:
            self._record_audit("policy.restrictions_off_expired", {"grant_id": ov.get("grant_id")})
            self._active_override = None
            self._policy_version += 1
            self._updated_at = _iso_utc(ts)
            self._persist_state()
            return None
        return ov

    # ---- Export Validated `policy-state.v1` ---------------------------------

    def export_state(self, *, now: float | None = None) -> dict[str, Any]:
        """Build and validate a `policy-state.v1` JSON object for `<ecosystem-policy-bar>`."""
        with self._lock:
            ov = self._effective_override(now=now)
            public_ov: dict[str, Any] | None = None
            if ov is not None:
                public_ov = {
                    "grant_id": ov["grant_id"],
                    "issued_by": ov["issued_by"],
                    "reason": ov["reason"],
                    "scope": ov["scope"],
                    "bypassed": ov["bypassed"],
                    "issued_at": ov["issued_at"],
                    "expires_at": ov.get("expires_at"),
                    "applied_devices": ov.get("applied_devices", []),
                    "pending_devices": ov.get("pending_devices", []),
                    "unreachable_devices": ov.get("unreachable_devices", []),
                }

            state = {
                "schema_version": 1,
                "policy_version": self._policy_version,
                "mode": "freeze" if self._frozen else self._mode,
                "restrictions": "off_scoped" if public_ov is not None else "on",
                "frozen": self._frozen,
                "freeze_info": copy.deepcopy(self._freeze_info) if self._frozen else None,
                "active_override": public_ov,
                "always_enforced": list(ALWAYS_ENFORCED_INVARIANTS),
                "authority": self._authority,
                "updated_at": self._updated_at,
            }
            assert_valid_schema(state, "policy-state.v1")
            return state

    # ---- Core Policy Evaluation (`decide()`) --------------------------------

    def authorize_external_target(self, target_host_or_ip: str) -> None:
        with self._lock:
            self._authorized_external_targets.add(target_host_or_ip)
            self._persist_state()

    def decide(self, req: ActionRequest, *, now: float | None = None) -> PolicyDecision:
        """Evaluate an `ActionRequest` deterministically against policy, freeze, grants, and invariants."""
        ts = time.time() if now is None else now
        with self._lock:
            ov = self._effective_override(now=ts)
            restrictions_str = "off_scoped" if ov is not None else "on"
            eff_mode = "freeze" if self._frozen else self._mode

            def _finalize(
                result: str,
                reason: str,
                *,
                async_approval: bool = False,
                ttl_seconds: int | None = None,
                on_deny: str = "abort",
                revert_plan: dict[str, Any] | None = None,
                grant_id: str | None = None,
                notice: str | None = None,
            ) -> PolicyDecision:
                deadline = _iso_utc(ts + ttl_seconds) if ttl_seconds else None
                audit_hash = self._record_audit(
                    "policy.decision",
                    {
                        "actor": req.actor,
                        "model": req.model,
                        "action": req.action,
                        "action_class": req.action_class,
                        "target": req.target,
                        "result": result,
                        "reason": reason,
                        "grant_id": grant_id,
                    },
                )
                return PolicyDecision(
                    result=result,
                    reason=reason,
                    policy_version=self._policy_version,
                    mode=eff_mode,
                    restrictions=restrictions_str,
                    frozen=self._frozen,
                    async_approval=async_approval,
                    ttl_seconds=ttl_seconds,
                    on_deny=on_deny,
                    revert_plan=revert_plan,
                    grant_id=grant_id,
                    notice=notice,
                    deadline=deadline,
                    audit_hash=audit_hash,
                )

            # 1. Always-enforced: command_authentication & input_validation
            if not req.authenticated:
                return _finalize("deny", "Unauthenticated command rejected (always_enforced: command_authentication)")
            if not req.action or req.action_class not in ACTION_CLASSES:
                return _finalize("deny", f"Invalid action or action_class '{req.action_class}' (always_enforced: input_validation)")

            # 2. Always-enforced: Freeze preempts everything except passive `observe`
            if self._frozen:
                if req.action_class == "observe":
                    return _finalize("allow", "Passive observation permitted while Freeze is active")
                return _finalize(
                    "deny",
                    "Ecosystem Freeze is active; all new mutating and scanning actions are suspended (always_enforced: freeze)",
                )

            # 3. Maintenance mode pauses scheduled scans and automations
            if self._mode == "maintenance" and req.action_class != "observe":
                if req.context.get("trigger") in ("schedule", "automation"):
                    return _finalize("deny", "Maintenance mode active; scheduled scans and automations are paused")

            # 4. Always-enforced: External target boundary (Restrictions: Off NEVER authorizes external recon)
            ext_target = req.target.get("external_ip") or (
                req.target.get("host") if req.target.get("is_external") or req.target.get("kind") == "external_ip" else None
            )
            if ext_target or req.target.get("kind") == "external_ip" or req.target.get("is_external"):
                passive_allowed = set(
                    self._policy.get("targets", {}).get("external_ip", {}).get(
                        "passive_actions", ["whois", "passive_dns", "reputation", "lookup_ioc"]
                    )
                )
                if req.action_class == "observe" or req.action in passive_allowed:
                    res = "allow" if req.action_class == "observe" else "allow_and_notify"
                    return _finalize(res, f"Passive external lookup '{req.action}' permitted", notice=f"{req.actor}: {req.action}")
                if not ext_target or str(ext_target) not in self._authorized_external_targets:
                    return _finalize(
                        "deny",
                        "External system lacks independent target authorization scope (always_enforced: target_authorization_and_consent)",
                    )

            # 5. Always-enforced: Cloud budget & sensitive data-release boundary
            dest = str(req.target.get("destination") or "").lower()
            classification = str(req.target.get("classification") or req.context.get("classification") or "").lower()
            if req.context.get("budget_exceeded"):
                return _finalize(
                    "deny",
                    "Cloud compute budget cap exceeded (always_enforced: cloud_budget_and_data_boundary)",
                )
            if classification == "sensitive" and dest in ("cloud", "cloud_gpu", "external"):
                if not req.context.get("approved_data_release_id"):
                    return _finalize(
                        "require_approval",
                        "Sensitive data egress to cloud/external requires explicit data_release approval (always_enforced: cloud_budget_and_data_boundary)",
                    )

            # 6. Always-enforced: Endpoint scan target consent & device-key auto_scan grants
            device_id = req.target.get("device_id")
            is_scan_action = req.action in ("zbt_scan", "device_scan", "scan.request", "endpoint_scan")
            if is_scan_action and device_id:
                enrolled = self._enrolled_devices.get(str(device_id))
                if enrolled is not None and enrolled.revoked:
                    return _finalize(
                        "deny",
                        f"AUP consent for device '{device_id}' was revoked (always_enforced: target_authorization_and_consent)",
                    )
                supplied_fp = req.target.get("public_key_fingerprint")
                if enrolled is not None and supplied_fp and supplied_fp != enrolled.public_key_fingerprint:
                    return _finalize(
                        "deny",
                        f"Cryptographic device-key mismatch for '{device_id}'; DHCP IP reuse does not transfer scan consent",
                    )
                if enrolled is None:
                    # Unenrolled LAN devices NEVER get bypassed by Restrictions: Off
                    return _finalize(
                        "require_approval",
                        f"Device '{device_id}' is unenrolled; network membership alone grants no scan permission",
                    )
                ok_grant, grant_msg = self.has_valid_auto_scan_grant(
                    str(device_id),
                    profile=str(req.context.get("profile") or "quick"),
                    initiator=req.actor,
                    public_key_fingerprint=supplied_fp,
                    now=ts,
                )
                if ok_grant:
                    return _finalize(
                        "allow_and_notify",
                        grant_msg,
                        notice=f"Authorized scan ({req.context.get('profile', 'quick')}) on {device_id}",
                    )

            # 7. Signed Scoped `Restrictions: Off` Override Grant (cannot bypass steps 1-6!)
            if ov is not None:
                scope = ov.get("scope", {})
                apps_scope = scope.get("apps", [])
                devs_scope = scope.get("devices", [])
                cls_scope = scope.get("action_classes", [])

                app_ok = "*" in apps_scope or req.app_name in apps_scope or req.actor in apps_scope
                cls_ok = "*" in cls_scope or req.action_class in cls_scope
                dev_ok = False
                if not device_id:
                    dev_ok = True
                elif str(device_id) in devs_scope:
                    enrolled = self._enrolled_devices.get(str(device_id))
                    dev_ok = enrolled is not None and not enrolled.revoked
                elif "*" in devs_scope:
                    # Newly joined devices do NOT inherit a permissive wildcard grant!
                    enrolled = self._enrolled_devices.get(str(device_id))
                    issued_ts = float(ov.get("issued_ts", 0.0))
                    if enrolled is not None and not enrolled.revoked and enrolled.enrolled_at <= issued_ts:
                        dev_ok = True

                if app_ok and cls_ok and dev_ok:
                    return _finalize(
                        "allow_and_notify",
                        f"Permitted by signed scoped Restrictions: Off grant {ov['grant_id']}",
                        grant_id=ov["grant_id"],
                        notice=f"[Override {ov['grant_id']}] {req.actor} -> {req.action}",
                    )

            # 8. Named Situational Overrides (`incident` / `survival`) — must be explicitly operator-enabled
            for named in self._policy.get("overrides", []):
                if not named.get("enabled"):
                    continue
                when = named.get("when", {})
                if when.get("mode") and when["mode"] != self._mode:
                    continue
                if req.action_class not in (named.get("allow") or []):
                    continue
                if req.action not in (named.get("only_actions") or []):
                    continue
                if when.get("verified_incident"):
                    inc_id = str(req.context.get("incident_id") or "")
                    if not inc_id or inc_id not in self._verified_incidents:
                        continue
                if when.get("target_authorization_valid") and device_id:
                    enr = self._enrolled_devices.get(str(device_id))
                    if enr is None or enr.revoked:
                        continue
                if when.get("target_is_local_device") and not req.target.get("is_local_device"):
                    continue
                decision = str(named.get("decision", "allow_and_notify"))
                return _finalize(
                    decision,
                    f"Permitted by operator-enabled situational override '{named['name']}'",
                    notice=f"[{named['name']}] {req.actor} -> {req.action}",
                )

            # 9. Blue-Team Defaults
            if req.action_class == "observe":
                return _finalize("allow", "Blue-team default: passive observation allowed")

            if req.action_class == "contain":
                contain_cfg = self._policy.get("defaults", {}).get("contain", {})
                ttl_sec = _parse_duration_seconds(contain_cfg.get("ttl", "24h"), default=86400)
                on_deny = str(contain_cfg.get("on_deny", "revert"))
                return _finalize(
                    "allow_and_notify",
                    "Blue-team default: protective containment allowed provisionally with async approval & TTL revert",
                    async_approval=True,
                    ttl_seconds=ttl_sec,
                    on_deny=on_deny,
                    revert_plan={"action": f"revert_{req.action}", "target": copy.deepcopy(req.target)},
                    notice=f"Provisional containment '{req.action}' active ({ttl_sec}s lease); approval requested",
                )

            return _finalize(
                "require_approval",
                f"Blue-team default: action_class '{req.action_class}' ('{req.action}') requires authenticated operator approval",
            )
