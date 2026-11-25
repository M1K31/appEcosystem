"""Zero-Breach-Toolkit (ZBT) Scan Runner for appEcosystem.

Wraps zero-breach-toolkit.py with:
- Dynamic schema and exit code inspection via `--describe`
- Blue-team PolicyEngine gating before execution
- Single-flight per-device execution locking
- Sensitive data retention boundary: full reports encrypted at rest (0600 key);
  redacted share.json summaries emitted onto the mesh event bus
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet

logger = logging.getLogger("ecosystem.scan_agent")


def _iso_utc(ts: float | None = None) -> str:
    from datetime import datetime, timezone
    dt = datetime.fromtimestamp(ts, tz=timezone.utc) if ts is not None else datetime.now(timezone.utc)
    return dt.isoformat()


def _generate_scan_id() -> str:
    try:
        from ecosystem_schemas.identifiers import generate_ulid
        return generate_ulid()
    except Exception:
        import uuid
        return uuid.uuid4().hex


def _validate_phone_folder(raw: str) -> tuple[str | None, str | None]:
    """Confine a requested `--phone` folder to an operator-configured allowlist.

    `phone_folder` flows straight to the ZBT subprocess, so an unconstrained
    value lets an authenticated caller point a scan at any directory on the
    host (``/``, another user's home, mounted volumes). We fail closed:

    - scanning is disabled unless ``ECOSYSTEM_PHONE_SCAN_BASE`` lists one or
      more allowed base directories (``os.pathsep``-separated);
    - the requested path is resolved with symlinks followed and existence
      required, then must sit inside one of those bases.

    Returns ``(resolved_path, None)`` when allowed, or ``(None, error)``.
    """
    bases_env = os.environ.get("ECOSYSTEM_PHONE_SCAN_BASE", "").strip()
    if not bases_env:
        return None, (
            "phone_folder scanning is disabled: set ECOSYSTEM_PHONE_SCAN_BASE to one or "
            "more allowed base directories (os.pathsep-separated) to enable it"
        )
    try:
        target = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        return None, f"phone_folder path could not be resolved: {exc!r}"
    if not target.is_dir():
        return None, f"phone_folder '{raw}' is not a directory"
    for base in bases_env.split(os.pathsep):
        base = base.strip()
        if not base:
            continue
        try:
            base_resolved = Path(base).expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if target == base_resolved or base_resolved in target.parents:
            return str(target), None
    return None, f"phone_folder '{raw}' is outside the allowed ECOSYSTEM_PHONE_SCAN_BASE roots"


def list_allowed_phone_folders() -> dict[str, Any]:
    """Return allowed phone-backup folders under ECOSYSTEM_PHONE_SCAN_BASE.

    Fails closed: returns ``enabled=False`` and an empty folder list when
    ``ECOSYSTEM_PHONE_SCAN_BASE`` is unset or points to no existing directories.
    Symlinks whose resolved target escapes all configured roots are excluded.
    """
    bases_env = os.environ.get("ECOSYSTEM_PHONE_SCAN_BASE", "").strip()
    if not bases_env:
        return {"enabled": False, "bases": [], "folders": []}
    resolved_bases: list[Path] = []
    bases: list[str] = []
    for raw_base in bases_env.split(os.pathsep):
        raw_base = raw_base.strip()
        if not raw_base:
            continue
        try:
            base_resolved = Path(raw_base).expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not base_resolved.is_dir():
            continue
        base_str = str(base_resolved)
        if base_str not in bases:
            bases.append(base_str)
            resolved_bases.append(base_resolved)

    folders: list[dict[str, str]] = []
    seen: set[str] = set()
    for base_resolved in resolved_bases:
        try:
            for child in sorted(base_resolved.iterdir()):
                if not child.is_dir():
                    continue
                try:
                    child_resolved = child.resolve(strict=True)
                except (OSError, RuntimeError):
                    continue
                if not any(
                    child_resolved == root or root in child_resolved.parents
                    for root in resolved_bases
                ):
                    continue
                child_str = str(child_resolved)
                if child_str not in seen:
                    seen.add(child_str)
                    folders.append({"name": child.name, "path": child_str})
        except OSError:
            continue
    return {"enabled": bool(bases), "bases": bases, "folders": folders}


@dataclass
class ZbtMetadata:
    schema_version: str = "unknown"
    tool_name: str = "zero-breach-toolkit"
    tool_version: str = "unknown"
    exit_codes: dict[str, str] = field(default_factory=dict)
    instructions_for_assistants: list[str] = field(default_factory=list)
    untrusted_fields: list[str] = field(default_factory=list)

    @classmethod
    def from_describe_dict(cls, data: dict[str, Any]) -> "ZbtMetadata":
        tool_info = data.get("tool", {})
        ct = data.get("content_trust", {})
        return cls(
            schema_version=str(data.get("schema_version", "unknown")),
            tool_name=str(tool_info.get("name", "zero-breach-toolkit")),
            tool_version=str(tool_info.get("version", "unknown")),
            exit_codes={str(k): str(v) for k, v in (data.get("exit_codes") or {}).items()},
            instructions_for_assistants=list(data.get("instructions_for_assistants") or []),
            untrusted_fields=list(ct.get("untrusted_fields") or []),
        )

    def map_exit_code(self, exit_code: int) -> str:
        code_str = str(exit_code)
        desc = self.exit_codes.get(code_str, "").lower()
        if exit_code == 0 or ("no actionable indicator matches were found" in desc and "every applicable check" in desc):
            return "clean"
        if exit_code == 2 or ("matches beyond saved references were found" in desc):
            return "findings"
        if exit_code == 3 or ("incomplete" in desc or "gaps" in desc):
            return "gaps"
        if exit_code == 4 or ("aborted" in desc or "left the start menu" in desc):
            return "aborted"
        if exit_code == 1 or ("setup or output error" in desc or "error" in desc):
            return "error"
        return "unknown"

    def map_wp6_outcome(self, exit_code: int) -> str:
        """Map ZBT exit code to canonical WP6 outcome: clean | findings | partial | unknown."""
        raw = self.map_exit_code(exit_code)
        if raw in ("clean", "findings"):
            return raw
        if raw in ("gaps", "aborted"):
            return "partial"
        return "unknown"


class ScanReportEncryptor:
    """Manages encryption of sensitive full forensic reports at rest."""

    def __init__(self, key_path: Path):
        self.key_path = key_path
        self._key = self._load_or_create_key()
        self._fernet = Fernet(self._key)

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            return self.key_path.read_bytes().strip()
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.key_path.parent, 0o700)
        except Exception:
            pass
        key = Fernet.generate_key()
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(str(self.key_path), flags, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        return key

    def encrypt_bytes(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt_bytes(self, token: bytes) -> bytes:
        return self._fernet.decrypt(token)


@dataclass
class ScanRequest:
    scan_id: str = field(default_factory=_generate_scan_id)
    device_id: str = "local"
    public_key_fingerprint: str | None = None
    profile: str = "quick"  # quick | full | standard
    offline: bool = False
    initiator: str = "ecosystem-scan"
    trigger: str = "on_demand"  # on_demand | schedule | automation | baseline | command_dispatch
    phone_folder: str | None = None
    authorization_ref: str | None = None


@dataclass
class ScanResult:
    scan_id: str
    device_id: str
    status: str  # clean | findings | gaps | error | aborted | deferred | denied
    exit_code: int
    exit_description: str
    share: dict[str, Any]
    report_ref: str
    started_at: str
    completed_at: str
    duration_seconds: float
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ScanRunner:
    """Production runner executing ZBT with policy checks, locking, and report encryption."""

    def __init__(
        self,
        zbt_path: str | Path | None = None,
        data_dir: str | Path | None = None,
        policy_engine: Any = None,
        event_bus: Any = None,
        keystore_dir: str | Path | None = None,
        notification_router: Any = None,
        extension_registry: Any = None,
    ):
        from .extensions import ScannerExtensionRegistry

        self.data_dir = Path(data_dir or Path.home() / ".local" / "share" / "ecosystem")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.scans_dir = self.data_dir / "scans"
        self.scans_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.scans_dir, 0o700)
        except Exception:
            pass

        ks_dir = Path(keystore_dir or self.data_dir / "keystore")
        ks_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(ks_dir, 0o700)
        except Exception:
            pass
        self.encryptor = ScanReportEncryptor(ks_dir / "scan_enc.key")

        self.policy_engine = policy_engine
        self.event_bus = event_bus
        self.notification_router = notification_router
        self.extension_registry = extension_registry if extension_registry is not None else ScannerExtensionRegistry()
        self.zbt_script = self._resolve_zbt_path(zbt_path)
        self._device_locks: dict[str, asyncio.Lock] = {}
        self._metadata: ZbtMetadata | None = None
        self._results_history: dict[str, ScanResult] = {}
        self._load_history()

    def _history_file(self) -> Path:
        return self.data_dir / "scan_history.json"

    def _load_history(self) -> None:
        hf = self._history_file()
        if hf.is_file():
            try:
                data = json.loads(hf.read_text(encoding="utf-8"))
                for sid, rdict in data.items():
                    self._results_history[sid] = ScanResult(**rdict)
            except Exception as exc:
                logger.warning("Failed loading scan history from %s: %r", hf, exc)

    def _persist_history(self) -> None:
        hf = self._history_file()
        try:
            data = {sid: res.to_dict() for sid, res in self._results_history.items()}
            tmp = hf.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            os.replace(tmp, hf)
        except Exception as exc:
            logger.warning("Failed writing scan history to %s: %r", hf, exc)

    def _resolve_zbt_path(self, override: str | Path | None) -> Path | None:
        if override:
            p = Path(override)
            if p.is_file():
                return p.resolve()
            if p.is_dir() and (p / "scan" / "zero-breach-toolkit.py").is_file():
                return (p / "scan" / "zero-breach-toolkit.py").resolve()

        which_zbt = shutil.which("zero-breach-toolkit") or shutil.which("zero-breach-toolkit.py")
        candidates = [
            os.environ.get("ECOSYSTEM_ZBT_SCRIPT"),
            os.environ.get("ECOSYSTEM_ZBT_PATH"),
            which_zbt,
            Path(__file__).resolve().parent.parent.parent.parent / "Zero-Breach-Toolkit" / "scan" / "zero-breach-toolkit.py",
            Path.home() / ".local" / "share" / "ecosystem" / "zbt" / "zero-breach-toolkit.py",
            Path.home() / "GitHub" / "Zero-Breach-Toolkit" / "scan" / "zero-breach-toolkit.py",
        ]
        for c in candidates:
            if c:
                cp = Path(c)
                if cp.is_file():
                    return cp.resolve()
                if cp.is_dir() and (cp / "scan" / "zero-breach-toolkit.py").is_file():
                    return (cp / "scan" / "zero-breach-toolkit.py").resolve()
        return None

    def get_metadata(self) -> ZbtMetadata:
        if self._metadata is not None:
            return self._metadata
        if not self.zbt_script or not self.zbt_script.is_file():
            self._metadata = ZbtMetadata()
            return self._metadata

        import subprocess
        try:
            res = subprocess.run(
                [sys.executable, str(self.zbt_script), "--describe"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                self._metadata = ZbtMetadata.from_describe_dict(data)
                return self._metadata
        except Exception as exc:
            logger.error("Failed describing ZBT (%r); using fallback metadata", exc)
        self._metadata = ZbtMetadata()
        return self._metadata

    def _get_device_lock(self, device_id: str) -> asyncio.Lock:
        if device_id not in self._device_locks:
            self._device_locks[device_id] = asyncio.Lock()
        return self._device_locks[device_id]

    async def run_scan(self, req: ScanRequest) -> ScanResult:
        started_at = _iso_utc()
        start_ts = time.time()
        metadata = self.get_metadata()

        # 1. Policy Engine evaluation (Freeze beats everything; action="scan.request")
        if self.policy_engine is not None:
            try:
                from ecosystem_policy.engine import ActionRequest
                act_req = ActionRequest(
                    actor=req.initiator,
                    action="scan.request",
                    action_class="investigate",
                    target={
                        "device_id": req.device_id,
                        "public_key_fingerprint": req.public_key_fingerprint,
                    },
                    context={
                        "profile": req.profile,
                        "trigger": req.trigger,
                        "offline": req.offline,
                    },
                    authenticated=True,
                )
                decision = self.policy_engine.decide(act_req)
                # An operator approval from WP1 execute_approved (`authorization_ref="approval:..."`)
                # satisfies `require_approval` only; `"deny"` and Freeze always block.
                approved_by_operator = (
                    decision.result == "require_approval"
                    and isinstance(req.authorization_ref, str)
                    and req.authorization_ref.startswith("approval:")
                )
                if decision.result not in ("allow", "allow_and_notify") and not approved_by_operator:
                    blocked_status = "denied" if decision.result == "deny" else "needs_approval"
                    res = ScanResult(
                        scan_id=req.scan_id,
                        device_id=req.device_id,
                        status=blocked_status,
                        exit_code=4,
                        exit_description=decision.reason,
                        share={"verdict": blocked_status, "reason": decision.reason},
                        report_ref="",
                        started_at=started_at,
                        completed_at=_iso_utc(),
                        duration_seconds=round(time.time() - start_ts, 2),
                        error_message=decision.reason,
                    )
                    self._results_history[req.scan_id] = res
                    self._persist_history()
                    return res
            except Exception as exc:
                logger.error("Policy check failed closed: %r", exc)
                res = ScanResult(
                    scan_id=req.scan_id,
                    device_id=req.device_id,
                    status="denied",
                    exit_code=4,
                    exit_description="Policy check failed closed",
                    share={"verdict": "denied", "reason": "Policy evaluation error"},
                    report_ref="",
                    started_at=started_at,
                    completed_at=_iso_utc(),
                    duration_seconds=round(time.time() - start_ts, 2),
                    error_message=str(exc),
                )
                self._results_history[req.scan_id] = res
                self._persist_history()
                return res

            # 1a. Recorded consent check for device targets (consent is data, never assumed)
            if not req.phone_folder and hasattr(self.policy_engine, "list_enrolled_devices"):
                enrolled_list = self.policy_engine.list_enrolled_devices() or []
                rec = next((d for d in enrolled_list if d.get("device_id") == req.device_id), None)
                if rec is None or rec.get("revoked") or not rec.get("owner") or not rec.get("aup_version"):
                    reason = (
                        f"Device '{req.device_id}' has no valid recorded AUP consent "
                        "(owner + aup_version required; revoked consent refuses scans)."
                    )
                    res = ScanResult(
                        scan_id=req.scan_id,
                        device_id=req.device_id,
                        status="denied",
                        exit_code=4,
                        exit_description=reason,
                        share={"verdict": "denied", "reason": reason},
                        report_ref="",
                        started_at=started_at,
                        completed_at=_iso_utc(),
                        duration_seconds=round(time.time() - start_ts, 2),
                        error_message=reason,
                    )
                    self._results_history[req.scan_id] = res
                    self._persist_history()
                    return res

        # 1b. Confine any requested phone_folder to the configured allowlist
        phone_path: str | None = None
        if req.phone_folder:
            phone_path, pf_err = _validate_phone_folder(req.phone_folder)
            if pf_err:
                res = ScanResult(
                    scan_id=req.scan_id,
                    device_id=req.device_id,
                    status="denied",
                    exit_code=4,
                    exit_description=pf_err,
                    share={"verdict": "denied", "reason": pf_err},
                    report_ref="",
                    started_at=started_at,
                    completed_at=_iso_utc(),
                    duration_seconds=round(time.time() - start_ts, 2),
                    error_message=pf_err,
                )
                self._results_history[req.scan_id] = res
                self._persist_history()
                return res

        # 2. Acquire single-flight lock per device
        lock = self._get_device_lock(req.device_id)
        if lock.locked():
            logger.info("Device %s is already scanning; marking as deferred", req.device_id)
            res = ScanResult(
                scan_id=req.scan_id,
                device_id=req.device_id,
                status="deferred",
                exit_code=4,
                exit_description="Device scan deferred: another scan is active on this endpoint",
                share={"verdict": "deferred", "reason": "Target endpoint locked"},
                report_ref="",
                started_at=started_at,
                completed_at=_iso_utc(),
                duration_seconds=0.0,
                error_message="Device busy / lock held",
            )
            self._results_history[req.scan_id] = res
            self._persist_history()
            return res

        async with lock:
            if not self.zbt_script or not self.zbt_script.is_file():
                res = ScanResult(
                    scan_id=req.scan_id,
                    device_id=req.device_id,
                    status="error",
                    exit_code=1,
                    exit_description="ZBT binary/script not found on host",
                    share={"verdict": "error", "error": "ZBT script missing"},
                    report_ref="",
                    started_at=started_at,
                    completed_at=_iso_utc(),
                    duration_seconds=round(time.time() - start_ts, 2),
                    error_message=f"zero-breach-toolkit.py not found at {self.zbt_script}",
                )
                self._results_history[req.scan_id] = res
                self._persist_history()
                return res

            out_dir = self.scans_dir / req.scan_id
            out_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(out_dir, 0o700)
            except Exception:
                pass

            full_json_path = out_dir / "full.json"
            share_json_path = out_dir / "share.json"

            args = [
                sys.executable,
                str(self.zbt_script),
                "--no-menu",
                "--no-banner",
                "--json",
                str(full_json_path),
                "--share-json",
                str(share_json_path),
            ]
            if req.offline:
                args.append("--no-feeds")
            if req.profile == "quick":
                args.append("--quick")
            if phone_path:
                args.extend(["--phone", phone_path])

            logger.info("Executing ZBT scan %s for device %s...", req.scan_id, req.device_id)
            timed_out = False
            cancelled = False
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr_data = await asyncio.wait_for(proc.communicate(), timeout=600.0)
                rc = proc.returncode if proc.returncode is not None else 1
                stderr_str = stderr_data.decode("utf-8", errors="replace")
            except asyncio.TimeoutError:
                timed_out = True
                if proc:
                    try:
                        proc.kill()
                        await proc.wait()
                    except Exception:
                        pass
                rc = 124
                stderr_str = "Scan execution timed out after 600s"
            except asyncio.CancelledError:
                if proc:
                    try:
                        proc.kill()
                        await proc.wait()
                    except Exception:
                        pass
                cancelled_res = ScanResult(
                    scan_id=req.scan_id,
                    device_id=req.device_id,
                    status="cancelled",
                    exit_code=4,
                    exit_description="Scan execution cancelled",
                    share={"verdict": "cancelled"},
                    report_ref="",
                    started_at=started_at,
                    completed_at=_iso_utc(),
                    duration_seconds=round(time.time() - start_ts, 2),
                    error_message="Scan cancelled",
                )
                self._results_history[req.scan_id] = cancelled_res
                self._persist_history()
                raise
            except Exception as exc:
                rc = 1
                stderr_str = f"Failed spawning ZBT process: {exc!r}"

            completed_at = _iso_utc()
            duration = round(time.time() - start_ts, 2)

            share_data: dict[str, Any] = {}
            share_valid = False
            if share_json_path.is_file():
                try:
                    share_data = json.loads(share_json_path.read_text(encoding="utf-8"))
                    share_valid = isinstance(share_data, dict)
                except Exception as exc:
                    logger.warning("Failed parsing share.json: %r", exc)
                    share_data = {"verdict": "unknown", "error": "Invalid share summary"}
            else:
                share_data = {"verdict": "timed_out" if timed_out else "unknown"}

            # Timed-out, partial, or unparseable runs are NEVER reported as clean
            if timed_out:
                status = "timed_out"
                exit_desc = "Scan execution timed out"
            else:
                status = metadata.map_wp6_outcome(rc)
                if status == "clean" and not share_valid:
                    status = "unknown"
                exit_desc = metadata.exit_codes.get(str(rc), f"Exit code {rc}")

            # ECO-04: Run registered pluggable scanner extensions (isolated, redacted summaries on bus)
            ext_results = []
            if self.extension_registry is not None and not timed_out:
                from .extensions import ExtensionContext

                ext_ctx = ExtensionContext(
                    scan_id=req.scan_id,
                    device_id=req.device_id,
                    profile=req.profile,
                    offline=req.offline,
                    phone_folder=phone_path,
                    core_status=status,
                )

                def _is_frozen() -> bool:
                    if self.policy_engine is None:
                        return False
                    try:
                        return bool(self.policy_engine.export_state().get("frozen"))
                    except Exception:
                        # Fail closed: if policy state cannot be read, treat as frozen
                        return True

                try:
                    ext_results = await self.extension_registry.run_all(ext_ctx, is_frozen_fn=_is_frozen)
                except asyncio.CancelledError:
                    if full_json_path.is_file():
                        try:
                            orig_len = full_json_path.stat().st_size
                            full_json_path.write_bytes(b"\x00" * orig_len)
                        except Exception:
                            pass
                        full_json_path.unlink(missing_ok=True)
                    cancelled_res = ScanResult(
                        scan_id=req.scan_id,
                        device_id=req.device_id,
                        status="cancelled",
                        exit_code=4,
                        exit_description="Scan execution cancelled during extensions",
                        share={"verdict": "cancelled"},
                        report_ref="",
                        started_at=started_at,
                        completed_at=_iso_utc(),
                        duration_seconds=round(time.time() - start_ts, 2),
                        error_message="Scan cancelled",
                    )
                    self._results_history[req.scan_id] = cancelled_res
                    self._persist_history()
                    raise

                if ext_results:
                    if not isinstance(share_data, dict):
                        share_data = {"verdict": "unknown", "error": "Invalid share summary"}
                    share_data["extensions"] = [r.to_public_summary() for r in ext_results]
                    if any(r.status == "findings" for r in ext_results) and status == "clean":
                        status = "findings"
                    elif any(r.status in ("partial", "error", "skipped_frozen") for r in ext_results) and status == "clean":
                        status = "partial"

            completed_at = _iso_utc()
            duration = round(time.time() - start_ts, 2)

            report_ref = ""
            full_payload_bytes: bytes | None = None
            ext_full_records = [r.to_full_record() for r in ext_results] if ext_results else []
            if full_json_path.is_file():
                try:
                    full_payload_bytes = full_json_path.read_bytes()
                    if ext_full_records:
                        try:
                            full_obj = json.loads(full_payload_bytes.decode("utf-8"))
                            if isinstance(full_obj, dict):
                                full_obj["extensions"] = ext_full_records
                                full_payload_bytes = json.dumps(full_obj, default=str).encode("utf-8")
                            else:
                                full_payload_bytes = json.dumps(
                                    {"core": full_obj, "extensions": ext_full_records},
                                    default=str,
                                ).encode("utf-8")
                        except Exception:
                            full_payload_bytes = json.dumps(
                                {
                                    "core_raw": full_payload_bytes.decode("utf-8", errors="replace"),
                                    "extensions": ext_full_records,
                                },
                                default=str,
                            ).encode("utf-8")
                except Exception as exc:
                    logger.error("Failed reading full scan report: %r", exc)
            elif ext_full_records:
                full_payload_bytes = json.dumps(
                    {"scan_id": req.scan_id, "extensions": ext_full_records},
                    default=str,
                ).encode("utf-8")

            if full_payload_bytes is not None:
                try:
                    enc_bytes = self.encryptor.encrypt_bytes(full_payload_bytes)
                    enc_path = out_dir / f"{req.scan_id}.full.enc"
                    enc_path.write_bytes(enc_bytes)
                    try:
                        os.chmod(enc_path, 0o600)
                    except Exception:
                        pass
                    # Overwrite and remove plaintext report
                    if full_json_path.is_file():
                        try:
                            orig_len = full_json_path.stat().st_size
                            full_json_path.write_bytes(b"\x00" * orig_len)
                        except Exception:
                            pass
                        full_json_path.unlink(missing_ok=True)
                    report_ref = str(enc_path)
                except Exception as exc:
                    logger.error("Failed encrypting full scan report: %r", exc)

            scan_result = ScanResult(
                scan_id=req.scan_id,
                device_id=req.device_id,
                status=status,
                exit_code=rc,
                exit_description=exit_desc,
                share=share_data,
                report_ref=report_ref,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                error_message=stderr_str if status in ("unknown", "timed_out", "cancelled") else None,
            )

            # Emit scan.completed onto event bus (only share.json summary — NEVER host paths)
            if self.event_bus is not None:
                try:
                    await self.event_bus.publish(
                        source="scan_agent",
                        event_type="scan.completed",
                        payload={
                            "scan_id": req.scan_id,
                            "device_id": req.device_id,
                            "status": status,
                            "exit_code": rc,
                            "share": share_data,
                            "has_full_report": bool(report_ref),
                            "duration_seconds": duration,
                        },
                    )
                except Exception as exc:
                    logger.warning("Failed publishing scan.completed event: %r", exc)

            # Publish completion notification with zero filesystem paths or indicator values
            if self.notification_router is not None:
                try:
                    from ecosystem_client.contracts import build_notification_envelope

                    sev = "high" if status == "findings" else ("medium" if status in ("partial", "timed_out") else "low")
                    title = f"Device scan {status}: {req.device_id}"
                    body = (
                        f"ZBT {req.profile} scan ({req.scan_id}) completed with status '{status}'. "
                        "Inspect the redacted summary or use step-up data_release to view full details."
                    )
                    envelope = build_notification_envelope(
                        "notify.scan",
                        "ecosystem_scan_agent",
                        sev,
                        title,
                        body,
                        dedupe_key=f"scan:{req.scan_id}:{status}",
                        privacy="redacted",
                    )
                    await self.notification_router.route(envelope)
                except Exception as exc:
                    logger.warning("Failed routing scan completion notification: %r", exc)

            self._results_history[req.scan_id] = scan_result
            self._persist_history()
            return scan_result

    def get_scan(self, scan_id: str) -> ScanResult | None:
        return self._results_history.get(scan_id)

    def list_scans(self, device_id: str | None = None) -> list[ScanResult]:
        scans = list(self._results_history.values())
        if device_id:
            scans = [s for s in scans if s.device_id == device_id]
        scans.sort(key=lambda s: s.started_at, reverse=True)
        return scans

    def decrypt_full_report(self, scan_id: str) -> dict[str, Any]:
        """Decrypts full report on demand for authorized operators."""
        scan = self.get_scan(scan_id)
        if not scan or not scan.report_ref:
            raise FileNotFoundError(f"No encrypted full report found for scan {scan_id}")
        ref_path = Path(scan.report_ref)
        if not ref_path.is_file():
            raise FileNotFoundError(f"Report file {ref_path} does not exist")
        enc_bytes = ref_path.read_bytes()
        dec_bytes = self.encryptor.decrypt_bytes(enc_bytes)
        return json.loads(dec_bytes.decode("utf-8"))
