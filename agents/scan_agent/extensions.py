"""ECO-04: Pluggable ZBT Scanner Extension Framework.

Provides a clean, fail-isolated interface allowing custom domain-specific
inspection checks (Python callables or sandboxed read-only scripts) to register
with ``ScanRunner`` alongside the core Zero Breach Toolkit mercenary spyware
checks.

Security & Privacy Invariants:
  - Read-only & offline by contract; script extensions run via
    ``create_subprocess_exec`` (``shell=False``) with a scrubbed environment
    that NEVER includes ``ECOSYSTEM_HMAC_SECRET`` or cloud API keys.
  - Script paths must reside strictly inside the configured ``extensions_dir``
    (symlinks and path traversal are rejected fail-closed) and optionally match
    a pinned SHA-256 digest.
  - Only redacted summaries (``extension_id``, ``status``, ``findings_count``,
    ``severity``, ``summary``) are placed in ``share.json``; full ``details``
    are stored solely inside the AES-256-GCM encrypted ``.full.enc`` report.
  - Extension crashes or timeouts never crash ``ScanRunner`` and never allow a
    scan with failed checks to be reported as ``clean``.
"""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import os
import re
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

logger = logging.getLogger("ecosystem.scan_extensions")

_SAFE_EXT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_VALID_PROFILES = frozenset({"quick", "standard", "full"})
_VALID_STATUSES = frozenset({"clean", "findings", "partial", "error", "skipped_frozen"})
_VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
_HOST_PATH_RE = re.compile(r"(/[A-Za-z0-9._-]+){2,}|[A-Za-z]:\\[^\s'\"]+")
_MAX_SCRIPT_STDOUT_BYTES = 256 * 1024

_SCRUBBED_ENV_KEYS = (
    "PATH",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
)


def _redact_text(text: str, max_len: int = 240) -> str:
    cleaned = _HOST_PATH_RE.sub("[redacted-path]", str(text or ""))
    return cleaned[:max_len]


@dataclass(frozen=True)
class ExtensionContext:
    """Read-only context passed to each scanner extension during a scan."""

    scan_id: str
    device_id: str
    profile: str
    offline: bool
    phone_folder: str | None = None
    core_status: str = "clean"


@dataclass
class ExtensionResult:
    """Structured outcome returned by a scanner extension."""

    extension_id: str
    status: str = "clean"  # clean | findings | partial | error | skipped_frozen
    findings_count: int = 0
    severity: str = "low"  # low | medium | high | critical
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in _VALID_STATUSES:
            self.status = "error"
        if self.severity not in _VALID_SEVERITIES:
            self.severity = "low"
        self.findings_count = max(0, int(self.findings_count))

    def to_public_summary(self) -> dict[str, Any]:
        """Safe, redacted summary suitable for ``share.json`` and bus notifications."""
        return {
            "extension_id": self.extension_id,
            "status": self.status,
            "findings_count": self.findings_count,
            "severity": self.severity,
            "summary": _redact_text(self.summary),
        }

    def to_full_record(self) -> dict[str, Any]:
        """Complete record stored exclusively inside the AES-256-GCM encrypted report."""
        rec = self.to_public_summary()
        rec["details"] = dict(self.details)
        return rec


ExtensionCallable = Callable[[ExtensionContext], ExtensionResult | Awaitable[ExtensionResult]]


class ScannerExtension:
    """Base class for in-process Python scanner extensions."""

    kind: str = "callable"

    def __init__(
        self,
        extension_id: str,
        *,
        display_name: str = "",
        version: str = "1.0.0",
        profiles: tuple[str, ...] = ("quick", "standard", "full"),
        timeout_seconds: float = 30.0,
        enabled: bool = True,
        handler: ExtensionCallable | None = None,
    ):
        eid = str(extension_id or "").strip().lower()
        if not _SAFE_EXT_ID_RE.match(eid):
            raise ValueError(f"Invalid extension_id: {extension_id!r}")
        cleaned_profiles = tuple(p.strip().lower() for p in profiles if p.strip().lower() in _VALID_PROFILES)
        if not cleaned_profiles:
            raise ValueError("Extension must declare at least one valid profile (quick, standard, full)")
        self.extension_id = eid
        self.display_name = str(display_name or eid).strip()
        self.version = str(version or "1.0.0").strip()
        self.profiles = cleaned_profiles
        self.timeout_seconds = max(1.0, min(300.0, float(timeout_seconds)))
        self.enabled = bool(enabled)
        self._handler = handler

    def metadata(self) -> dict[str, Any]:
        return {
            "extension_id": self.extension_id,
            "display_name": self.display_name,
            "version": self.version,
            "kind": self.kind,
            "profiles": list(self.profiles),
            "timeout_seconds": self.timeout_seconds,
            "enabled": self.enabled,
        }

    async def run(self, ctx: ExtensionContext) -> ExtensionResult:
        if self._handler is None:
            raise NotImplementedError("ScannerExtension requires a handler callable or run() override")
        res = self._handler(ctx)
        if inspect.isawaitable(res):
            res = await res
        if not isinstance(res, ExtensionResult):
            raise TypeError(f"Extension {self.extension_id!r} returned {type(res).__name__}, expected ExtensionResult")
        return res


class ScriptScannerExtension(ScannerExtension):
    """Sandboxed external script extension confined to an allowlisted ``extensions_dir``.

    The script is invoked with ``--context-json <json>`` (via ``create_subprocess_exec``,
    ``shell=False``) and must emit a single JSON object on stdout with keys
    ``status``, ``findings_count``, ``severity``, ``summary``, and optional ``details``.
    """

    kind: str = "script"

    def __init__(
        self,
        extension_id: str,
        script_path: str | Path,
        *,
        extensions_dir: str | Path,
        expected_sha256: str | None = None,
        display_name: str = "",
        version: str = "1.0.0",
        profiles: tuple[str, ...] = ("quick", "standard", "full"),
        timeout_seconds: float = 30.0,
        enabled: bool = True,
    ):
        super().__init__(
            extension_id,
            display_name=display_name,
            version=version,
            profiles=profiles,
            timeout_seconds=timeout_seconds,
            enabled=enabled,
        )
        base_dir = Path(extensions_dir).resolve()
        raw_script = Path(script_path)
        if raw_script.is_symlink():
            raise ValueError(f"Extension script may not be a symlink: {script_path}")
        resolved = raw_script.resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"Extension script not found: {script_path}")
        try:
            resolved.relative_to(base_dir)
        except ValueError as exc:
            raise ValueError(
                f"Extension script {resolved.name!r} is outside allowed extensions_dir"
            ) from exc

        self.script_path = resolved
        self.extensions_dir = base_dir
        self.expected_sha256 = str(expected_sha256).strip().lower() if expected_sha256 else None
        if self.expected_sha256:
            self._verify_sha256()

    def _verify_sha256(self) -> None:
        if not self.expected_sha256:
            return
        actual = hashlib.sha256(self.script_path.read_bytes()).hexdigest().lower()
        if actual != self.expected_sha256:
            raise PermissionError(
                f"Extension script SHA-256 mismatch for {self.extension_id!r}"
            )

    @staticmethod
    def _scrubbed_env() -> dict[str, str]:
        env = {k: os.environ[k] for k in _SCRUBBED_ENV_KEYS if k in os.environ}
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["ECOSYSTEM_EXTENSION_READONLY"] = "1"
        return env

    async def run(self, ctx: ExtensionContext) -> ExtensionResult:
        self._verify_sha256()
        ctx_payload = json.dumps(
            {
                "scan_id": ctx.scan_id,
                "device_id": ctx.device_id,
                "profile": ctx.profile,
                "offline": ctx.offline,
                "phone_folder": ctx.phone_folder,
            }
        )
        cmd = (
            [sys.executable, str(self.script_path), "--context-json", ctx_payload]
            if self.script_path.suffix == ".py"
            else [str(self.script_path), "--context-json", ctx_payload]
        )
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._scrubbed_env(),
        )
        try:
            stdout_bytes, _stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            return ExtensionResult(
                extension_id=self.extension_id,
                status="partial",
                summary=f"Extension timed out after {int(self.timeout_seconds)}s",
            )

        if proc.returncode != 0:
            return ExtensionResult(
                extension_id=self.extension_id,
                status="error",
                summary=f"Extension exited with code {proc.returncode}",
            )
        if len(stdout_bytes) > _MAX_SCRIPT_STDOUT_BYTES:
            return ExtensionResult(
                extension_id=self.extension_id,
                status="error",
                summary="Extension stdout exceeded 256 KiB safety limit",
            )
        try:
            parsed = json.loads(stdout_bytes.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("Extension stdout must be a JSON object")
        except Exception:
            return ExtensionResult(
                extension_id=self.extension_id,
                status="error",
                summary="Extension produced invalid JSON output",
            )

        return ExtensionResult(
            extension_id=self.extension_id,
            status=str(parsed.get("status") or "clean").strip().lower(),
            findings_count=int(parsed.get("findings_count") or 0),
            severity=str(parsed.get("severity") or "low").strip().lower(),
            summary=str(parsed.get("summary") or ""),
            details=dict(parsed.get("details") or {}) if isinstance(parsed.get("details"), dict) else {},
        )


class ScannerExtensionRegistry:
    """Thread-safe registry of pluggable scanner extensions executed by ``ScanRunner``."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._extensions: dict[str, ScannerExtension] = {}

    def register(self, extension: ScannerExtension) -> dict[str, Any]:
        with self._lock:
            self._extensions[extension.extension_id] = extension
            return extension.metadata()

    def register_callable(
        self,
        extension_id: str,
        handler: ExtensionCallable,
        *,
        display_name: str = "",
        version: str = "1.0.0",
        profiles: tuple[str, ...] = ("quick", "standard", "full"),
        timeout_seconds: float = 30.0,
        enabled: bool = True,
    ) -> dict[str, Any]:
        ext = ScannerExtension(
            extension_id,
            display_name=display_name,
            version=version,
            profiles=profiles,
            timeout_seconds=timeout_seconds,
            enabled=enabled,
            handler=handler,
        )
        return self.register(ext)

    def unregister(self, extension_id: str) -> bool:
        with self._lock:
            return self._extensions.pop(str(extension_id).strip().lower(), None) is not None

    def list_extensions(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._extensions[k].metadata() for k in sorted(self._extensions.keys())]

    async def run_all(
        self,
        ctx: ExtensionContext,
        *,
        is_frozen_fn: Callable[[], bool] | None = None,
    ) -> list[ExtensionResult]:
        """Run all enabled extensions matching ``ctx.profile``, isolated against failures."""
        with self._lock:
            candidates = [
                ext
                for _, ext in sorted(self._extensions.items())
                if ext.enabled and ctx.profile in ext.profiles
            ]

        results: list[ExtensionResult] = []
        for ext in candidates:
            if is_frozen_fn is not None and is_frozen_fn():
                results.append(
                    ExtensionResult(
                        extension_id=ext.extension_id,
                        status="skipped_frozen",
                        summary="Skipped due to active Ecosystem Freeze",
                    )
                )
                continue
            try:
                res = await asyncio.wait_for(ext.run(ctx), timeout=ext.timeout_seconds + 2.0)
                results.append(res)
            except asyncio.TimeoutError:
                results.append(
                    ExtensionResult(
                        extension_id=ext.extension_id,
                        status="partial",
                        summary=f"Extension timed out after {int(ext.timeout_seconds)}s",
                    )
                )
            except Exception as exc:
                logger.warning("Scanner extension '%s' failed: %r", ext.extension_id, exc)
                results.append(
                    ExtensionResult(
                        extension_id=ext.extension_id,
                        status="error",
                        summary="Extension execution failed",
                    )
                )
        return results
