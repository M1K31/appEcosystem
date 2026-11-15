"""Embeddable HubRuntime supporting `host | join | auto | off` across ecosystem projects."""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from ecosystem_auth.tokens import sign_request
from ecosystem_client import EcosystemClient
from ecosystem_client.config import EcosystemConfig
from ecosystem_client.contracts import build_notification_envelope
from ecosystem_client.ulid import generate_ulid, resolve_device_id

from .capabilities import CapabilityRegistry, CapabilityResolution
from .lock import SingleHostLock
from .outbox import DurableOutbox, default_outbox_path

logger = logging.getLogger(__name__)


class HubRole(str, Enum):
    HOST = "host"
    JOIN = "join"
    AUTO = "auto"
    OFF = "off"


def _parse_role(value: str | HubRole | None) -> HubRole:
    raw = (value.value if isinstance(value, HubRole) else (value or os.environ.get("ECOSYSTEM_HUB_ROLE") or "auto")).strip().lower()
    for member in HubRole:
        if member.value == raw:
            return member
    logger.warning("Unknown ECOSYSTEM_HUB_ROLE %r — defaulting to 'auto'", raw)
    return HubRole.AUTO


class HubRuntime:
    """Lifecycle coordinator enabling any eligible app to host, join, or run standalone.

    Guarantees:
    - Single-host lock (`SingleHostLock`) prevents duplicate embedded Hubs on one device.
    - Hardware-tier awareness declines auto-hosting on `T0_MINIMAL` (<4 GB RAM) devices
      unless `role='host'` or `allow_minimal_host=True` is explicitly configured.
    - Capabilities work locally when standalone and sync to `/capabilities/register` when joined.
    - `notify()` delivers to `/notifications/publish` when connected or buffers in a
      SQLite `DurableOutbox` when offline, flushing automatically on reconnection.
    """

    def __init__(
        self,
        app_name: str,
        *,
        service_port: int = 0,
        priority: int = 0,
        role: str | HubRole | None = None,
        capabilities: list[dict[str, Any]] | None = None,
        subscriptions: list[str] | None = None,
        health_endpoint: str = "/health",
        config: EcosystemConfig | None = None,
        lock_path: str | Path | None = None,
        outbox_path: str | Path | None = None,
        allow_minimal_host: bool = False,
        sync_interval: float = 20.0,
        host_spawner: Callable[[str, int], subprocess.Popen[Any]] | None = None,
    ):
        self.app_name = app_name
        self.service_port = int(service_port)
        self.priority = int(priority)
        self.role = _parse_role(role)
        self.health_endpoint = health_endpoint
        self.device_id = resolve_device_id()

        self.config = config or EcosystemConfig.from_env()
        if priority:
            self.config.priority = priority

        self.local_capabilities = CapabilityRegistry()
        self._initial_capabilities = list(capabilities or [])
        self._subscriptions = list(subscriptions or [])
        self._lock = SingleHostLock(lock_path)
        self.outbox = DurableOutbox(outbox_path or default_outbox_path(app_name))
        self._allow_minimal_host = allow_minimal_host
        self._sync_interval = max(1.0, float(sync_interval))
        self._host_spawner = host_spawner

        self._client: EcosystemClient | None = None
        self._sidecar_proc: subprocess.Popen[Any] | None = None
        self._hosting = False
        self._joined = False
        self._effective_mode = "standalone"
        self._started = False
        self._bg_task: asyncio.Task[None] | None = None
        # How invoke()/get_command() open their HTTP client; tests substitute a transport.
        self._http_factory: Callable[[float], httpx.AsyncClient] = lambda timeout: httpx.AsyncClient(timeout=timeout)

    @property
    def effective_mode(self) -> str:
        """One of `'hosting'`, `'joined'`, or `'standalone'`."""
        return self._effective_mode

    @property
    def is_hosting(self) -> bool:
        return self._hosting

    @property
    def is_joined(self) -> bool:
        return self._joined

    @property
    def client(self) -> EcosystemClient | None:
        return self._client

    def _normalize_manifest(self, partial: dict[str, Any]) -> dict[str, Any]:
        """Fill default provider `{app, device_id}` and `schema_version` if omitted."""
        m = dict(partial)
        m.setdefault("schema_version", 1)
        m.setdefault("provider", {"app": self.app_name, "device_id": self.device_id})
        return m

    def _can_auto_host(self) -> bool:
        if self.priority <= 0:
            return False
        if self._allow_minimal_host:
            return True
        try:
            from ecosystem_ai.hardware import CapabilityTier, probe, tier_for

            hw = probe()
            if tier_for(hw) == CapabilityTier.T0_MINIMAL:
                logger.info(
                    "HubRuntime(%s): Tier T0_MINIMAL (<4 GB RAM) detected; preferring join/standalone over auto-hosting",
                    self.app_name,
                )
                return False
        except Exception:
            pass
        return True

    async def _probe_hub_health(self, timeout: float = 1.5) -> bool:
        url = f"{self.config.registry_url.rstrip('/')}/health"
        try:
            async with httpx.AsyncClient(timeout=timeout) as http:
                resp = await http.get(url)
                return resp.status_code == 200
        except Exception:
            return False

    def _default_spawn_sidecar(self, bind_host: str, port: int) -> subprocess.Popen[Any]:
        repo_root = Path(__file__).resolve().parents[3]
        env = os.environ.copy()
        py_paths = [
            str(repo_root),
            str(repo_root / "auth" / "python"),
            str(repo_root / "packages" / "ecosystem-ai"),
            str(repo_root / "packages" / "ecosystem-client"),
            str(repo_root / "packages" / "ecosystem-hub"),
            str(repo_root / "packages" / "ecosystem-policy"),
        ]
        existing_py = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = os.pathsep.join(py_paths + ([existing_py] if existing_py else []))
        cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "registry.app:app",
            "--host",
            bind_host,
            "--port",
            str(port),
            "--log-level",
            "warning",
        ]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        return subprocess.Popen(
            cmd,
            cwd=str(repo_root),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )

    async def _try_start_host(self) -> bool:
        parsed = urlparse(self.config.registry_url)
        bind_host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 8500

        if not self._lock.acquire(
            app_name=self.app_name,
            hub_url=self.config.registry_url,
            priority=self.priority,
        ):
            # Another local app holds the lock — wait briefly for its /health to come up.
            for _ in range(10):
                if await self._probe_hub_health(timeout=0.5):
                    return False
                await asyncio.sleep(0.25)
            return False

        spawner = self._host_spawner or self._default_spawn_sidecar
        try:
            self._sidecar_proc = spawner(bind_host, port)
        except Exception as exc:
            logger.warning("HubRuntime(%s): failed to launch Hub sidecar: %r", self.app_name, exc)
            self._lock.release()
            return False

        for _ in range(25):
            if self._sidecar_proc.poll() is not None:
                break
            if await self._probe_hub_health(timeout=0.5):
                self._hosting = True
                return True
            await asyncio.sleep(0.2)

        # Failed health startup — clean up sidecar and release lock.
        self._terminate_sidecar()
        self._lock.release()
        return False

    def _terminate_sidecar(self) -> None:
        proc = self._sidecar_proc
        self._sidecar_proc = None
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except Exception:
            pass

    def _signed_headers(self, method: str, url: str, body: Any = None) -> dict[str, str]:
        secret = self.config.hmac_secret
        if not secret:
            return {}
        return sign_request(method, url, secret, body=body)

    async def _sync_capabilities_to_hub(self) -> bool:
        manifests = [
            rec["manifest"]
            for rec in self.local_capabilities.list_capabilities(app=self.app_name, active_only=True)
        ]
        if not manifests:
            return True
        url = f"{self.config.registry_url.rstrip('/')}/capabilities/register"
        body = {"capabilities": manifests}
        headers = self._signed_headers("POST", url, body)
        try:
            async with httpx.AsyncClient(timeout=self.config.request_timeout) as http:
                resp = await http.post(url, json=body, headers=headers)
                return resp.status_code < 400
        except Exception as exc:
            logger.debug("HubRuntime(%s): capability sync deferred: %r", self.app_name, exc)
            return False

    async def _withdraw_capabilities_from_hub(self) -> None:
        url = f"{self.config.registry_url.rstrip('/')}/capabilities/{self.app_name}"
        headers = self._signed_headers("DELETE", url)
        try:
            async with httpx.AsyncClient(timeout=2.5) as http:
                await http.delete(url, headers=headers)
        except Exception:
            pass

    async def _deliver_notification_to_hub(self, envelope: dict[str, Any]) -> bool:
        url = f"{self.config.registry_url.rstrip('/')}/notifications/publish"
        headers = self._signed_headers("POST", url, envelope)
        async with httpx.AsyncClient(timeout=self.config.request_timeout) as http:
            resp = await http.post(url, json=envelope, headers=headers)
            return resp.status_code < 400

    async def _join_reachable_hub(self) -> None:
        if self.service_port > 0 and self._client is None:
            self._client = EcosystemClient(
                service_name=self.app_name,
                service_port=self.service_port,
                health_endpoint=self.health_endpoint,
                subscriptions=self._subscriptions,
                config=self.config,
                priority=self.priority,
            )
            await self._client.start()

        self._joined = True
        self._effective_mode = "hosting" if self._hosting else "joined"
        await self._sync_capabilities_to_hub()
        await self.outbox.flush(self._deliver_notification_to_hub)

    async def start(self) -> str:
        """Start the HubRuntime according to `role`, returning `effective_mode`."""
        if self._started:
            return self._effective_mode

        for raw_cap in self._initial_capabilities:
            self.local_capabilities.register(self._normalize_manifest(raw_cap))

        self._started = True

        if self.role == HubRole.OFF:
            self._effective_mode = "standalone"
            return self._effective_mode

        if await self._probe_hub_health():
            await self._join_reachable_hub()
        elif self.role == HubRole.HOST or (self.role == HubRole.AUTO and self._can_auto_host()):
            hosted = await self._try_start_host()
            if hosted or await self._probe_hub_health():
                await self._join_reachable_hub()
            else:
                self._effective_mode = "standalone"
        else:
            self._effective_mode = "standalone"

        self._bg_task = asyncio.create_task(self._background_loop())
        return self._effective_mode

    async def _background_loop(self) -> None:
        while self._started:
            await asyncio.sleep(self._sync_interval)
            try:
                alive = await self._probe_hub_health()
                if alive:
                    if not self._joined:
                        await self._join_reachable_hub()
                    else:
                        await self._sync_capabilities_to_hub()
                        if self.outbox.pending_count() > 0:
                            await self.outbox.flush(self._deliver_notification_to_hub)
                else:
                    if self._joined and not self._hosting:
                        self._joined = False
                        self._effective_mode = "standalone"
            except Exception as exc:
                logger.debug("HubRuntime(%s) background sync error: %r", self.app_name, exc)

    async def stop(self) -> None:
        """Orderly shutdown: withdraw capabilities, close client, stop hosted sidecar, release lock."""
        self._started = False
        if self._bg_task:
            self._bg_task.cancel()
            try:
                await self._bg_task
            except asyncio.CancelledError:
                pass
            self._bg_task = None

        if self._joined and not self._hosting:
            await self._withdraw_capabilities_from_hub()

        if self._client is not None:
            try:
                await self._client.stop()
            except Exception:
                pass
            self._client = None

        if self._hosting:
            self._terminate_sidecar()
            self._hosting = False

        self._lock.release()
        self._joined = False
        self._effective_mode = "standalone"

    async def register_capability(self, manifest: dict[str, Any]) -> dict[str, Any]:
        norm = self._normalize_manifest(manifest)
        rec = self.local_capabilities.register(norm)
        if self._joined:
            await self._sync_capabilities_to_hub()
        return rec

    async def withdraw_capability(self, capability: str, *, reason: str | None = None) -> int:
        count = self.local_capabilities.withdraw(
            capability,
            self.app_name,
            device_id=self.device_id,
            reason=reason,
        )
        if self._joined:
            url = f"{self.config.registry_url.rstrip('/')}/capabilities/{self.app_name}/{capability}"
            headers = self._signed_headers("DELETE", url)
            try:
                async with httpx.AsyncClient(timeout=2.5) as http:
                    await http.delete(url, headers=headers)
            except Exception:
                pass
        return count

    def resolve_capability(self, capability: str) -> CapabilityResolution:
        return self.local_capabilities.resolve(capability)

    async def notify(
        self,
        notify_type: str,
        severity: str,
        title: str,
        body: str,
        *,
        dedupe_key: str,
        actions: list[dict[str, Any]] | None = None,
        privacy: str = "redacted",
        ttl: str = "24h",
        deep_link: str | None = None,
    ) -> dict[str, Any]:
        """Build a signed NotificationEnvelope and deliver to Hub or queue in DurableOutbox."""
        envelope = build_notification_envelope(
            notify_type=notify_type,
            source_app=self.app_name,
            severity=severity,
            title=title,
            body=body,
            dedupe_key=dedupe_key,
            device_id=self.device_id,
            actions=actions,
            privacy=privacy,
            ttl=ttl,
            deep_link=deep_link,
            secret=self.config.hmac_secret or None,
        )
        if self._joined:
            try:
                if await self._deliver_notification_to_hub(envelope):
                    return {"status": "delivered", "id": envelope["id"]}
            except Exception:
                pass

        queued = self.outbox.enqueue(envelope)
        return {
            "status": "queued_offline" if queued else "deduplicated_offline",
            "id": envelope["id"],
        }

    # ---- capability invocation --------------------------------------------

    async def invoke(
        self,
        capability: str,
        target: dict[str, Any],
        parameters: dict[str, Any] | None = None,
        *,
        rationale: str | None = None,
        idempotency_key: str | None = None,
        actor_type: str = "service",
        actor_id: str | None = None,
        correlation_id: str | None = None,
        context: dict[str, Any] | None = None,
        step_up_token: str | None = None,
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """Ask the hub to run a capability and return its status document.

        The hub decides (policy, approval) and forwards to the provider;
        `status` is one of completed, accepted, pending_approval, denied,
        failed or provider_unavailable. Nothing is ever queued: if the hub
        cannot be reached the answer is provider_unavailable, and the caller
        decides whether to try again. To retry safely after an unknown
        outcome, pass the same `idempotency_key`.
        """
        if not self.config.hmac_secret:
            return {"status": "provider_unavailable", "error": "not_configured", "command_id": None}
        key = idempotency_key or generate_ulid()
        body: dict[str, Any] = {
            "capability": capability,
            "target": dict(target or {}),
            "parameters": dict(parameters or {}),
            "actor": {
                "app": self.app_name,
                "id": actor_id or self.app_name,
                "type": actor_type,
                "device_id": self.device_id,
            },
            "idempotency_key": key,
        }
        for name, value in (
            ("rationale", rationale),
            ("correlation_id", correlation_id),
            ("context", context),
            ("step_up_token", step_up_token),
        ):
            if value is not None:
                body[name] = value

        url = f"{self.config.registry_url.rstrip('/')}/commands/dispatch"
        try:
            async with self._http_factory(timeout) as http:
                resp = await http.post(url, json=body, headers=self._signed_headers("POST", url, body))
        except (httpx.ConnectError, httpx.ConnectTimeout):
            # Never connected: the hub did not receive the request.
            return {"status": "provider_unavailable", "error": "hub_unreachable", "command_id": None}
        except httpx.HTTPError as exc:
            return {
                "status": "failed",
                "error": f"no answer from the hub ({type(exc).__name__})",
                "outcome_unknown": True,
                "command_id": None,
                "idempotency_key": key,
            }

        try:
            payload = resp.json()
        except ValueError:
            payload = None
        if resp.status_code == 200 and isinstance(payload, dict):
            return payload
        detail = payload.get("detail") if isinstance(payload, dict) else None
        out: dict[str, Any] = {
            "status": "failed",
            "error": str(detail) if detail else f"hub answered HTTP {resp.status_code}",
            "http_status": resp.status_code,
            "command_id": None,
            "idempotency_key": key,
        }
        if resp.status_code >= 500 or resp.status_code == 200:
            # The hub may have got as far as forwarding the command.
            out["outcome_unknown"] = True
        return out

    async def get_command(self, command_id: str) -> dict[str, Any] | None:
        """The hub's record of a command (status, result, audit events), or None."""
        url = f"{self.config.registry_url.rstrip('/')}/commands/{command_id}"
        try:
            async with self._http_factory(self.config.request_timeout) as http:
                resp = await http.get(url, headers=self._signed_headers("GET", url))
            if resp.status_code != 200:
                return None
            payload = resp.json()
        except (httpx.HTTPError, ValueError):
            return None
        return payload if isinstance(payload, dict) else None

    def status(self) -> dict[str, Any]:
        return {
            "app_name": self.app_name,
            "device_id": self.device_id,
            "role": self.role.value,
            "effective_mode": self._effective_mode,
            "hosting": self._hosting,
            "joined": self._joined,
            "hub_url": self.config.registry_url,
            "lock_owner": self._lock.inspect_owner(),
            "registered_capabilities": [
                r["capability"]
                for r in self.local_capabilities.list_capabilities(app=self.app_name, active_only=True)
            ],
            "pending_outbox": self.outbox.pending_count(),
        }
