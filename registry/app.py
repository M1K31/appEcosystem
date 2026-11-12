"""FastAPI application for the ecosystem service registry."""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from typing import Optional

from fastapi import Body, FastAPI, HTTPException, Request, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel
from ecosystem_auth.middleware import (
    authenticate_request, require_ecosystem_auth, security_scheme,
)

from .app_store import AppStore, RESERVED_NAMES, default_apps_path
from .credential_store import SUPPORTED_PROVIDERS, ProviderCredentialStore
from .health_monitor import HealthMonitor
from .models import HealthCheckResult, ServiceRecord, ServiceRegistration
from .registry import ServiceRegistry

if TYPE_CHECKING:
    from events.event_bus import EventBus

logger = logging.getLogger(__name__)


def _create_capability_registry(persistence_path: str):
    import sys
    from pathlib import Path

    hub_pkg = Path(__file__).resolve().parent.parent / "packages" / "ecosystem-hub"
    if hub_pkg.is_dir() and str(hub_pkg) not in sys.path:
        sys.path.insert(0, str(hub_pkg))
    from ecosystem_hub.capabilities import CapabilityRegistry

    return CapabilityRegistry(persistence_path=persistence_path)


def _ecosystem_secret_or_empty() -> str:
    """The shared secret used to sign outgoing commands, or "" when the hub has none."""
    from ecosystem_auth.tokens import get_ecosystem_secret

    try:
        return get_ecosystem_secret() or ""
    except Exception:
        return ""


def _create_policy_and_approvals(data_dir: str, notification_router, event_bus):
    import sys
    from pathlib import Path

    policy_pkg = Path(__file__).resolve().parent.parent / "packages" / "ecosystem-policy"
    if policy_pkg.is_dir() and str(policy_pkg) not in sys.path:
        sys.path.insert(0, str(policy_pkg))
    from ecosystem_policy.crypto import Ed25519PolicySigner
    from ecosystem_policy.engine import PolicyEngine
    from ecosystem_policy.step_up import StepUpAuthenticator
    from .approvals import ApprovalService

    key_dir = os.environ.get("ECOSYSTEM_POLICY_KEY_DIR") or os.path.join(data_dir, "policy_keys")
    signer = Ed25519PolicySigner.load_or_create(key_dir=key_dir)
    policy_state_path = os.environ.get("ECOSYSTEM_POLICY_STATE_FILE") or os.path.join(data_dir, "policy_state.json")
    policy_yaml_path = os.environ.get("ECOSYSTEM_POLICY_FILE")
    policy_engine = PolicyEngine.load(
        policy_yaml_path,
        signer=signer,
        authority="hub_synced",
        state_path=policy_state_path,
    )

    step_up_path = os.environ.get("ECOSYSTEM_STEP_UP_FILE") or os.path.join(data_dir, "step_up_credentials.json")
    step_up_auth = StepUpAuthenticator(store_path=step_up_path)

    approvals_db = os.environ.get("ECOSYSTEM_APPROVALS_DB") or os.path.join(data_dir, "approvals.db")
    approval_service = ApprovalService(
        db_path=approvals_db,
        step_up=step_up_auth,
        policy_engine=policy_engine,
        notification_router=notification_router,
        event_bus=event_bus,
    )
    return policy_engine, step_up_auth, approval_service


def _create_scan_service(data_dir: str, policy_engine, event_bus):
    import sys
    from pathlib import Path

    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from agents.scan_agent import ScanRunner, ScanScheduler

    scan_runner = ScanRunner(
        data_dir=data_dir,
        policy_engine=policy_engine,
        event_bus=event_bus,
    )
    scan_scheduler = ScanScheduler(
        runner=scan_runner,
        policy_engine=policy_engine,
    )
    return scan_runner, scan_scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    from .logging_config import configure_logging
    from .notifications import NotificationRouter
    from ecosystem_auth.tokens import get_ecosystem_secret

    configure_logging()
    # Fail closed at startup if no valid shared secret is provisioned (or if set
    # to the rejected development placeholder).
    get_ecosystem_secret()

    persistence_path = os.environ.get(
        "ECOSYSTEM_REGISTRY_FILE", "data/registry.json"
    )
    registry = ServiceRegistry(persistence_path=persistence_path)

    cap_path = os.environ.get(
        "ECOSYSTEM_CAPABILITIES_FILE",
        str(os.path.join(os.path.dirname(persistence_path) or "data", "capabilities.json")),
    )
    capability_registry = _create_capability_registry(cap_path)

    notify_db_path = os.environ.get(
        "ECOSYSTEM_NOTIFICATIONS_DB",
        str(os.path.join(os.path.dirname(persistence_path) or "data", "notifications.db")),
    )
    notification_router = NotificationRouter(persistence_path=notify_db_path)

    # Pre-register projects from ecosystem.yaml if available
    _register_static_projects(registry)

    try:
        from events.event_bus import EventBus
        event_bus = EventBus(registry=registry)
    except ImportError:
        event_bus = None
        logger.debug("Event bus not available — unhealthy events won't be published")

    interval = int(os.environ.get("ECOSYSTEM_HEALTH_INTERVAL", "30"))
    max_failures = int(os.environ.get("ECOSYSTEM_MAX_FAILURES", "5"))
    health_monitor = HealthMonitor(
        registry=registry,
        interval_seconds=interval,
        max_failures=max_failures,
        event_bus=event_bus,
        capability_registry=capability_registry,
    )
    await health_monitor.start()

    # Shared AI profile (single source of truth for ecosystem LLM settings).
    from .profile_store import AIProfileStore
    ai_profile_path = os.environ.get("ECOSYSTEM_AI_PROFILE_FILE", "data/ai_profile.json")
    ai_profile_store = AIProfileStore(persistence_path=ai_profile_path)

    # Per-app credential store for third-party participants (owner path uses the
    # shared secret; enrolled apps use their own key). Live-reloads from disk.
    app_store = AppStore(persistence_path=default_apps_path())

    # Cloud AI provider API keys (Anthropic/OpenAI/Gemini), file-backed at
    # ~/.config/ecosystem/provider_keys.json. Local-only surface — see the
    # /ai/providers routes below, which gate writes to loopback callers.
    provider_credential_store = ProviderCredentialStore()

    data_dir = os.path.dirname(persistence_path) or "data"
    policy_engine, step_up_auth, approval_service = _create_policy_and_approvals(
        data_dir,
        notification_router=notification_router,
        event_bus=event_bus,
    )
    await approval_service.start()

    scan_runner, scan_scheduler = _create_scan_service(
        data_dir,
        policy_engine=policy_engine,
        event_bus=event_bus,
    )

    # Command dispatch: the durable record of every capability invocation, and
    # the dispatcher that gates, signs and forwards them. Commands that were
    # mid-dispatch when the hub last stopped are marked as having an unknown
    # outcome; they are never re-sent on their own.
    from ecosystem_hub.command_store import CommandStore
    from .commands import CommandDispatcher

    command_store = CommandStore(os.environ.get("ECOSYSTEM_COMMANDS_DB") or os.path.join(data_dir, "commands.db"))
    interrupted = command_store.recover_interrupted()
    if interrupted:
        logger.warning("%d command(s) were interrupted by the last shutdown; outcome unknown", interrupted)
    command_dispatcher = CommandDispatcher(
        store=command_store,
        capability_registry=capability_registry,
        service_registry=registry,
        policy_engine=policy_engine,
        approval_service=approval_service,
        notification_router=notification_router,
        app_store=app_store,
        secret_fn=_ecosystem_secret_or_empty,
    )
    # A command waiting on an approval that expires will not run; say so on its record.
    approval_service.on_expired = lambda rec: command_dispatcher.mark_approval_closed(rec, outcome="expired")
    closed = command_dispatcher.reconcile_closed_approvals()
    if closed:
        logger.info("%d command(s) closed because their approval had been denied or had expired", closed)

    # Stash on app.state so request handlers resolve them via dependencies
    # rather than module globals (which could be None before startup).
    app.state.registry = registry
    app.state.health_monitor = health_monitor
    app.state.event_bus = event_bus
    app.state.ai_profile_store = ai_profile_store
    app.state.app_store = app_store
    app.state.provider_credential_store = provider_credential_store
    app.state.capability_registry = capability_registry
    app.state.notification_router = notification_router
    app.state.policy_engine = policy_engine
    app.state.step_up_auth = step_up_auth
    app.state.approval_service = approval_service
    app.state.scan_runner = scan_runner
    app.state.scan_scheduler = scan_scheduler
    app.state.command_dispatcher = command_dispatcher

    logger.info("Ecosystem registry started")
    yield

    await scan_scheduler.stop()
    await approval_service.stop()
    await health_monitor.stop()
    if event_bus:
        await event_bus.close()
    logger.info("Ecosystem registry stopped")


def get_registry(request: Request) -> ServiceRegistry:
    """Dependency: resolve the registry, 503 if startup has not completed."""
    registry = getattr(request.app.state, "registry", None)
    if registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Registry not initialized",
        )
    return registry


def get_health_monitor(request: Request) -> HealthMonitor:
    """Dependency: resolve the health monitor, 503 if startup has not completed."""
    monitor = getattr(request.app.state, "health_monitor", None)
    if monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Health monitor not initialized",
        )
    return monitor


def get_profile_store(request: Request):
    """Dependency: resolve the AI profile store, 503 before startup completes."""
    store = getattr(request.app.state, "ai_profile_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI profile store not initialized",
        )
    return store


def get_capability_registry(request: Request):
    """Dependency: resolve the capability registry, 503 before startup completes."""
    cap_reg = getattr(request.app.state, "capability_registry", None)
    if cap_reg is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Capability registry not initialized",
        )
    return cap_reg


def get_notification_router(request: Request):
    """Dependency: resolve the notification router, 503 before startup completes."""
    router = getattr(request.app.state, "notification_router", None)
    if router is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Notification router not initialized",
        )
    return router


def _read_auth_required() -> bool:
    """Whether read endpoints (service listings) require authentication.

    Off by default so discovery stays frictionless on a trusted/loopback
    network; enable with ECOSYSTEM_REQUIRE_READ_AUTH to avoid leaking topology.
    """
    return os.environ.get("ECOSYSTEM_REQUIRE_READ_AUTH", "false").lower() in (
        "1", "true", "yes",
    )


def _key_resolver(request: Request):
    """Build a per-app key resolver from the request's AppStore (or None)."""
    store = getattr(request.app.state, "app_store", None)
    if store is None:
        return None

    def resolve(key_id: str):
        return store.get_by_key_id(key_id)  # None if unknown/suspended

    return resolve


async def require_registry_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> dict:
    """Registry auth: per-app key when present, else shared-secret owner."""
    return await authenticate_request(request, credentials, key_resolver=_key_resolver(request))


def require_name_owner(name: str, auth: dict) -> None:
    """403 unless the caller owns `name` (owner may use any non-collision name)."""
    owned = auth.get("owned_names", [])
    if owned == ["*"]:
        return
    if name in RESERVED_NAMES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"'{name}' is a reserved first-party service name",
        )
    if name not in owned:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"app '{auth.get('app_id')}' does not own service name '{name}'",
        )


async def require_read_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
):
    """Conditionally enforce ecosystem auth on read endpoints."""
    if not _read_auth_required():
        return None
    return await require_registry_auth(request, credentials)


app = FastAPI(
    title="Ecosystem Registry",
    version="0.3.0",
    description="Service discovery and health monitoring for the app ecosystem",
    lifespan=lifespan,
)

def _cors_origins() -> list[str]:
    """Resolve allowed CORS origins from the environment.

    Defaults to "*" for local development but should be set to an explicit,
    comma-separated origin list in production.
    """
    raw = os.environ.get("ECOSYSTEM_CORS_ORIGINS", "*").strip()
    if raw == "*" or not raw:
        return ["*"]
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Ecosystem-Signature",
        "X-Ecosystem-Timestamp",
        "X-Ecosystem-Nonce",
        "X-Ecosystem-Step-Up",
    ],
)

from .policy_routes import router as policy_router
from .scan_routes import router as scan_router
from .command_routes import router as command_router


def _ensure_voice_pkg():
    import sys
    from pathlib import Path
    voice_pkg = Path(__file__).resolve().parent.parent / "packages" / "ecosystem-voice"
    if voice_pkg.is_dir() and str(voice_pkg) not in sys.path:
        sys.path.insert(0, str(voice_pkg))


_ensure_voice_pkg()
from ecosystem_voice import router as voice_router

app.include_router(policy_router)
app.include_router(scan_router)
app.include_router(command_router)
app.include_router(voice_router)


@app.get("/", include_in_schema=False)
async def root_redirect():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/ui")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    from fastapi import Response
    return Response(status_code=204)


@app.get("/health")
async def health():
    """Registry's own health endpoint."""
    return {"status": "healthy", "service": "ecosystem-registry"}


@app.get("/metrics")
async def metrics_endpoint(request: Request):
    """Prometheus-format metrics (counters + live service gauges)."""
    from . import metrics
    from fastapi.responses import PlainTextResponse

    reg = getattr(request.app.state, "registry", None)
    return PlainTextResponse(metrics.render_prometheus(reg))


@app.get("/ai-profile")
async def get_ai_profile(
    store=Depends(get_profile_store),
    _auth=Depends(require_read_auth),
):
    """Return the shared ecosystem AI/LLM profile (the synced source of truth)."""
    return store.get()


@app.get("/ai-placement")
async def ai_placement(
    registry: ServiceRegistry = Depends(get_registry),
    _auth=Depends(require_read_auth),
):
    """Recommend the best host for LLM workloads from reported resources.

    Returns null when no registered service has reported its hardware."""
    from .placement import recommend_llm_host
    return recommend_llm_host(registry.get_all())


@app.put("/ai-profile")
async def update_ai_profile(
    changes: dict,
    request: Request,
    auth: dict = Depends(require_registry_auth),
    store=Depends(get_profile_store),
):
    """Apply changes to the shared AI profile, bump its version, and broadcast an
    `ecosystem.ai_profile_changed` event so other apps update live.

    Owner-only in Phase 1: the shared AI profile is a trust-critical surface, so
    third-party (enrolled) keys are rejected regardless of scope."""
    if auth.get("app_id") != "__owner__":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="AI profile changes are owner-only",
        )
    updated_by = (auth or {}).get("app_id") or "unknown"
    profile = store.update(changes, updated_by=updated_by)

    event_bus = getattr(request.app.state, "event_bus", None)
    if event_bus:
        try:
            from events.schemas import EventEnvelope
            await event_bus.publish(EventEnvelope(
                type="ecosystem.ai_profile_changed",
                source="registry",
                data={
                    "version": profile.get("version"),
                    "updated_by": updated_by,
                    "changed": [k for k in changes if k in profile],
                    "profile": profile,
                },
            ))
        except Exception as e:
            logger.debug("Failed to publish ai_profile_changed event: %s", e)

    return profile


class ProviderKeyBody(BaseModel):
    api_key: str


def _provider_store(request: Request) -> ProviderCredentialStore:
    return request.app.state.provider_credential_store


def _require_loopback(request: Request) -> None:
    """Key writes are loopback-only, 404-cloaked (mirrors the secret endpoints).

    A forwarded header means the request crossed a proxy, so it is not a genuine
    local caller even when request.client.host looks local. 404 (not 403) so the
    existence of these write routes isn't disclosed to a remote caller.
    """
    if request.headers.get("x-forwarded-for"):
        raise HTTPException(status_code=404, detail="Not Found")
    host = (request.client.host if request.client else "") or ""
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(status_code=404, detail="Not Found")


@app.get("/ai/providers")
async def list_provider_keys(
    request: Request,
    _auth=Depends(require_read_auth),
):
    """Non-secret status for every supported provider. Never returns a key."""
    return {"providers": _provider_store(request).status()}


@app.put("/ai/providers/{provider}/key")
async def set_provider_key(
    provider: str,
    request: Request,
    body: ProviderKeyBody = Body(...),
    auth: dict = Depends(require_registry_auth),
):
    """Store (or replace) a provider's API key.

    Loopback-only AND registry-auth-gated: loopback stops remote callers,
    auth stops unauthorized local ones (e.g. a different local user/process).
    """
    _require_loopback(request)
    store = _provider_store(request)
    try:
        store.set_key(provider, body.api_key)
    except ValueError as e:
        # ValueError text is about the provider name or emptiness - never the key.
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "stored", "provider": provider, "last4": store.status()[provider]["last4"]}


@app.delete("/ai/providers/{provider}/key")
async def delete_provider_key(
    provider: str,
    request: Request,
    auth: dict = Depends(require_registry_auth),
):
    """Remove a provider's stored API key, if any.

    Loopback-only AND registry-auth-gated (see set_provider_key)."""
    _require_loopback(request)
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider {provider!r}")
    removed = _provider_store(request).delete_key(provider)
    return {"status": "deleted" if removed else "not_found", "provider": provider}


@app.post("/register", response_model=ServiceRecord, status_code=status.HTTP_201_CREATED)
async def register_service(
    registration: ServiceRegistration,
    auth: dict = Depends(require_registry_auth),
    registry: ServiceRegistry = Depends(get_registry),
):
    """Register a new service with the ecosystem."""
    require_name_owner(registration.name, auth)
    record = registry.register(registration)
    return record


@app.delete("/deregister/{name}")
async def deregister_service(
    name: str,
    request: Request,
    auth: dict = Depends(require_registry_auth),
    registry: ServiceRegistry = Depends(get_registry),
):
    """Remove a service from the registry and withdraw its advertised capabilities."""
    require_name_owner(name, auth)
    if not registry.deregister(name):
        raise HTTPException(status_code=404, detail=f"Service '{name}' not found")

    cap_reg = getattr(request.app.state, "capability_registry", None)
    if cap_reg is not None:
        withdrawn = cap_reg.withdraw_provider(
            name,
            reason=f"Provider '{name}' deregistered",
        )
        event_bus = getattr(request.app.state, "event_bus", None)
        if withdrawn and event_bus:
            _schedule_bus_event(
                request,
                event_type="capability.withdrawn",
                source="registry",
                data={
                    "app": name,
                    "capabilities": [r["capability"] for r in withdrawn],
                    "reason": f"Provider '{name}' deregistered",
                },
            )
    return {"status": "deregistered", "name": name}


@app.get("/services", response_model=list[ServiceRecord])
async def list_services(
    registry: ServiceRegistry = Depends(get_registry),
    _auth=Depends(require_read_auth),
):
    """List all registered services."""
    return registry.get_all()


@app.get("/services/priority", response_model=list[ServiceRecord])
async def list_services_by_priority(
    registry: ServiceRegistry = Depends(get_registry),
    _auth=Depends(require_read_auth),
):
    """List all services sorted by priority (highest first, healthy first)."""
    return registry.get_by_priority()


@app.get("/services/{name}", response_model=ServiceRecord)
async def get_service(
    name: str,
    registry: ServiceRegistry = Depends(get_registry),
    _auth=Depends(require_read_auth),
):
    """Get a specific service by name."""
    record = registry.get(name)
    if not record:
        raise HTTPException(status_code=404, detail=f"Service '{name}' not found")
    return record


@app.get("/services/{name}/health", response_model=HealthCheckResult)
async def check_service_health(
    name: str,
    registry: ServiceRegistry = Depends(get_registry),
    health_monitor: HealthMonitor = Depends(get_health_monitor),
    _auth=Depends(require_read_auth),
):
    """Run an on-demand health check for a specific service."""
    record = registry.get(name)
    if not record:
        raise HTTPException(status_code=404, detail=f"Service '{name}' not found")
    result = await health_monitor.check_one(name)
    return result


@app.post("/events/publish")
async def publish_event(request: Request, envelope: dict = Body(...)):
    """
    Accept a signed event from an ecosystem service and fan it out to subscribers.

    This is the registry-side counterpart of ecosystem-client's registry-mode
    publisher (`event_publisher.py::_publish_via_registry`), which POSTs here. The
    client had no fallback, so before this route existed every cross-app event 404'd
    and was silently dropped (see todos_changelog.md, 2026-07-25).

    Auth: the event is HMAC-signed by the publisher (the envelope's `signature`
    field). We verify it against the shared ecosystem secret — no separate
    Authorization credential — then delegate to the existing EventBus, which
    re-signs and delivers to each subscriber's webhook by subscription.
    """
    event_bus = getattr(request.app.state, "event_bus", None)
    if event_bus is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="event bus not configured",
        )

    from events.schemas import EventEnvelope
    from ecosystem_auth.tokens import verify_signature

    try:
        event = EventEnvelope(**envelope)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="invalid event envelope",
        )

    if not event.signature or not verify_signature(
        event.signable_dict(), event.signature, event_bus.hmac_secret
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing event signature",
        )

    # Accept-and-ack: fan out to subscribers in the BACKGROUND. A publish to the
    # bus must never block on subscriber delivery — awaiting it here meant a slow
    # or unreachable subscriber (its own retries: 3 x 5s) made every publish
    # exceed the client's 5s request_timeout, so the publisher logged a
    # ReadTimeout warning per event (log spam) even though the event was valid.
    # The bus already has per-subscriber retries + logging; we only ack acceptance.
    task = asyncio.create_task(event_bus.publish(event))
    _pending = getattr(request.app.state, "_event_delivery_tasks", None)
    if _pending is None:
        _pending = set()
        request.app.state._event_delivery_tasks = _pending
    _pending.add(task)
    task.add_done_callback(_pending.discard)
    return {"queued": True}


def _schedule_bus_event(
    request: Request,
    *,
    event_type: str,
    source: str | dict,
    data: dict,
) -> None:
    """Queue an internal EventBus fan-out task without blocking the HTTP response."""
    event_bus = getattr(request.app.state, "event_bus", None)
    if event_bus is None:
        return
    try:
        from events.schemas import EventEnvelope

        event = EventEnvelope(type=event_type, source=source, data=data)
        task = asyncio.create_task(event_bus.publish(event))
        pending = getattr(request.app.state, "_event_delivery_tasks", None)
        if pending is None:
            pending = set()
            request.app.state._event_delivery_tasks = pending
        pending.add(task)
        task.add_done_callback(pending.discard)
    except Exception as exc:
        logger.debug("Failed to schedule internal bus event %s: %r", event_type, exc)


# ---- Phase 2: Capability Registry Endpoints ------------------------------


@app.post("/capabilities/register", status_code=status.HTTP_201_CREATED)
async def register_capabilities(
    request: Request,
    payload: dict = Body(...),
    auth: dict = Depends(require_registry_auth),
    cap_reg=Depends(get_capability_registry),
):
    """Register one or more project-contributed capability manifests."""
    from ecosystem_client.contracts import SchemaValidationError

    raw_items = payload.get("capabilities") if "capabilities" in payload else [payload]
    if not isinstance(raw_items, list) or not raw_items:
        raise HTTPException(status_code=400, detail="capabilities must be a non-empty list or manifest")

    records = []
    for item in raw_items:
        if not isinstance(item, dict):
            raise HTTPException(status_code=422, detail="Each capability manifest must be an object")
        provider = item.get("provider") or {}
        provider_app = provider.get("app", "") if isinstance(provider, dict) else ""
        if not provider_app:
            raise HTTPException(status_code=422, detail="provider.app is required")
        require_name_owner(provider_app, auth)
        try:
            rec = cap_reg.register(item)
        except SchemaValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        records.append(rec)
        _schedule_bus_event(
            request,
            event_type="capability.registered",
            source={"app": provider_app, "device_id": provider.get("device_id", "local-device")},
            data={"capability": rec["capability"], "manifest": rec["manifest"]},
        )

    return {"registered": records}


@app.get("/capabilities")
async def list_or_resolve_capabilities(
    action_class: Optional[str] = None,
    app_name: Optional[str] = None,
    capability: Optional[str] = None,
    active_only: bool = True,
    resolve: bool = False,
    cap_reg=Depends(get_capability_registry),
    _auth=Depends(require_read_auth),
):
    """List registered capabilities or resolve availability/unavailability reason for one capability."""
    if resolve and capability:
        return cap_reg.resolve(capability).to_dict()
    return {
        "capabilities": cap_reg.list_capabilities(
            action_class=action_class,
            app=app_name,
            capability=capability,
            active_only=active_only,
        )
    }


@app.delete("/capabilities/{service_name}")
async def withdraw_service_capabilities(
    service_name: str,
    request: Request,
    auth: dict = Depends(require_registry_auth),
    cap_reg=Depends(get_capability_registry),
):
    """Withdraw all active capabilities owned by `service_name`."""
    require_name_owner(service_name, auth)
    affected = cap_reg.withdraw_provider(
        service_name,
        reason=f"Capabilities withdrawn by provider '{service_name}'",
    )
    if affected:
        _schedule_bus_event(
            request,
            event_type="capability.withdrawn",
            source=service_name,
            data={"app": service_name, "capabilities": [r["capability"] for r in affected]},
        )
    return {"status": "withdrawn", "app": service_name, "count": len(affected)}


@app.delete("/capabilities/{service_name}/{capability_name}")
async def withdraw_single_capability(
    service_name: str,
    capability_name: str,
    request: Request,
    auth: dict = Depends(require_registry_auth),
    cap_reg=Depends(get_capability_registry),
):
    """Withdraw a specific capability owned by `service_name`."""
    require_name_owner(service_name, auth)
    count = cap_reg.withdraw(capability_name, service_name)
    if count:
        _schedule_bus_event(
            request,
            event_type="capability.withdrawn",
            source=service_name,
            data={"app": service_name, "capabilities": [capability_name]},
        )
    return {"status": "withdrawn", "app": service_name, "capability": capability_name, "count": count}


# ---- Phase 2: Cross-Device Notification Router Endpoints -----------------


@app.post("/notifications/publish")
async def publish_notification(
    request: Request,
    envelope: dict = Body(...),
    auth: dict = Depends(require_registry_auth),
    router=Depends(get_notification_router),
):
    """Deduplicate, redact, apply quiet hours, and fan out a `notify.*` envelope across devices."""
    from ecosystem_client.contracts import SchemaValidationError

    src = envelope.get("source") or {}
    src_app = src.get("app", "") if isinstance(src, dict) else ""
    if src_app:
        require_name_owner(src_app, auth)

    try:
        result = await router.route(envelope)
    except SchemaValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if result["status"] == "routed" and envelope.get("privacy") != "local_only":
        _schedule_bus_event(
            request,
            event_type=envelope["type"],
            source=envelope["source"],
            data={k: v for k, v in envelope.items() if k != "signature"},
        )

    return result


@app.post("/notifications/subscriptions", status_code=status.HTTP_201_CREATED)
async def upsert_notification_subscription(
    sub: dict = Body(...),
    auth: dict = Depends(require_registry_auth),
    router=Depends(get_notification_router),
):
    """Register or update a user/device notification subscription or federated mobile push sink."""
    sub_id = str(sub.get("subscriber_id") or sub.get("device") or "").strip()
    if auth.get("owned_names") != ["*"]:
        require_name_owner(sub_id, auth)
    try:
        record = router.upsert_subscription(sub)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return record


@app.get("/notifications/subscriptions")
async def list_notification_subscriptions(
    _auth: dict = Depends(require_registry_auth),
    router=Depends(get_notification_router),
):
    """List configured notification subscriptions (with tokens redacted)."""
    return {"subscriptions": router.list_subscriptions(include_secrets=False)}


@app.delete("/notifications/subscriptions/{subscriber_id}")
async def delete_notification_subscription(
    subscriber_id: str,
    auth: dict = Depends(require_registry_auth),
    router=Depends(get_notification_router),
):
    if auth.get("owned_names") != ["*"]:
        require_name_owner(subscriber_id, auth)
    removed = router.delete_subscription(subscriber_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Subscription {subscriber_id!r} not found")
    return {"status": "deleted", "subscriber_id": subscriber_id}


@app.get("/notifications/recent")
async def list_recent_notifications(
    limit: int = 50,
    min_severity: Optional[str] = None,
    _auth=Depends(require_read_auth),
    router=Depends(get_notification_router),
):
    """Return recent non-local-only notifications for dashboards and companion mobile apps."""
    return {
        "notifications": router.recent_notifications(
            limit=limit,
            include_local_only=False,
            min_severity=min_severity,
        )
    }


def _register_static_projects(reg: ServiceRegistry) -> None:
    """Pre-register projects defined in ecosystem.yaml that are present locally.

    Subset/multi-device tolerance: only projects whose repo actually exists on
    this device are pre-registered, so a partial install does not show
    not-installed apps as "unhealthy". Apps deployed on other devices self-
    register over the network when they start. Set
    ``ECOSYSTEM_REGISTER_ALL_STATIC=1`` to force pre-registering every project
    regardless of local presence (e.g. a single-host dev box with all repos)."""
    try:
        import yaml
        from pathlib import Path

        config_path = os.environ.get("ECOSYSTEM_CONFIG", "ecosystem.yaml")
        if not os.path.exists(config_path):
            return
        with open(config_path) as f:
            config = yaml.safe_load(f)

        # In lan mode, loopback hosts in committed config are advertised on this
        # host's LAN IP so other devices can health-check co-located services.
        try:
            from ecosystem_client.topology import resolve_static_host
        except Exception:
            def resolve_static_host(host: str) -> str:  # type: ignore
                return host or "localhost"

        # Resolve the sibling-repo base path the same way the CLI does so the
        # local-presence check matches where apps are actually installed.
        register_all = os.environ.get(
            "ECOSYSTEM_REGISTER_ALL_STATIC", ""
        ).lower() in ("1", "true", "yes")
        base_str = (
            os.environ.get("ECOSYSTEM_BASE_PATH")
            or (config.get("ecosystem") or {}).get("base_path", "")
        )
        # ecosystem.yaml lives at <repo>/ecosystem.yaml; siblings live in <repo>/..
        base = Path(base_str) if base_str else Path(config_path).resolve().parent.parent

        for key, proj in (config.get("projects") or {}).items():
            # Validate per-project so one malformed entry doesn't abort the
            # entire static load.
            if "port" not in proj:
                logger.warning(f"Skipping static project '{key}': missing 'port'")
                continue
            rel_path = proj.get("path")
            if not register_all and rel_path and not (base / rel_path).exists():
                logger.info(
                    "Skipping static project '%s': not installed locally (%s). "
                    "It will appear if it self-registers from its own device.",
                    key, base / rel_path,
                )
                continue
            try:
                reg.register(
                    ServiceRegistration(
                        name=key,
                        host=resolve_static_host(proj.get("host", "localhost")),
                        port=proj["port"],
                        health_endpoint=proj.get("health_endpoint", "/health"),
                        priority=proj.get("priority", 0),
                        metadata={"stack": proj.get("stack", ""), "description": proj.get("description", "")},
                        static=True,
                    )
                )
                logger.info(f"Pre-registered static project: {key}")
            except Exception as e:
                logger.warning(f"Skipping invalid static project '{key}': {e}")
    except Exception as e:
        logger.warning(f"Could not load static projects: {e}")
