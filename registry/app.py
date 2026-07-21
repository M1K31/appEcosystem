"""FastAPI application for the ecosystem service registry."""

from __future__ import annotations

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    from .logging_config import configure_logging
    configure_logging()

    persistence_path = os.environ.get(
        "ECOSYSTEM_REGISTRY_FILE", "data/registry.json"
    )
    registry = ServiceRegistry(persistence_path=persistence_path)

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

    # Stash on app.state so request handlers resolve them via dependencies
    # rather than module globals (which could be None before startup).
    app.state.registry = registry
    app.state.health_monitor = health_monitor
    app.state.event_bus = event_bus
    app.state.ai_profile_store = ai_profile_store
    app.state.app_store = app_store
    app.state.provider_credential_store = provider_credential_store

    logger.info("Ecosystem registry started")
    yield

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
    allow_headers=["Authorization", "Content-Type", "X-Ecosystem-Signature"],
)


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
    auth: dict = Depends(require_registry_auth),
    registry: ServiceRegistry = Depends(get_registry),
):
    """Remove a service from the registry."""
    require_name_owner(name, auth)
    if not registry.deregister(name):
        raise HTTPException(status_code=404, detail=f"Service '{name}' not found")
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
