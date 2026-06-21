"""FastAPI application for the ecosystem service registry."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from typing import Optional

from fastapi import FastAPI, HTTPException, Request, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials
from auth.python.ecosystem_auth.middleware import require_ecosystem_auth, security_scheme

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

    # Stash on app.state so request handlers resolve them via dependencies
    # rather than module globals (which could be None before startup).
    app.state.registry = registry
    app.state.health_monitor = health_monitor
    app.state.event_bus = event_bus
    app.state.ai_profile_store = ai_profile_store

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


async def require_read_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
):
    """Conditionally enforce ecosystem auth on read endpoints."""
    if not _read_auth_required():
        return None
    return await require_ecosystem_auth(request, credentials)


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


@app.put("/ai-profile")
async def update_ai_profile(
    changes: dict,
    request: Request,
    auth: dict = Depends(require_ecosystem_auth),
    store=Depends(get_profile_store),
):
    """Apply changes to the shared AI profile, bump its version, and broadcast an
    `ecosystem.ai_profile_changed` event so other apps update live."""
    updated_by = (auth or {}).get("service") or "unknown"
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


@app.post("/register", response_model=ServiceRecord, status_code=status.HTTP_201_CREATED)
async def register_service(
    registration: ServiceRegistration,
    auth: dict = Depends(require_ecosystem_auth),
    registry: ServiceRegistry = Depends(get_registry),
):
    """Register a new service with the ecosystem."""
    record = registry.register(registration)
    return record


@app.delete("/deregister/{name}")
async def deregister_service(
    name: str,
    auth: dict = Depends(require_ecosystem_auth),
    registry: ServiceRegistry = Depends(get_registry),
):
    """Remove a service from the registry."""
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
    """Pre-register projects defined in ecosystem.yaml."""
    try:
        import yaml

        config_path = os.environ.get("ECOSYSTEM_CONFIG", "ecosystem.yaml")
        if not os.path.exists(config_path):
            return
        with open(config_path) as f:
            config = yaml.safe_load(f)

        for key, proj in (config.get("projects") or {}).items():
            # Validate per-project so one malformed entry doesn't abort the
            # entire static load.
            if "port" not in proj:
                logger.warning(f"Skipping static project '{key}': missing 'port'")
                continue
            try:
                reg.register(
                    ServiceRegistration(
                        name=key,
                        host=proj.get("host", "localhost"),
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
