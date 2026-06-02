"""FastAPI application for the ecosystem service registry."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from auth.python.ecosystem_auth.middleware import require_ecosystem_auth

from .health_monitor import HealthMonitor
from .models import HealthCheckResult, ServiceRecord, ServiceRegistration
from .registry import ServiceRegistry

if TYPE_CHECKING:
    from events.event_bus import EventBus

logger = logging.getLogger(__name__)

# Module-level singletons initialized in lifespan
registry: ServiceRegistry = None  # type: ignore
health_monitor: HealthMonitor = None  # type: ignore
event_bus: EventBus = None  # type: ignore


@asynccontextmanager
async def lifespan(app: FastAPI):
    global registry, health_monitor, event_bus

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

    logger.info("Ecosystem registry started")
    yield

    await health_monitor.stop()
    if event_bus:
        await event_bus.close()
    logger.info("Ecosystem registry stopped")


app = FastAPI(
    title="Ecosystem Registry",
    version="0.1.0",
    description="Service discovery and health monitoring for the app ecosystem",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    """Registry's own health endpoint."""
    return {"status": "healthy", "service": "ecosystem-registry"}


@app.post("/register", response_model=ServiceRecord, status_code=status.HTTP_201_CREATED)
async def register_service(
    registration: ServiceRegistration,
    auth: dict = Depends(require_ecosystem_auth),
):
    """Register a new service with the ecosystem."""
    record = registry.register(registration)
    return record


@app.delete("/deregister/{name}")
async def deregister_service(
    name: str,
    auth: dict = Depends(require_ecosystem_auth),
):
    """Remove a service from the registry."""
    if not registry.deregister(name):
        raise HTTPException(status_code=404, detail=f"Service '{name}' not found")
    return {"status": "deregistered", "name": name}


@app.get("/services", response_model=list[ServiceRecord])
async def list_services():
    """List all registered services."""
    return registry.get_all()


@app.get("/services/priority", response_model=list[ServiceRecord])
async def list_services_by_priority():
    """List all services sorted by priority (highest first, healthy first)."""
    return registry.get_by_priority()


@app.get("/services/{name}", response_model=ServiceRecord)
async def get_service(name: str):
    """Get a specific service by name."""
    record = registry.get(name)
    if not record:
        raise HTTPException(status_code=404, detail=f"Service '{name}' not found")
    return record


@app.get("/services/{name}/health", response_model=HealthCheckResult)
async def check_service_health(name: str):
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
            reg.register(
                ServiceRegistration(
                    name=key,
                    host=proj.get("host", "localhost"),
                    port=proj["port"],
                    health_endpoint=proj.get("health_endpoint", "/health"),
                    priority=proj.get("priority", 0),
                    metadata={"stack": proj.get("stack", ""), "description": proj.get("description", "")},
                )
            )
            logger.info(f"Pre-registered static project: {key}")
    except Exception as e:
        logger.warning(f"Could not load static projects: {e}")
