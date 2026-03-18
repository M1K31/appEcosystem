"""Pydantic models for the service registry."""

import time
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class ServiceRegistration(BaseModel):
    """A service registering with the ecosystem registry."""

    name: str = Field(..., description="Unique service name (e.g., 'openeye')")
    host: str = Field(default="localhost")
    port: int = Field(..., ge=1, le=65535)
    health_endpoint: str = Field(default="/health")
    webhook_url: Optional[str] = Field(
        default=None,
        description="URL to receive event bus webhooks",
    )
    subscriptions: list[str] = Field(
        default_factory=list,
        description="Event types this service subscribes to (e.g., ['security.*'])",
    )
    metadata: dict = Field(default_factory=dict)
    priority: int = Field(default=0, description="Higher priority = preferred service (0=default)")


class ServiceRecord(BaseModel):
    """Internal record for a registered service, including health state."""

    name: str
    host: str
    port: int
    health_endpoint: str
    base_url: str
    webhook_url: Optional[str] = None
    subscriptions: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    priority: int = 0
    status: HealthStatus = HealthStatus.UNKNOWN
    last_health_check: Optional[float] = None
    last_healthy: Optional[float] = None
    registered_at: float = Field(default_factory=time.time)
    consecutive_failures: int = 0


class HealthCheckResult(BaseModel):
    """Result of a health check against a service."""

    service_name: str
    status: HealthStatus
    response_time_ms: Optional[float] = None
    detail: Optional[str] = None
    checked_at: float = Field(default_factory=time.time)
