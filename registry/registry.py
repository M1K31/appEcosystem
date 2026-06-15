"""In-memory service registry with JSON file persistence."""

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from .models import HealthStatus, ServiceRecord, ServiceRegistration

logger = logging.getLogger(__name__)


class ServiceRegistry:
    """
    Manages service registrations in memory with optional JSON persistence.

    Services register with their connection details and health endpoints.
    The registry tracks health status and persists state to a JSON file.
    """

    def __init__(self, persistence_path: Optional[str] = None):
        self._services: dict[str, ServiceRecord] = {}
        self._persistence_path = persistence_path
        if persistence_path:
            self._load()

    def register(self, registration: ServiceRegistration) -> ServiceRecord:
        """Register a service or update an existing registration."""
        base_url = f"http://{registration.host}:{registration.port}"
        record = ServiceRecord(
            name=registration.name,
            host=registration.host,
            port=registration.port,
            health_endpoint=registration.health_endpoint,
            base_url=base_url,
            webhook_url=registration.webhook_url,
            subscriptions=registration.subscriptions,
            metadata=registration.metadata,
            priority=registration.priority,
            static=registration.static,
            status=HealthStatus.UNKNOWN,
            registered_at=time.time(),
        )
        self._services[registration.name] = record
        self._persist()
        logger.info(f"Registered service: {registration.name} at {base_url}")
        return record

    def deregister(self, name: str) -> bool:
        """Remove a service from the registry."""
        if name in self._services:
            del self._services[name]
            self._persist()
            logger.info(f"Deregistered service: {name}")
            return True
        return False

    def get(self, name: str) -> Optional[ServiceRecord]:
        """Get a service record by name."""
        return self._services.get(name)

    def get_all(self) -> list[ServiceRecord]:
        """Get all registered services."""
        return list(self._services.values())

    def get_by_priority(self) -> list[ServiceRecord]:
        """Get all services sorted by priority (highest first), healthy first."""
        return sorted(
            self._services.values(),
            key=lambda s: (
                s.status == HealthStatus.HEALTHY,  # healthy first
                s.priority,                         # then by priority
            ),
            reverse=True,
        )

    def update_health(
        self,
        name: str,
        status: HealthStatus,
        response_time_ms: Optional[float] = None,
    ) -> Optional[ServiceRecord]:
        """Update health status for a service."""
        record = self._services.get(name)
        if not record:
            return None

        now = time.time()
        record.status = status
        record.last_health_check = now

        if status == HealthStatus.HEALTHY:
            record.last_healthy = now
            record.consecutive_failures = 0
        else:
            record.consecutive_failures += 1

        self._persist()
        return record

    def get_subscribers(self, event_type: str) -> list[ServiceRecord]:
        """Get all services subscribed to an event type (supports wildcards)."""
        subscribers = []
        for service in self._services.values():
            if not service.webhook_url:
                continue
            for pattern in service.subscriptions:
                if self._matches_pattern(event_type, pattern):
                    subscribers.append(service)
                    break
        return subscribers

    @staticmethod
    def _matches_pattern(event_type: str, pattern: str) -> bool:
        """Check if an event type matches a subscription pattern."""
        if pattern == "*":
            return True
        if pattern.endswith(".*"):
            prefix = pattern[:-2]
            return event_type.startswith(prefix + ".")
        return event_type == pattern

    def _persist(self) -> None:
        """Save registry state to JSON file."""
        if not self._persistence_path:
            return
        try:
            path = Path(self._persistence_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                name: record.model_dump() for name, record in self._services.items()
            }
            path.write_text(json.dumps(data, indent=2, default=str))
        except Exception as e:
            logger.error(f"Failed to persist registry: {e}")

    def _load(self) -> None:
        """Load registry state from JSON file."""
        if not self._persistence_path:
            return
        path = Path(self._persistence_path)
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            for name, record_data in data.items():
                self._services[name] = ServiceRecord(**record_data)
            logger.info(f"Loaded {len(self._services)} services from {path}")
        except Exception as e:
            logger.error(f"Failed to load registry: {e}")
