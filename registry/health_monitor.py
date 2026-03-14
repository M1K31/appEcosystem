"""Async health poller for registered services."""

import asyncio
import logging
import time
from typing import Optional

import httpx

from .models import HealthCheckResult, HealthStatus
from .registry import ServiceRegistry

logger = logging.getLogger(__name__)


class HealthMonitor:
    """
    Background task that polls registered services' health endpoints.

    Runs on a configurable interval (default 30s). Updates the registry
    with each service's health status.
    """

    def __init__(
        self,
        registry: ServiceRegistry,
        interval_seconds: int = 30,
        timeout_seconds: int = 5,
    ):
        self.registry = registry
        self.interval = interval_seconds
        self.timeout = timeout_seconds
        self._task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self) -> None:
        """Start the health monitoring background task."""
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        logger.info(f"Health monitor started (interval={self.interval}s)")

    async def stop(self) -> None:
        """Stop the health monitoring background task."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Health monitor stopped")

    async def check_one(self, service_name: str) -> HealthCheckResult:
        """Run a single health check for a named service."""
        record = self.registry.get(service_name)
        if not record:
            return HealthCheckResult(
                service_name=service_name,
                status=HealthStatus.UNKNOWN,
                detail="Service not found in registry",
            )

        url = f"{record.base_url}{record.health_endpoint}"
        start = time.time()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url)
            elapsed_ms = (time.time() - start) * 1000

            if resp.status_code == 200:
                status = HealthStatus.HEALTHY
                detail = "OK"
            elif 200 < resp.status_code < 500:
                status = HealthStatus.DEGRADED
                detail = f"HTTP {resp.status_code}"
            else:
                status = HealthStatus.UNHEALTHY
                detail = f"HTTP {resp.status_code}"

        except httpx.TimeoutException:
            elapsed_ms = (time.time() - start) * 1000
            status = HealthStatus.UNHEALTHY
            detail = "Timeout"
        except httpx.ConnectError:
            elapsed_ms = (time.time() - start) * 1000
            status = HealthStatus.UNHEALTHY
            detail = "Connection refused"
        except Exception as e:
            elapsed_ms = (time.time() - start) * 1000
            status = HealthStatus.UNHEALTHY
            detail = str(e)

        self.registry.update_health(service_name, status)

        return HealthCheckResult(
            service_name=service_name,
            status=status,
            response_time_ms=round(elapsed_ms, 2),
            detail=detail,
        )

    async def check_all(self) -> list[HealthCheckResult]:
        """Run health checks for all registered services concurrently."""
        services = self.registry.get_all()
        if not services:
            return []
        tasks = [self.check_one(s.name) for s in services]
        return await asyncio.gather(*tasks)

    async def _poll_loop(self) -> None:
        """Main polling loop."""
        while self._running:
            try:
                results = await self.check_all()
                unhealthy = [r for r in results if r.status != HealthStatus.HEALTHY]
                if unhealthy:
                    names = ", ".join(r.service_name for r in unhealthy)
                    logger.warning(f"Unhealthy services: {names}")
            except Exception as e:
                logger.error(f"Health poll error: {e}")
            await asyncio.sleep(self.interval)
