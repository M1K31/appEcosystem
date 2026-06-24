"""Webhook-based event bus with HMAC signing, async fan-out, and retry."""

import asyncio
import logging
from typing import Optional

import httpx

from .schemas import EventEnvelope

logger = logging.getLogger(__name__)


class EventBus:
    """
    Publishes events to subscriber webhooks via HTTP POST.

    Features:
    - HMAC-SHA256 signing of payloads
    - Async fan-out to all matching subscribers
    - Retry with configurable attempts and delay
    """

    def __init__(
        self,
        registry=None,
        hmac_secret: Optional[str] = None,
        retry_attempts: int = 3,
        retry_delay: float = 5.0,
        timeout: float = 10.0,
    ):
        from ecosystem_auth.tokens import get_ecosystem_secret

        self.registry = registry
        self.hmac_secret = get_ecosystem_secret(hmac_secret)
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)

    async def close(self) -> None:
        """Close the persistent HTTP connection pool."""
        await self._client.aclose()

    async def publish(self, event: EventEnvelope) -> dict:
        """
        Publish an event to all subscribed services.

        Signs the event payload and delivers via HTTP POST to each
        subscriber's webhook_url. Returns delivery results.
        """
        # Sign the event
        from ecosystem_auth.tokens import sign_payload

        event.signature = sign_payload(event.signable_dict(), self.hmac_secret)

        # Find subscribers
        if not self.registry:
            logger.warning("No registry attached - cannot deliver events")
            return {"delivered": 0, "failed": 0, "subscribers": []}

        subscribers = self.registry.get_subscribers(event.type)
        if not subscribers:
            logger.debug(f"No subscribers for event type: {event.type}")
            return {"delivered": 0, "failed": 0, "subscribers": []}

        # Fan out delivery
        tasks = [
            self._deliver(event, sub.webhook_url, sub.name)
            for sub in subscribers
            if sub.webhook_url
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        delivered = sum(1 for r in results if r is True)
        failed = len(results) - delivered

        self._record_metrics(delivered, failed)

        if failed:
            logger.warning(
                f"Event {event.type} delivery: {delivered} ok, {failed} failed"
            )

        return {
            "delivered": delivered,
            "failed": failed,
            "subscribers": [s.name for s in subscribers],
        }

    @staticmethod
    def _record_metrics(delivered: int, failed: int) -> None:
        """Record delivery metrics. Soft dependency: no-op if registry.metrics
        is unavailable so the event bus stays usable standalone."""
        try:
            from registry import metrics
        except Exception:
            return
        metrics.inc(metrics.EVENTS_PUBLISHED)
        metrics.inc(metrics.EVENTS_DELIVERED, delivered)
        metrics.inc(metrics.EVENTS_FAILED, failed)

    async def _deliver(
        self, event: EventEnvelope, webhook_url: str, service_name: str
    ) -> bool:
        """Deliver an event to a single webhook with retry."""
        payload = event.model_dump()
        headers = {
            "Content-Type": "application/json",
            "X-Ecosystem-Signature": event.signature or "",
            "X-Ecosystem-Event": event.type,
            "X-Ecosystem-Source": event.source,
        }

        for attempt in range(1, self.retry_attempts + 1):
            try:
                resp = await self._client.post(webhook_url, json=payload, headers=headers)
                if resp.status_code < 400:
                    logger.debug(
                        f"Delivered {event.type} to {service_name} (attempt {attempt})"
                    )
                    return True
                logger.warning(
                    f"Webhook {service_name} returned {resp.status_code} (attempt {attempt})"
                )
            except Exception as e:
                logger.warning(
                    f"Webhook delivery to {service_name} failed (attempt {attempt}): {e}"
                )

            if attempt < self.retry_attempts:
                await asyncio.sleep(self.retry_delay)

        logger.error(
            f"Failed to deliver {event.type} to {service_name} after {self.retry_attempts} attempts"
        )
        return False
