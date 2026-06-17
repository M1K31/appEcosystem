"""Lightweight, dependency-free metrics for the registry.

Exposes counters incremented across the registry/health-monitor/event-bus and
renders them, alongside live gauges, in Prometheus text exposition format. No
external client library is required.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .registry import ServiceRegistry
    from .models import HealthStatus

_lock = threading.Lock()
_counters: dict[str, int] = {}

# Counter names (monotonic).
HEALTH_CHECKS = "ecosystem_health_checks_total"
HEALTH_CHECK_FAILURES = "ecosystem_health_check_failures_total"
EVENTS_PUBLISHED = "ecosystem_events_published_total"
EVENTS_DELIVERED = "ecosystem_events_delivered_total"
EVENTS_FAILED = "ecosystem_events_failed_total"
AUTO_DEREGISTRATIONS = "ecosystem_auto_deregistrations_total"

_COUNTER_HELP = {
    HEALTH_CHECKS: "Total health checks performed.",
    HEALTH_CHECK_FAILURES: "Total health checks that returned non-healthy.",
    EVENTS_PUBLISHED: "Total events published to the event bus.",
    EVENTS_DELIVERED: "Total successful event webhook deliveries.",
    EVENTS_FAILED: "Total failed event webhook deliveries.",
    AUTO_DEREGISTRATIONS: "Total services auto-deregistered after failures.",
}


def inc(name: str, n: int = 1) -> None:
    """Increment a counter by ``n`` (thread-safe)."""
    if n <= 0:
        return
    with _lock:
        _counters[name] = _counters.get(name, 0) + n


def snapshot() -> dict[str, int]:
    """Return a copy of all counters (with known counters defaulted to 0)."""
    with _lock:
        data = {name: 0 for name in _COUNTER_HELP}
        data.update(_counters)
        return data


def reset() -> None:
    """Clear all counters (used by tests)."""
    with _lock:
        _counters.clear()


def render_prometheus(registry: "ServiceRegistry | None") -> str:
    """Render counters and live registry gauges in Prometheus text format."""
    from .models import HealthStatus

    lines: list[str] = []

    lines.append("# HELP ecosystem_registry_up Registry process is serving.")
    lines.append("# TYPE ecosystem_registry_up gauge")
    lines.append("ecosystem_registry_up 1")

    counters = snapshot()
    for name, value in sorted(counters.items()):
        lines.append(f"# HELP {name} {_COUNTER_HELP.get(name, name)}")
        lines.append(f"# TYPE {name} counter")
        lines.append(f"{name} {value}")

    # Live gauge: registered services by status.
    if registry is not None:
        counts = {status.value: 0 for status in HealthStatus}
        for record in registry.get_all():
            counts[record.status.value] = counts.get(record.status.value, 0) + 1
        lines.append("# HELP ecosystem_services Registered services by status.")
        lines.append("# TYPE ecosystem_services gauge")
        for status_value, count in sorted(counts.items()):
            lines.append(f'ecosystem_services{{status="{status_value}"}} {count}')

    return "\n".join(lines) + "\n"
