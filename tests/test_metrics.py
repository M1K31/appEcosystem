"""Tests for the registry metrics module."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from registry import metrics
from registry.models import HealthStatus, ServiceRegistration
from registry.registry import ServiceRegistry


def test_inc_and_snapshot():
    metrics.reset()
    metrics.inc(metrics.HEALTH_CHECKS)
    metrics.inc(metrics.HEALTH_CHECKS, 2)
    metrics.inc(metrics.EVENTS_DELIVERED, 0)  # no-op
    snap = metrics.snapshot()
    assert snap[metrics.HEALTH_CHECKS] == 3
    assert snap[metrics.EVENTS_DELIVERED] == 0


def test_render_includes_gauges_and_counters():
    metrics.reset()
    metrics.inc(metrics.EVENTS_PUBLISHED, 5)
    reg = ServiceRegistry()
    reg.register(ServiceRegistration(name="a", port=8001))
    reg.update_health("a", HealthStatus.HEALTHY)

    text = metrics.render_prometheus(reg)
    assert "ecosystem_registry_up 1" in text
    assert "ecosystem_events_published_total 5" in text
    assert 'ecosystem_services{status="healthy"} 1' in text
    # Prometheus text must end with a newline.
    assert text.endswith("\n")


def test_render_without_registry():
    metrics.reset()
    text = metrics.render_prometheus(None)
    assert "ecosystem_registry_up 1" in text
    assert "ecosystem_services{" not in text
