"""Tests for event schemas and types."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from events.event_types import EventType
from events.schemas import EventEnvelope


class TestEventTypes:
    def test_event_type_values(self):
        assert EventType.SECURITY_ALERT == "security.alert"
        assert EventType.SYSTEM_STARTUP == "system.startup"
        assert EventType.NETWORK_ANOMALY == "network.anomaly"

    def test_event_type_is_string(self):
        assert isinstance(EventType.SECURITY_ALERT, str)


class TestEventEnvelope:
    def test_create_minimal(self):
        event = EventEnvelope(type="security.alert", source="openeye")
        assert event.type == "security.alert"
        assert event.source == "openeye"
        assert event.id  # auto-generated
        assert event.timestamp > 0

    def test_create_with_data(self):
        event = EventEnvelope(
            type="security.motion_detected",
            source="openeye",
            data={"camera_id": "front_door", "confidence": 0.95},
        )
        assert event.data["camera_id"] == "front_door"

    def test_signable_dict_excludes_signature(self):
        event = EventEnvelope(
            type="test.event",
            source="test",
            signature="should-not-appear",
        )
        signable = event.signable_dict()
        assert "signature" not in signable
        assert "type" in signable
        assert "source" in signable

    def test_correlation_id(self):
        event = EventEnvelope(
            type="security.alert",
            source="openeye",
            correlation_id="incident-123",
        )
        assert event.correlation_id == "incident-123"

    def test_auto_id_uniqueness(self):
        e1 = EventEnvelope(type="test", source="test")
        e2 = EventEnvelope(type="test", source="test")
        assert e1.id != e2.id
