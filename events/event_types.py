"""Canonical event types for the ecosystem event bus."""

from enum import Enum


class EventType(str, Enum):
    """
    All ecosystem event types follow a dot-delimited namespace convention:
      <domain>.<action>

    Projects publish events under their domain; the event bus fans out
    to all subscribers registered for that event type (or wildcard).
    """

    # Security events (OpenEye, AsusGuard)
    SECURITY_ALERT = "security.alert"
    SECURITY_MOTION_DETECTED = "security.motion_detected"
    SECURITY_PERSON_DETECTED = "security.person_detected"
    SECURITY_INTRUSION = "security.intrusion"
    SECURITY_THREAT_BLOCKED = "security.threat_blocked"

    # System events (any project)
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_HEALTH_CHANGED = "system.health_changed"
    SYSTEM_ERROR = "system.error"
    SYSTEM_CONFIG_CHANGED = "system.config_changed"

    # Network events (AsusGuard)
    NETWORK_DEVICE_CONNECTED = "network.device_connected"
    NETWORK_DEVICE_DISCONNECTED = "network.device_disconnected"
    NETWORK_ANOMALY = "network.anomaly"
    NETWORK_BANDWIDTH_ALERT = "network.bandwidth_alert"

    # Display events (MagicMirror)
    DISPLAY_UPDATE = "display.update"
    DISPLAY_ALERT = "display.alert"
    DISPLAY_WIDGET_CHANGED = "display.widget_changed"

    # AI events (AI_For_Survival)
    AI_ANALYSIS_COMPLETE = "ai.analysis_complete"
    AI_RECOMMENDATION = "ai.recommendation"
    AI_PLAYBOOK_TRIGGERED = "ai.playbook_triggered"

    # Ecosystem events (registry)
    ECOSYSTEM_SERVICE_REGISTERED = "ecosystem.service_registered"
    ECOSYSTEM_SERVICE_DEREGISTERED = "ecosystem.service_deregistered"
    ECOSYSTEM_SERVICE_UNHEALTHY = "ecosystem.service_unhealthy"
