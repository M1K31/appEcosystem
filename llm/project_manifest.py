"""Project capability manifests for LLM tool-calling integration."""

from typing import Any

from pydantic import BaseModel, Field


class APIEndpoint(BaseModel):
    """An API endpoint exposed by a project."""

    method: str = Field(..., description="HTTP method (GET, POST, etc.)")
    path: str = Field(..., description="URL path (e.g., '/api/v1/cameras')")
    description: str = Field(default="")
    parameters: dict[str, Any] = Field(default_factory=dict)
    auth_required: bool = Field(default=True)


class ProjectCapability(BaseModel):
    """A capability that a project provides to the ecosystem."""

    name: str = Field(..., description="Capability name (e.g., 'motion_detection')")
    description: str = Field(default="")
    endpoints: list[APIEndpoint] = Field(default_factory=list)
    event_types: list[str] = Field(
        default_factory=list,
        description="Event types this capability can publish",
    )


class ProjectManifest(BaseModel):
    """
    Full capability manifest for a project.

    Used by the LLM discovery agent to understand what each project
    can do and how to interact with it via API calls.
    """

    name: str
    description: str = ""
    version: str = "0.1.0"
    base_url: str = ""
    capabilities: list[ProjectCapability] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


# Static manifests for known projects
KNOWN_MANIFESTS: dict[str, ProjectManifest] = {
    "openeye": ProjectManifest(
        name="OpenEye",
        description="OpenCV home security surveillance system with motion/person detection",
        base_url="http://localhost:8200",
        capabilities=[
            ProjectCapability(
                name="camera_monitoring",
                description="Real-time camera feed monitoring with motion and person detection",
                endpoints=[
                    APIEndpoint(method="GET", path="/api/cameras", description="List all cameras"),
                    APIEndpoint(method="GET", path="/api/cameras/{id}/status", description="Camera status"),
                ],
                event_types=["security.motion_detected", "security.person_detected"],
            ),
            ProjectCapability(
                name="security_alerts",
                description="Security alert management",
                endpoints=[
                    APIEndpoint(method="GET", path="/api/alerts", description="List recent alerts"),
                    APIEndpoint(method="POST", path="/api/alerts/acknowledge", description="Acknowledge alert"),
                ],
                event_types=["security.alert", "security.intrusion"],
            ),
        ],
        tags=["security", "surveillance", "opencv", "cameras"],
    ),
    "magicmirror": ProjectManifest(
        name="MagicMirror",
        description="Smart mirror with modular widget system and display management",
        base_url="http://localhost:8080",
        capabilities=[
            ProjectCapability(
                name="display_management",
                description="Control what is displayed on the smart mirror",
                endpoints=[
                    APIEndpoint(method="GET", path="/api/v1/modules", description="List active modules"),
                    APIEndpoint(method="POST", path="/api/v1/notification", description="Send notification to mirror"),
                ],
                event_types=["display.update", "display.alert"],
            ),
        ],
        tags=["display", "dashboard", "widgets", "electron"],
    ),
    "ai_for_survival": ProjectManifest(
        name="AI_For_Survival",
        description="AI-powered survival and security assistant with RAG pipeline and playbooks",
        base_url="http://localhost:8000",
        capabilities=[
            ProjectCapability(
                name="ai_analysis",
                description="Run AI analysis using RAG pipeline and tool-calling agents",
                endpoints=[
                    APIEndpoint(method="POST", path="/api/chat", description="Send chat/analysis request"),
                    APIEndpoint(method="GET", path="/api/playbooks", description="List available playbooks"),
                    APIEndpoint(method="POST", path="/api/playbooks/run", description="Execute a playbook"),
                ],
                event_types=["ai.analysis_complete", "ai.recommendation"],
            ),
        ],
        tags=["ai", "llm", "security", "analysis", "playbooks"],
    ),
    "asusguard": ProjectManifest(
        name="AsusGuard",
        description="Router log analysis and network security monitoring",
        base_url="http://localhost:8088",
        capabilities=[
            ProjectCapability(
                name="log_analysis",
                description="Analyze router and network logs for security threats",
                endpoints=[
                    APIEndpoint(method="GET", path="/api/status", description="System status"),
                    APIEndpoint(method="GET", path="/api/logs/recent", description="Recent log entries"),
                    APIEndpoint(method="POST", path="/api/analyze", description="Trigger log analysis"),
                ],
                event_types=["network.anomaly", "security.threat_blocked"],
            ),
            ProjectCapability(
                name="network_monitoring",
                description="Monitor connected devices and bandwidth",
                endpoints=[
                    APIEndpoint(method="GET", path="/api/devices", description="List connected devices"),
                ],
                event_types=["network.device_connected", "network.device_disconnected"],
            ),
        ],
        tags=["network", "logs", "router", "security"],
    ),
}
