# Ecosystem Usage & API Guide

## Lifecycle Management
The ecosystem is controlled via the `appEcosystem` CLI wrapper.
- **Start/Stop All Services**: `python -m cli start-all` / `python -m cli stop-all`
- **Monitor Services**: `python -m cli monitor -i 10`
- **Tail Logs**: `python -m cli logs ai_for_survival`

## API Consumption
The central Service Registry provides service discovery and event routing.
**1. Service Discovery**
Query the registry to find active services: `curl http://localhost:8500/discover`

**2. Publishing Events**
Publish cross-ecosystem events (e.g., a security alert from OpenEye to AegisSIEM).
```json
POST http://localhost:8500/events/publish
Content-Type: application/json
{
  "type": "security.alert",
  "source": "openeye",
  "data": { "intrusion_detected": true, "camera_id": "front_door" }
}
```

## UI Components & Theming
Connected projects inherit global CSS properties for a cohesive design language.
```html
<!-- Include global theme -->
<link rel="stylesheet" href="http://localhost:8500/theme/ecosystem-theme.css">
```
