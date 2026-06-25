# Ecosystem TODOs & Pending Work

## 📋 Phase 3: Frontend Polish & UX Remediation (Pending)
**MagicMirror³**
- **UI/UX**: Fix facebook birthday issue in calendar fetcher (`calendarfetcherutils.js`)

**OpenEye Surveillance**
- **UI/Components**: Replace native alerts with proper notification components (`HardwareDetectionPage.jsx`)
- **PTZ Controls**: Implement logic to fetch current pan position (`PTZControl.jsx`)

---

## 📋 Phase 4: Backend Orchestration & Integrations (Pending)
**OpenEye Surveillance**
- **Automation Engine**: 
  - Integrate with the actual push notification system
  - Integrate with camera recording system and fetch `recording_id` from database
  - Register with the face detection event system
- **Ecosystem API**: 
  - Load push notification configuration from the database
  - Implement actual notification delivery methods
- **Integrations**: Load and save configurations for Home Assistant, HomeKit, and Google Nest

---

## 📋 Phase 5: Core & Refactoring (Backlog)
**MagicMirror³**
- **Security Dashboard**: Show specific camera in fullscreen mode (`security.js`)
- **Weather Integration**: Add unit conversion for precipitation (currently hardcoded to `mm`) (`weatherflow.js`)
- **Core Refactor**: Move configuration passing logic into core to prevent breaking tests (`main.js`, `check_config.js`)
- **Hotfix**: Pending hotfix pull request (`app.js`)

**OpenEye Surveillance**
- **Face Recognition API**:
  - Make training feature toggles configurable
  - Dynamically calculate quality scores and encoding quality instead of hardcoding `0.9`
- **Hardware API**: Implement statistics collection from running cameras
- **DevOps**: Set Docker Hub credentials and username in `docker-push.sh`
