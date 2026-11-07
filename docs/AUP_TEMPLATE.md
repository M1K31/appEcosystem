# Endpoint Scanning Acceptable Use Policy (AUP) Template

This document provides the standard Acceptable Use Policy (AUP) text presented to device owners during onboarding and enrollment for local forensic and spyware scanning.

---

## Acceptable Use Policy for Endpoint Security & Spyware Sweep

**Version**: 1.0  
**Effective Date**: 2026-11-01  
**Publisher**: Smart Industries LLC / appEcosystem

### 1. Scope of Collection and Read-Only Guarantee
By opting in to endpoint scanning:
- The system runs the local, read-only **Zero-Breach-Toolkit (ZBT)** inspection tool.
- The inspection sweeps standard browser caches, bookmark records, network connection logs, and system persistence indicators for known traces of commercial spyware (e.g. Pegasus, Predator, Candiru, Arid Viper).
- **The scanner NEVER modifies, alters, deletes, or moves any files or records on your device.**
- **The scanner NEVER resolves, connects to, or transmits data to any matched indicator or C2 domain.**

### 2. Cryptographic Device Binding & Churn Protection
- Your consent is cryptographically bound to the unique Ed25519 public key fingerprint of this specific device.
- Temporary IP address changes via DHCP do not transfer consent to any other device on your network.
- Scans are strictly confined to the enrolled endpoint.

### 3. Data Retention & Sharing Boundaries
- **Full Reports**: Comprehensive forensic sweep reports (`full.json`) contain local file paths and browser visit artifacts. These reports are **encrypted at rest** on this device using an AES-256-GCM key with `0600` access permissions. Plaintext copies are wiped immediately.
- **Mesh Summaries**: Only the sanitized, redacted summary (`share.json` verdict: clean, findings, gaps) is published onto the ecosystem mesh bus. File paths and personal browsing records are never broadcast.
- **Operator Decryption**: Decrypting the sensitive full report requires step-up authentication (TOTP 2FA or Passkey).

### 4. Voluntary Participation & Instant Revocation
- Participation is strictly voluntary. You may decline during setup without impacting other application functions.
- You may revoke automatic scan authorization at any time in the settings panel. Revocation takes effect immediately and halts any scheduled jobs.

### 5. False Negatives & Professional Assessment Notice
> [!IMPORTANT]
> A clean scan result is **NOT** a guarantee that a device is completely free of malware or undetected intrusion. It indicates only that no actionable indicators from the currently known signature sets were detected in the inspected scope. If you have credible reasons to believe you are being targeted by sophisticated state-sponsored spyware, preserve the device and seek assistance from qualified incident responders.

