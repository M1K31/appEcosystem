# `appecosystem-policy` (`ecosystem_policy`)

Signed blue-team policy engine, Ed25519 override grant verifier, `Freeze` kill-switch preemption, device-key-bound `auto_scan` grant authorization, TOTP / WebAuthn Passkey step-up authentication, and unified SQLite approval queue (`F10`) for the `appEcosystem` suite.

## Core Guarantees
- **Blue-Team Default Posture:** `observe` is allowed; `investigate`, `remediate`, `data_release`, and `system_change` require explicit authorization or operator approval; `contain` allows protective time-limited isolation with an asynchronous approval lease (`on_deny: revert`).
- **`Freeze` Preempts Everything:** Activating `Freeze` halts new mutating/scanning jobs immediately — even while a timed `Restrictions: Off (authorized scope)` grant is active.
- **Unbypassable Invariants (`always_enforced`):** Command authentication, target consent/AUP scope, input validation, tamper-evident audit logging, `Freeze`, and cloud budget/data-release boundaries remain enforced at all times.
- **DHCP-Immune Scan Grants:** Automatic scan designations bind to enrolled cryptographic `device_id` + public-key fingerprint rather than mutable IPv4/IPv6 leases.

