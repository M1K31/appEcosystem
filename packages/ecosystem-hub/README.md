# `appecosystem-hub` (`ecosystem_hub`)

App-embeddable Hub lifecycle manager, single-host lock, capability registry, and SQLite durable notification outbox for `appEcosystem`.

## Role Modes (`ECOSYSTEM_HUB_ROLE`)

- `auto` *(default)*: Discovers an existing Hub (`registry → mDNS → static`); if none responds and the device is at least Tier 1 (`>= 4 GB` RAM), acquires a single-host advisory file lock and launches a managed Hub sidecar.
- `host`: Explicitly hosts the Hub on this device (falling back to `join` if another local app already holds the single-host lock and passes `/health`).
- `join`: Joins an existing Hub when reachable; degrades gracefully to local standalone operation + durable SQLite outbox when offline.
- `off`: Pure standalone operation with zero network discovery or hosting.

