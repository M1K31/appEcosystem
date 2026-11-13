# Phase 0 Approval & Action Gate Inventory (`F10`)

**Date**: 2026-11-01  
**Purpose**: Verified behavioral inventory of existing human-in-the-loop approval and autonomous action pathways across `AegisSIEM`, `cyber-agents` (`AegisSIEM_Daemon`), and `AI-for-Survival`. Serves as the authoritative baseline for **Phase 3** consolidation around `ecosystem-policy` (`decide()`), preserving standalone operation when the `appEcosystem` hub is offline.

---

## 1. Side-by-Side Implementation Matrix

| Dimension | `AegisSIEM` (`response/approvals.py`) | `cyber-agents` (`daemon/response.py`) | `AI-for-Survival` (`api/ecosystem_handlers.py`) |
| :--- | :--- | :--- | :--- |
| **Class / Entrypoint** | `aegissiem.response.approvals.ApprovalManager` (`__init__(config: dict, db: Database)`) | `daemon.response.ApprovalManager` (`__init__(db: Database)`) | `_auto_trigger_playbook(app, playbook_name, variables, reason)` |
| **Checkpoint Signature** | `create_checkpoint(profile: dict, recommended_action: str, llm_assessment: str = "") -> int` | `create_checkpoint(profile_id: int, action: str, summary: str) -> int` | None — bypasses approval queue when `severity in {"high", "critical"}` |
| **Persistence Table** | `~/.aegissiem/aegissiem.db` → `approvals(id, profile_id, action, status, summary, created_at, resolved_at)` | `~/.aegissiem/daemon.db` → `approvals(id, profile_id, action, status, summary, created_at, resolved_at)` | None (ephemeral `asyncio` task logs only) |
| **Notification Side Effects** | Sends synchronous Slack (`send_slack_sync`) and macOS iMessage (`send_imessage`) immediately on checkpoint creation, enriched with `/24` peer IPs & optional LLM assessment | **None** on `create_checkpoint()` (threat alert fired earlier in `ResponsePipeline.handle_threat`, not tied to approval ID) | None (logs playbook start/completion only) |
| **`approve(id)` Behavior** | Scans `db.get_pending_approvals()`; resolves status to `"approved"`; returns approval `dict \| None`. **Gap**: does **not** automatically resume/execute the deferred action or emit an ecosystem event. | Fetches `db.get_approval(id)`; verifies `status == "pending"`; updates status to `"approved"`; returns `bool`. **Gap**: does **not** execute deferred action or notify peers. | N/A |
| **`deny(id)` Behavior** | Resolves status to `"denied"`; locks attacker profile `escalation_level` at `PROFILED` (`aegissiem.detection.escalation.PROFILED`); returns `dict \| None`. | Updates status to `"denied"`; returns `bool`. **Gap**: does **not** lock attacker profile escalation level or revert async containment (`on_deny: revert`). | N/A |
| **HTTP / CLI Surface & Auth** | Flask `GET /api/approvals` (unauthenticated read), `POST /api/approvals/<id>/approve` (`@require_pin`), `POST /api/approvals/<id>/deny` (`@require_pin`), plus CLI `aegissiem approvals` / `approve` / `deny`. | `aiohttp` `GET /api/approvals`, `POST /api/approvals/{id}/approve`, `POST /api/approvals/{id}/deny` (`daemon/aegissiem_daemon.py:198-211`). **Critical Gap**: **no** PIN, token, or HMAC signature verification on approve/deny endpoints. | Triggered internally from `/ecosystem/events` webhook handler upon `security.*` / `network.*` events (after-hours severity boost elevates `"medium"` to `"high"`, triggering playbooks automatically). |
| **TTL / Expiry / Audit Hash** | None (pending indefinitely; no tamper-evident hash chain or operator identity recorded). | None (pending indefinitely; no operator identity or rationale recorded). | None. |

---

## 2. Phase 3 Consolidation Requirements

1. **Single Canonical Contract (`approval.requested` / `approval.resolved`)**:
   - Standardize checkpoint fields across standalone SQLite stores and hub sync: `approval_id` (UUIDv7/ULID + legacy integer mapping), `action_class` (`observe | investigate | contain | remediate | data_release | system_change`), `action`, `target`, `requester_service`, `policy_version`, `mode`, `ttl_seconds`, `on_deny` (`hold_profiled | revert_containment | abort`), `resolved_by`, `auth_method` (`pin | totp | passkey | cli_local`), and `resolved_at`.
2. **Close Unauthenticated Approval Mutation Gap in `cyber-agents`**:
   - Require `ecosystem_auth` HMAC request verification (for hub/dashboard proxy calls) or local operator step-up token on `POST /api/approvals/{id}/approve` and `POST /api/approvals/{id}/deny` in `cyber-agents/daemon/aegissiem_daemon.py`.
3. **Gate `AI-for-Survival` `_auto_trigger_playbook` Behind `ecosystem_policy.decide()`**:
   - Replace raw `_AUTO_TRIGGER_THRESHOLD = {"high", "critical"}` auto-execution with `ecosystem_policy.decide()` so severity or after-hours boosting alone cannot bypass `require_approval` unless `mode` is `incident`/`survival` **and** the specific playbook + target match an explicitly operator-enabled override.
4. **Post-Resolution Execution & Reversion Callbacks**:
   - Wire `approve()` to dispatch the bound deferred action (re-checking `freeze` mode immediately prior to execution) and wire `deny()` to both lock escalation (`PROFILED`) and revert any provisional `contain` action (`unblock_ip` / quarantine rollback) when `on_deny == "revert"`.
5. **Standalone Parity**:
   - Both `AegisSIEM` and `cyber-agents` must retain local SQLite persistence and local CLI/dashboard approval resolution when `appEcosystem` registry (`:8500`) is unreachable, syncing pending/resolved records once reconnected.

