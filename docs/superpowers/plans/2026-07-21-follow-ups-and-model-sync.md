# Follow-ups: Model-Selection Sync + Everything Flagged This Session

**Created:** 2026-07-21
**Status:** Not started. Part 1 is a plan ready to execute; Part 2 is a triaged backlog.

This captures work identified during the 2026-07-19→21 install-hardening and
AI-provider effort that was deliberately left out of scope. Nothing here is a
regression from that work unless explicitly marked.

---

# PART 1 — Model-selection sync (planned)

**Goal:** Make the selected model genuinely shared: a change in any app becomes
the model every app uses, and a failure to propagate is visible rather than
silent.

## The problem, evidenced

Live on the dev machine at time of writing:

```
AFS active.json  selected_model: 'phi3'      <- what the user picked
shared profile   selected_model: 'auto'      <- what the ecosystem believes
harness sees                   : 'auto'      -> falls back to tinyllama:1.1b
```

The user selected phi3; the component doing security analysis never found out.

## Root causes

1. **The change event goes nowhere.** `registry/app.py:274` publishes
   `ecosystem.ai_profile_changed` with the comment "so other apps update live".
   Zero subscribers exist in any of the four projects. It has always been a no-op.
2. **Local state outranks shared state.** AFS treats `data/models/active.json` as
   truth. `ecosystem_ai_bridge.shared_selected_model()` exists and is tested, but
   only feeds a read-only endpoint (`api/v1/models.py:227`) — it never decides
   which model AFS uses. AegisSIEM has the same unused pair.
3. **Propagation failure is swallowed.** `/switch` sets `propagated = False` on
   any exception and logs at debug only. A transient registry hiccup during the
   2026-07-21 reinstall silently lost the phi3 selection; nothing surfaced it.

## Current propagation matrix

| Direction | State |
|---|---|
| AFS -> shared profile | Best-effort on `/switch`; failure swallowed |
| shared -> harness | Works (reads fresh on every call) |
| shared -> AFS | **Missing** — reads local active.json |
| shared -> OpenEye | **Missing** — no runtime reader |
| shared -> AegisSIEM | Bridge functions exist; confirm whether called |

## Tasks

### Task 1: Reconcile on read (AFS)

Make the shared profile authoritative and `active.json` a cache.

- Modify: `AI-for-Survival/backend/src/api/v1/models.py` (`get_current_model`, ~line 189)
- On `/current`, fetch `shared_selected_model()`. If it is set, not `"auto"`, and
  differs from `active.json`, adopt it: update the local file, call
  `llm_service.set_active_model()`, invalidate the status cache.
- If the registry is unreachable, keep using `active.json` — a standalone install
  must not break.
- Test: local says A, shared says B -> `/current` returns B and rewrites the cache;
  registry down -> returns A unchanged.

### Task 2: Make propagation failure visible (AFS)

- Modify: `AI-for-Survival/backend/src/api/v1/models.py` (`/switch` return)
- `/switch` already returns `ecosystem_propagated`. Surface it in the UI: when it
  is `false`, show "Saved locally, but the ecosystem was not updated — other apps
  will keep using the previous model." Add a retry affordance.
- Modify: `AI-for-Survival/frontend/src/components/Dashboard/ModelSettings.tsx`
- Test: propagation raising -> response has `ecosystem_propagated: false` and the
  banner renders.

### Task 3: Subscribe to `ecosystem.ai_profile_changed`

- The registry already publishes it; give it consumers so changes land without a
  restart or a poll.
- Modify: AFS and AegisSIEM ecosystem clients to subscribe and, on receipt,
  re-read the profile and adopt `selected_model`.
- If subscription is impractical for a given app, a 60s poll is acceptable —
  document which mechanism each app uses.
- Test: publish the event with a new model; assert the app adopts it.

### Task 4: OpenEye reads the shared model

- OpenEye has `backend/core/ecosystem_ai_bridge.py` but no runtime reader.
- Decide first whether OpenEye actually performs LLM work today. If it does not,
  close this task as "not applicable" rather than adding unused plumbing.

### Task 5: Prefer the most capable installed model in the fallback

- `ecosystem_ai/router.py::_ensure_local_model` currently picks `installed[0]`,
  which on the dev machine chose `tinyllama:1.1b` — the weakest available — for
  security analysis while `mistral:7.2B` and `qwen3.5:9.7B` sat unused.
- Rank installed models by `parameter_size` and prefer the strongest that fits,
  rather than list order. Keep the explicit `selected_model` override winning.
- Test: installed = [tiny, mistral] -> picks mistral.

### Final verification

```bash
# change the model in AFS, confirm every consumer agrees
~/.local/share/ecosystem/venv/bin/python -c "
import httpx; p=httpx.get('http://127.0.0.1:8500/ai-profile',timeout=8).json()
print('shared:', (p.get('profile',p)).get('selected_model'))"
```
Shared profile, AFS `/current`, and the harness's view must all report the same
model with no manual reconciliation.

---

# PART 1b — Cross-app AI request coordination (NEEDS DESIGN, not yet planned)

**Stated intent (owner, 2026-07-21):** OpenEye, AI-for-Survival and AegisSIEM are
all intended to have AI features. Each must install and run **standalone**, but
when several are present on a network they cooperate through the shared harness
and ecosystem. Example: a verbal request to MagicMirror — "summarise the events
OpenEye recorded at 3AM" — is serviced by whichever of OpenEye / AFS / AegisSIEM
is best placed, using the shared AI and harness routing. The ecosystem client
should be installed in every project so any app on the network can join and add
capability.

**Why this is not just wiring.** The owner explicitly called out avoiding race
conditions and duplicate requests, and that is the whole difficulty:

- **Duplicate servicing.** If a request is broadcast and all three apps can
  answer, all three call an LLM. That is 3x cost (metered, for cloud), 3x
  latency, and three different answers with no defined winner. Needs
  single-servicer arbitration.
- **Capability-based routing.** "Events OpenEye recorded" implies the request
  must reach whoever *owns the data*, which is not necessarily whoever is best at
  *analysis*. Data ownership and analysis capability are different axes.
- **Idempotency.** A retried or re-broadcast request must not produce a second
  action — especially for anything with side effects (blocking an IP, recording).
- **Standalone parity.** Each app must behave correctly alone, so coordination
  has to be an enhancement, never a dependency.
- **Partition behaviour.** Two apps that cannot see each other must not both
  elect themselves servicer and then both act.

**Foundations that already exist** (do not rebuild):
- Service registration with `priority` and a `resources` capability report
  (`ecosystem_client/discovery.py::register_self` -> `_detect_resources`).
- An event bus with `EventEnvelope` publish (registry), already used for
  `ecosystem.ai_profile_changed`.
- Shared AI profile with per-task provider routing (`task_providers`), so once a
  servicer is chosen, *where* it runs the model is already solved.
- The harness daemon with a single-instance guard, already proven.

**Open decisions before any implementation:**
1. Arbitration mechanism — registry as coordinator (simple, single point of
   failure) vs. capability-bid/claim among peers (resilient, more moving parts)?
2. Does a request address a *capability* ("summarise events") or a *service*
   ("openeye")? The former needs a capability registry; the latter is simpler but
   pushes routing knowledge to the caller.
3. Lease/claim semantics: how long is a claim valid, and what happens when the
   claimant dies mid-request?
4. Is at-most-once required, or is at-least-once with idempotency keys enough?
   (Cheaper, and usually the right answer.)

**Recommended next step:** a design pass (brainstorm -> spec -> plan) before any
code. This is the kind of feature where inventing the interface first and
discovering the semantics later produces exactly the class of defect this session
has been full of. It is deliberately NOT planned here — the near-term settings
UI work (Tasks 9-10) is independent and can proceed without it.

---

# PART 2 — Everything else flagged this session

## P1 — Correctness / trust

**Linux is entirely unexercised.**
No Linux code path in this effort has ever run on any host. Both Linux defects
found (`sed -i` portability; systemd `WorkingDirectory` serving from the external
volume) were caught by *reading*, and a third (`rsync` undeclared) by review — all
in code a prior read-only review had already blessed. The final reviewer's verdict:
"high enough not to claim Linux support."
*Action:* run the installers once in **debian-slim** and **alpine** containers.
That settles sed portability, systemd `WorkingDirectory`, the rsync dependency,
and the `systemctl disable --now` uninstall branch in one pass. Cheap via Docker;
does not need a Pi.

**The harness runs from the external volume.**
`com.smartindustries.cyber-harness` has `WorkingDirectory` on `/Volumes/Locker2`.
Its venv is internal, but the *code* is not — the same class of problem that made
OpenEye crash-loop (macOS TCC denial) and SIGBUS (force-unmount). It works today
only because its interpreter happens to be TCC-approved.
*Action:* apply OpenEye's Task 9 pattern — snapshot code to
`~/.local/share/cyber-harness/app` and point `WorkingDirectory` there.

**Cloud chat does not stream.**
Cloud-served turns arrive as a single chunk because the shared router's `chat()`
is request/response. Local chat still streams. Acceptable, but if cloud becomes a
primary chat path it will feel broken next to local.
*Action:* add a streaming method to the provider protocol, or document the
limitation in the settings UI.

**`analyze_with_harness()` may be dead code.**
`AI-for-Survival/backend/src/llm/llm_service.py:216` defines it; confirm anything
calls it. If not, AFS's harness integration is nominal only.

## P2 — Hygiene / maintainability

**Harness repo has no git remote.**
`CybersecurityTeam/cyber-claude-agents` has 4 local-only commits (install tooling,
dedup guard, provider routing, capability warning). One `rm -rf` from gone.
*Action:* add a remote and push. Owner decision — not done unilaterally.

**OpenEye `main` lacks the `.env` security fix.**
Commit `2440686` (0600 secrets file) is on `fix/camera-discovery-and-ws-rce` by the
owner's explicit choice on 2026-07-21. `main` still ships the 0644 defect until
that branch merges. **Deliberate, not an oversight — do not "helpfully" cherry-pick.**

**Non-editable installs need a reinstall, not a restart.**
appEcosystem and OpenEye install their packages non-editable, so code changes need
`install-local.sh` re-run. This bit twice this session (registry silently served
old code and dropped `task_providers` with a 200 response).
*Action:* document in each README; consider an editable dev-mode flag.

**`ecosystem-client` does not declare `ecosystem-auth`.**
It imports it at runtime. Documented as a peer requirement with an actionable
ImportError (`_require_auth()`), but a hard dependency is impossible until both
are published. Revisit during the deferred publishing phase.

**The profile store silently drops unknown fields.**
`PUT /ai-profile` returns 200 while discarding anything outside `_WRITABLE`. That
is forward-compatible but means a client cannot tell its write was ignored — which
is exactly how the `task_providers` drop went unnoticed.
*Action:* echo accepted fields in the response, or 400 on unknown keys.

**Transient `launchctl bootstrap` I/O error.**
Seen once when reinstalling the harness while its KeepAlive job was still dying.
Self-resolved on retry. Watch for recurrence; may warrant a bootout + short sleep.

## P3 — Deferred minors (accepted by the final review)

- OpenEye `setup_venv()` ends with a redundant `source "$VENV/bin/activate"`.
- OpenEye `start.sh` gets `chmod +x` twice.
- Theoretical `start.sh.tmp` litter if `mv` fails after a successful `sed`.
- MagicMirror binds `127.0.0.1` unless `ECO_LAN`/`MM_ADDRESS` is set (documented).
- MagicMirror `node: command not found` was fixed for launchd; the systemd branch
  got the same `Environment=PATH=` but has never been exercised (see Linux, above).

## Known-and-intended (do not "fix")

- `test_guardrail_engine.py` self-skips: the engine source was removed in `fe88985`.
  It re-enables automatically if Guardrails return for OS Distribution Phase 2.
- OpenEye's app is a **snapshot** under `~/.local/share/openeye/app`; repo edits
  require re-running the installer. That is the deliberate cost of not depending on
  the external volume.
- Publishing (Part A) remains deferred at the owner's request.
