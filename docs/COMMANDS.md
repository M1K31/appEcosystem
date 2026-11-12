# Commands: invoking a capability

A capability an app registers with the hub can be invoked by another app. The request goes through the hub, which decides whether it may run, forwards a signed `CommandEnvelope` to the provider, and reports the result only after the provider confirms it.

```
caller ──invoke──▶ hub ── gate 1 (hub policy) ──▶ provider ── gate 2 (provider policy) ──▶ handler
                    │                                                                        │
                    └── record + audit trail ◀──────────── status, result ◀──────────────────┘
```

Three rules hold everywhere:

- **Two policy gates.** The hub's `PolicyEngine` decides before anything is sent; the provider's own engine decides again before anything runs.
- **Done means confirmed.** `completed` is reported only when the provider's handler returned.
- **Nothing is queued.** If the hub or the provider cannot be reached now, the answer is `provider_unavailable`. A containment that fires hours later, out of context, is worse than one that did not fire.

## Calling a capability

Python (`appecosystem-hub`):

```python
result = await hub.invoke(
    "threat_intel.lookup_ioc",
    {"scope": "local", "identifier": "192.168.1.20"},
    {"indicator": "192.168.1.20"},
    rationale="repeated failed logins from this host",
)
```

JavaScript (`@smartindustriesllc/ecosystem-client`):

```js
const result = await hub.invoke(
    "camera.snapshot",
    { scope: "local", service: "openeye" },
    { camera: "front-door" },
    { rationale: "doorbell pressed" },
);
```

Both send a signed `POST /commands/dispatch`. The body:

| Field | Meaning |
|---|---|
| `capability` | Dotted capability id, as registered. |
| `target` | Where the action applies: `{scope, device_id?, service?, identifier?}`. `scope` is `local`, `device`, `group`, `ecosystem` or `external`. `service` names the provider to use; `identifier` is the subject (an address, a hostname). |
| `parameters` | Inputs for the handler, at most 64 KiB. Validated against the manifest's `inputs_schema` when it has one. |
| `actor` | `{app, id?, type?, device_id?}`. `type` is `service` (default), `automation`, `voice_intent`, `ai_proposal` or `operator`. |
| `rationale` | Why. Shown to the person who approves. |
| `idempotency_key` | Required. The clients generate one when you do not pass it. |
| `correlation_id`, `context` | Optional. `context` may carry `incident_id`, `profile`, and a `trigger` of `schedule` or `automation`. |
| `step_up_token` | Required when `actor.type` is `operator`. |

### The answer

Every policy or provider outcome is HTTP 200 with a status document:

```json
{"command_id": "01J…", "status": "completed", "capability": "threat_intel.lookup_ioc",
 "provider": "aegissiem", "decision": {"result": "allow", "…": "…"}, "approval_id": null,
 "result": {"verdict": "clean"}, "error": null, "outcome_unknown": false, "correlation_id": "01J…"}
```

| `status` | What it promises |
|---|---|
| `completed` | The provider's handler ran and returned. `result` is its answer. |
| `accepted` | The provider started long-running work and will report the result later. |
| `pending_approval` | Nothing was sent. An approval was opened (`approval_id`); approving it runs the command. |
| `denied` | Policy refused, at the hub or at the provider. `error` says why. Nothing ran. |
| `provider_unavailable` | No eligible provider, or it could not be connected to. Nothing was sent. |
| `failed` | It was sent and did not succeed. Check `outcome_unknown`. |

`outcome_unknown: true` means the command was sent and no usable answer came back, so it may or may not have run. Dispatch again **with the same `idempotency_key`**: the hub re-checks policy and asks the provider, which answers from its replay store without running anything twice.

Other responses: `401` unsigned, `403` not permitted to act as that app or as an operator, `409` the idempotency key was already used for a different request, `422` malformed request.

### Who may dispatch

- Dispatching always needs a signed request. There is no exemption for local processes.
- An app with its own key needs the `commands:dispatch` scope and may only name a service it owns in `actor.app`. To read command records it needs `commands:read`, and it sees only commands it requested or was asked to run.
- First-party apps sign with the shared secret, which the hub sees as one identity. For them `actor.app` is a claim; it must name a registered service, and the audit trail marks such commands `identity: "shared_secret"`.
- `actor.type: "operator"` is believed only with a valid step-up token, and the operator recorded is the one the token names.

### Reading the record

- `GET /commands/{command_id}` — the status document plus `action_class`, `requester_app`, `actor`, `target`, `parameters`, `digest`, the approval record, and `events` (the ordered audit trail).
- `GET /commands?correlation_id=&status=&limit=`.

## What the policy sees

The hub and the provider evaluate the same request:

- **Action class** comes from the capability's registered manifest, never from the caller. A provider refuses an envelope whose class differs from the one it registered.
- **Action name** is the capability id. The one exception is `threat_intel.lookup_ioc`, evaluated as `lookup_ioc` while it is registered as `observe` or `investigate`, because policy files list that passive lookup by its bare name.
- **External targets.** For `investigate`, `remediate` and `system_change` — classes that reach into the subject's own system — the target is external unless everything the request names is provably on the owner's network: a strictly written private, loopback, link-local or unique-local address or CIDR, or a hostname under `.local`, `.lan`, `.home.arpa` or `.internal`. Public addresses, other hostnames, bare names, integer/hex/leading-zero address spellings, URLs with userinfo or backslashes, and a request that names no subject at all are external, and the engine denies them unless they are separately authorised. For `contain` and `observe` the subject is acted on from the owner's own infrastructure (blocking an attacker's public address on the owner's router), so only `scope: "external"` makes the target external.
- **Approvals.** `require_approval` stores the command and opens an approval. Approving it (step-up required) evaluates the policy again as it stands at that moment, then forwards the command with `authorization_ref: "approval:<id>"`. Provisional containment runs at once and opens an approval alongside; if that approval is denied or expires, a revert is requested.

## Providing a capability

```python
from ecosystem_hub import CommandReceiver, CommandFailed, HubApprovalVerifier, build_command_router

receiver = CommandReceiver(
    "aegissiem",
    secret=ecosystem_secret,
    policy_engine=policy_engine,                 # this app's own engine: gate 2
    replay_db_path=data_dir / "commands-replay.db",
    approval_verifier=HubApprovalVerifier(registry_url, ecosystem_secret, app_name="aegissiem"),
)

async def lookup_ioc(ctx):
    verdict = await intel.lookup(ctx.parameters["indicator"])
    if verdict is None:
        raise CommandFailed("no intelligence source answered")
    return {"verdict": verdict.label, "sources": verdict.sources}

receiver.register("threat_intel.lookup_ioc", "observe", lookup_ioc, timeout_seconds=10)
app.include_router(build_command_router(receiver))   # POST /ecosystem/commands
```

Checklist for a handler:

1. **Register the class you advertise.** The action class passed to `register` must be the one in the capability manifest.
2. **Return only after confirmation.** Returning a result object means "this took effect". For `containment.block_ip` that is after the router confirmed the rule, not after the command was sent to it.
3. **Raise `CommandFailed`** when the action definitely did not take effect. Any other exception is reported as `failed` with an unknown outcome, and only the exception's type name leaves the process.
4. **Take the subject from `ctx.target["identifier"]`**, or from a parameter named `host`, `ip`, `address`, `url`, `domain`, `cidr`, `network`, `indicator` or a plural of those. The policy gates classify exactly those. A hostname read from any other parameter was not checked.
5. **Give the manifest an `inputs_schema`**, so the hub rejects malformed parameters before they reach you.
6. **Long-running work:** return `Accepted(job_ref)`; when the work ends, send a signed `POST /commands/{command_id}/result` with `{"status": "completed" | "failed", "result"?, "error"?}`. It is accepted once.
7. **Undo provisional containment** when a `containment.reverted` event arrives for it.

What the receiver does before your handler runs: verifies the envelope's schema, signature and expiry; checks the command is addressed to this app; answers a repeated idempotency key from its replay store; evaluates this app's policy engine; and, where the decision is `require_approval`, confirms with the hub that the approval is real, is for this exact request and provider, and is being dispatched right now. An approval named in an envelope is never taken on trust.

## Idempotency

One `(requesting app, idempotency_key)` is one command. Repeating it returns the first answer, at the hub and at the provider, and a new attempt needs a new key. The same key with a different request is a `409`. A denied command stays denied for its key even if policy later changes.

## Limits in this version

- Apps that authenticate with their own key cannot be providers yet: they cannot verify a hub-signed envelope.
- Among first-party apps the requester's identity is a claim (see "Who may dispatch"). Per-app keys for first-party apps are planned.
- Commands that were being dispatched when the hub stopped are marked `failed` with an unknown outcome on restart; they are not re-sent.
