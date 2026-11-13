"use strict";

const { test } = require("node:test");
const assert = require("node:assert");

const {
    EcosystemConfig,
    EventPublisher,
    EventSubscriber,
    EventType,
    generateUlid,
    isUlid,
    ulidTimestampMs,
    listSchemas,
    assertValidSchema,
    validateAgainstSchema,
    buildEventEnvelopeV2,
    verifyEventEnvelope,
    buildCommandEnvelope,
    verifyCommandEnvelope,
    buildNotificationEnvelope,
} = require("../src/index");
const { signPayload } = require("../src/_auth");

const SECRET = "js-phase1-contract-secret-abcdef0123456789";

test("ULID generation is monotonic, 26-char Crockford Base32, and preserves timestamp", () => {
    const fixedTs = 1762000555123;
    const single = generateUlid(fixedTs);
    assert.strictEqual(single.length, 26);
    assert.ok(isUlid(single));
    assert.strictEqual(ulidTimestampMs(single), fixedTs);

    const batch = Array.from({ length: 50 }, () => generateUlid());
    const sorted = batch.slice().sort();
    assert.deepStrictEqual(batch, sorted);
    assert.strictEqual(new Set(batch).size, 50);
    assert.strictEqual(isUlid("8ZZZZZZZZZZZZZZZZZZZZZZZZZ"), false);
});

test("All 5 canonical schemas load and validate v2 EventEnvelope", () => {
    assert.deepStrictEqual(listSchemas(), [
        "capability-manifest.v1",
        "command-envelope.v1",
        "event-envelope.v2",
        "notification-envelope.v1",
        "policy-state.v1",
    ]);

    const env = buildEventEnvelopeV2(
        EventType.SCAN_COMPLETED,
        "zero-breach-toolkit",
        { critical: 0, medium: 1 },
        SECRET,
        { deviceId: "edge-pi", correlationId: "scan-run-1" }
    );
    assertValidSchema(env, "event-envelope.v2");
    assert.strictEqual(verifyEventEnvelope(env, SECRET), true);
    assert.strictEqual(verifyEventEnvelope(env, "wrong-secret"), false);
});

test("EventSubscriber accepts both v2 and legacy v1 signed envelopes", async () => {
    const received = [];
    const sub = new EventSubscriber(SECRET);
    sub.on("security.*", async (e) => received.push(e));

    const v2 = buildEventEnvelopeV2(EventType.SECURITY_ALERT, "openeye", { cam: "front" }, SECRET);
    assert.strictEqual(await sub.dispatch(v2), true);

    const legacyV1Signable = {
        id: "123e4567-e89b-12d3-a456-426614174000",
        type: "security.intrusion",
        source: "aegissiem",
        timestamp: 1700000100,
        data: { host: "nas-01" },
    };
    const legacyV1 = Object.assign({}, legacyV1Signable, {
        signature: signPayload(legacyV1Signable, SECRET),
    });
    assert.strictEqual(await sub.dispatch(legacyV1), true);
    assert.strictEqual(received.length, 2);
});

test("EventPublisher emits valid v2 envelopes and skips network in standalone mode", async () => {
    const cfg = new EcosystemConfig({ hmacSecret: SECRET });
    const pub = new EventPublisher(cfg, "standalone", "magicmirror");
    const res = await pub.publish(EventType.DISPLAY_ALERT, { message: "Motion at gate" });
    assert.strictEqual(res.mode, "standalone");

    const env = pub._buildEnvelope(EventType.DISPLAY_ALERT, { message: "Motion at gate" });
    assertValidSchema(env, "event-envelope.v2");
    assert.strictEqual(env.source.app, "magicmirror");
    assert.strictEqual(EventPublisher._sourceHeader(env), "magicmirror");
});

test("CommandEnvelope enforces expiry, signature integrity, and forbids notify:* authorization_ref", () => {
    const actor = { id: "admin-1", type: "operator", app: "hub", device_id: "mac-studio" };
    const target = { scope: "device", device_id: "pi-nvr", service: "openeye" };

    const cmd = buildCommandEnvelope("camera.ptz_preset", "investigate", actor, target, SECRET, {
        issuedAt: 1700000000,
        ttlSeconds: 30,
        parameters: { preset: "driveway" },
    });
    assert.deepStrictEqual(verifyCommandEnvelope(cmd, SECRET, { now: 1700000010 }), {
        valid: true,
        reason: "ok",
    });
    assert.strictEqual(
        verifyCommandEnvelope(cmd, SECRET, { now: 1700000035 }).valid,
        false
    );

    assert.throws(() =>
        buildCommandEnvelope("host.isolate", "contain", actor, target, SECRET, {
            authorizationRef: "notify:01J9XYZ",
        })
    );
});

test("NotificationEnvelope validates against notification-envelope.v1 schema", () => {
    const note = buildNotificationEnvelope(
        EventType.NOTIFY_APPROVAL,
        "cyber-agents",
        "critical",
        "Containment approval needed",
        "Block outbound C2 IP 198.51.100.42 on firewall.",
        {
            dedupeKey: "cyber-agents:approval:198.51.100.42",
            actions: [{ id: "review_in_hub", label: "Review in Dashboard", requires: "approver_auth" }],
            secret: SECRET,
        }
    );
    assert.deepStrictEqual(validateAgainstSchema(note, "notification-envelope.v1"), []);
});


test("policy-state.v1 accepts freeze_confirmed and the schema copies stay identical", () => {
    const fs = require("fs");
    const path = require("path");
    const localOnlyFreeze = {
        schema_version: 1,
        policy_version: 1,
        mode: "freeze",
        restrictions: "on",
        frozen: true,
        freeze_confirmed: false,
        freeze_info: { initiated_by: "magicmirror_display", channel: "touch", reason: "hub offline", since: "2026-11-10T00:00:00Z" },
        always_enforced: ["audit_log"],
        authority: "standalone_local",
        updated_at: "2026-11-10T00:00:00Z",
    };
    assertValidSchema(localOnlyFreeze, "policy-state.v1");
    assert.throws(() => assertValidSchema({ ...localOnlyFreeze, freeze_confirmed: "no" }, "policy-state.v1"));
    const { freeze_confirmed: _omit, ...hubState } = localOnlyFreeze;
    assertValidSchema(hubState, "policy-state.v1");   // the field is optional

    const root = path.resolve(__dirname, "../..");
    const canonical = fs.readFileSync(path.join(root, "contracts/schemas/policy-state.v1.schema.json"), "utf8");
    for (const copy of ["ecosystem_client_js/schemas", "ecosystem_client/schemas"]) {
        assert.strictEqual(
            fs.readFileSync(path.join(root, copy, "policy-state.v1.schema.json"), "utf8"),
            canonical,
            `${copy} copy differs from contracts/schemas`
        );
    }
});
