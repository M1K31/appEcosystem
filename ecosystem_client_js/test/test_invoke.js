"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { HubClient } = require("../src/index");
const { isUlid } = require("../src/ulid");

const SECRET = "js-invoke-test-secret-0123456789abcdef";

function client(opts = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "eco-js-invoke-"));
    const outboxPath = path.join(dir, "outbox.json");
    const hub = new HubClient("magicmirror", Object.assign({
        registryUrl: "http://hub.local:8500",
        secret: SECRET,
        deviceId: "hallway-pi",
        outboxPath,
    }, opts));
    return { hub, outboxPath };
}

function respond(status, body) {
    return { ok: status >= 200 && status < 300, status, json: async () => body };
}

test("invoke sends a signed POST to /commands/dispatch", async () => {
    const calls = [];
    global.fetch = async (url, init) => {
        calls.push({ url, init });
        return respond(200, { command_id: "01HZZZZZZZZZZZZZZZZZZZZZZ1", status: "completed", result: { ok: true } });
    };
    const { hub } = client();
    const out = await hub.invoke(
        "camera.snapshot",
        { scope: "local", service: "openeye" },
        { camera: "front-door" },
        { rationale: "doorbell", correlationId: "visit-9", context: { trigger: "automation" }, actorType: "automation" },
    );
    assert.strictEqual(out.status, "completed");
    assert.strictEqual(calls.length, 1);
    assert.strictEqual(calls[0].url, "http://hub.local:8500/commands/dispatch");
    assert.strictEqual(calls[0].init.method, "POST");
    assert.match(calls[0].init.headers["X-Ecosystem-Signature"], /^[0-9a-f]{64}$/);
    const body = JSON.parse(calls[0].init.body);
    assert.strictEqual(body.capability, "camera.snapshot");
    assert.deepStrictEqual(body.target, { scope: "local", service: "openeye" });
    assert.deepStrictEqual(body.parameters, { camera: "front-door" });
    assert.deepStrictEqual(body.actor, {
        app: "magicmirror", id: "magicmirror", type: "automation", device_id: "hallway-pi",
    });
    assert.strictEqual(body.rationale, "doorbell");
    assert.strictEqual(body.correlation_id, "visit-9");
    assert.deepStrictEqual(body.context, { trigger: "automation" });
    assert.ok(!("step_up_token" in body));
});

test("invoke generates an idempotency key, and reuses one that is given", async () => {
    const bodies = [];
    global.fetch = async (url, init) => {
        bodies.push(JSON.parse(init.body));
        return respond(200, { command_id: "x", status: "completed" });
    };
    const { hub } = client();
    await hub.invoke("camera.snapshot", { scope: "local" });
    await hub.invoke("camera.snapshot", { scope: "local" });
    await hub.invoke("camera.snapshot", { scope: "local" }, {}, { idempotencyKey: "retry-me" });
    assert.ok(isUlid(bodies[0].idempotency_key));
    assert.notStrictEqual(bodies[0].idempotency_key, bodies[1].idempotency_key);
    assert.strictEqual(bodies[2].idempotency_key, "retry-me");
    assert.deepStrictEqual(bodies[0].parameters, {});
});

test("invoke returns provider_unavailable and queues nothing when the hub is down", async () => {
    global.fetch = async () => {
        const err = new TypeError("fetch failed");
        err.cause = { code: "ECONNREFUSED" };
        throw err;
    };
    const { hub, outboxPath } = client();
    const out = await hub.invoke("containment.block_ip", { scope: "local", identifier: "203.0.113.9" });
    assert.deepStrictEqual(out, { status: "provider_unavailable", error: "hub_unreachable", command_id: null });
    assert.strictEqual(fs.existsSync(outboxPath), false);
});

test("invoke without a secret is not_configured and sends nothing", async () => {
    let called = 0;
    global.fetch = async () => { called += 1; return respond(200, {}); };
    const { hub } = client({ secret: "" });
    const out = await hub.invoke("camera.snapshot", { scope: "local" });
    assert.deepStrictEqual(out, { status: "provider_unavailable", error: "not_configured", command_id: null });
    assert.strictEqual(called, 0);
});

test("invoke reports a timeout after sending as an unknown outcome", async () => {
    global.fetch = async () => {
        const err = new Error("The operation was aborted due to timeout");
        err.name = "TimeoutError";
        throw err;
    };
    const { hub } = client();
    const out = await hub.invoke("containment.block_ip", { scope: "local" }, {}, { idempotencyKey: "k-1" });
    assert.strictEqual(out.status, "failed");
    assert.strictEqual(out.outcome_unknown, true);
    assert.strictEqual(out.idempotency_key, "k-1");
});

test("invoke surfaces a 4xx as failed", async () => {
    global.fetch = async () => respond(409, { detail: "idempotency_key 'k' was already used for a different request" });
    const { hub } = client();
    const out = await hub.invoke("camera.snapshot", { scope: "local" }, {}, { idempotencyKey: "k" });
    assert.strictEqual(out.status, "failed");
    assert.strictEqual(out.http_status, 409);
    assert.match(out.error, /already used/);
    assert.strictEqual(out.command_id, null);
    assert.ok(!out.outcome_unknown);
});

test("getCommand returns the record, and null on 404", async () => {
    global.fetch = async (url) => (url.endsWith("/commands/known")
        ? respond(200, { command_id: "known", status: "completed", events: [] })
        : respond(404, { detail: "not found" }));
    const { hub } = client();
    assert.strictEqual((await hub.getCommand("known")).status, "completed");
    assert.strictEqual(await hub.getCommand("missing"), null);
});
