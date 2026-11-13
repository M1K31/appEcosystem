"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { HubClient, EventType } = require("../src/index");

const SECRET = "js-phase2-hub-test-secret-0123456789";

function sampleCap() {
    return {
        capability: "display.show_alert",
        version: 1,
        description: "Show alert banner on MagicMirror wall HUD",
        action_class: "observe",
        required_grant: "display:alert",
        timeout_seconds: 10,
        cancellable: false,
        idempotent: true,
        offline_behavior: "run_local",
    };
}

test("HubClient queues deduplicated notifications offline and flushes + syncs capabilities when Hub comes online", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "eco-js-hub-"));
    const outboxPath = path.join(tmpDir, "outbox-magicmirror.json");

    // 1. Start while Hub is unreachable
    global.fetch = async () => {
        throw new Error("ECONNREFUSED");
    };

    const hub = new HubClient("magicmirror", {
        registryUrl: "http://hub.local:8500",
        secret: SECRET,
        deviceId: "hallway-pi",
        outboxPath,
        capabilities: [sampleCap()],
    });

    assert.strictEqual(await hub.start(), "standalone");
    assert.strictEqual(hub.isJoined, false);

    // Local capability still resolves offline
    const localRes = await hub.resolveCapability("display.show_alert");
    assert.strictEqual(localRes.available, true);
    const remoteRes = await hub.resolveCapability("scan.request");
    assert.strictEqual(remoteRes.available, false);

    // Offline notify queues once and deduplicates repeat dedupeKey
    const n1 = await hub.notify(EventType.NOTIFY_SECURITY, "high", "Gate opened", "Front gate sensor", {
        dedupeKey: "mm:gate:1",
    });
    const n2 = await hub.notify(EventType.NOTIFY_SECURITY, "high", "Gate opened", "Duplicate", {
        dedupeKey: "mm:gate:1",
    });
    assert.strictEqual(n1.status, "queued_offline");
    assert.strictEqual(n2.status, "deduplicated_offline");

    // 2. Hub comes online -> start() registers capabilities and flushes offline outbox
    const calls = [];
    global.fetch = async (url, opts = {}) => {
        calls.push({ url, method: opts.method || "GET", headers: opts.headers || {}, body: opts.body });
        if (url.endsWith("/health")) {
            return { ok: true, status: 200, json: async () => ({ status: "healthy" }) };
        }
        if (url.endsWith("/capabilities/register")) {
            return { ok: true, status: 201, json: async () => ({ registered: [sampleCap()] }) };
        }
        if (url.endsWith("/notifications/publish")) {
            return { ok: true, status: 200, json: async () => ({ status: "routed" }) };
        }
        if (url.includes("/capabilities/magicmirror")) {
            return { ok: true, status: 200, json: async () => ({ status: "withdrawn" }) };
        }
        return { ok: true, status: 200, json: async () => ({ notifications: [] }) };
    };

    assert.strictEqual(await hub.start(), "joined");
    assert.strictEqual(hub.isJoined, true);
    assert.ok(calls.some((c) => c.url.endsWith("/capabilities/register") && c.headers["X-Ecosystem-Signature"]));
    assert.ok(calls.some((c) => c.url.endsWith("/notifications/publish") && c.headers["X-Ecosystem-Signature"]));

    // Outbox is now empty
    const remaining = JSON.parse(fs.readFileSync(outboxPath, "utf8"));
    assert.strictEqual(remaining.length, 0);

    await hub.stop();
    assert.ok(calls.some((c) => c.method === "DELETE" && c.url.endsWith("/capabilities/magicmirror")));
    fs.rmSync(tmpDir, { recursive: true, force: true });
});

