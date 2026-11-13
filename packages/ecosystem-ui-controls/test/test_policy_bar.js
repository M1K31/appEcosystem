"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const { makeHarness } = require("./helpers/fake_dom");

const frozenWithOverride = (expiresAt) => ({
    mode: "freeze", frozen: true, restrictions: "off_scoped", authority: "hub_synced",
    freeze_info: { initiated_by: "operator", reason: "drill" },
    active_override: { grant_id: "g-1", expires_at: expiresAt, issued_by: "admin", reason: "maint",
        scope: { apps: ["a"], devices: ["d"], action_classes: ["c"] } },
});

const expiredOverride = (grantId) => ({
    mode: "normal", frozen: false, restrictions: "off_scoped", authority: "hub_synced",
    active_override: { grant_id: grantId, expires_at: new Date(Date.now() - 1000).toISOString(),
        issued_by: "admin", reason: "maint", scope: {} },
});

test("override expiring during a freeze is reflected without a hub poll", (t) => {
    t.mock.timers.enable({ apis: ["setTimeout", "setInterval", "Date"], now: 1_000_000 });
    const bar = makeHarness().create("ecosystem-policy-bar");
    bar.policyState = frozenWithOverride(new Date(1_005_000).toISOString());
    assert.ok(bar.shadowRoot.innerHTML.includes("Scoped override suspended while frozen"));
    t.mock.timers.tick(5100);
    assert.ok(!bar.shadowRoot.innerHTML.includes("Scoped override suspended while frozen"));
    assert.ok(bar.shadowRoot.innerHTML.includes("FROZEN"));
    assert.strictEqual(bar.events.filter((e) => e.type === "ecosystem-override-expired").length, 1);
    bar.disconnectedCallback();
});

test("a frozen bar does not re-render every second while waiting for expiry", (t) => {
    t.mock.timers.enable({ apis: ["setTimeout", "setInterval", "Date"], now: 1_000_000 });
    const bar = makeHarness().create("ecosystem-policy-bar");
    bar.policyState = frozenWithOverride(new Date(1_060_000).toISOString());
    let renders = 0;
    const realRender = bar.render.bind(bar);
    bar.render = () => { renders += 1; realRender(); };
    t.mock.timers.tick(30_000);
    assert.strictEqual(renders, 0);
    bar.disconnectedCallback();
    t.mock.timers.tick(60_000);
    assert.strictEqual(renders, 0, "disconnect cancels the pending expiry timer");
});

test("ecosystem-override-expired fires after the DOM shows the restored state", () => {
    const h = makeHarness();
    const bar = h.create("ecosystem-policy-bar");
    let htmlAtDispatch = null;
    bar.dispatchEvent = (ev) => {
        if (ev.type === "ecosystem-override-expired") htmlAtDispatch = bar.shadowRoot.innerHTML;
        return true;
    };
    bar.policyState = expiredOverride("g-2");
    assert.ok(htmlAtDispatch.includes("RESTRICTIONS: ON"));
    assert.ok(htmlAtDispatch.includes("Previous scoped override expired"));
    bar.disconnectedCallback();
});

test("a listener that sets a frozen state from the expiry event is not overwritten", () => {
    const bar = makeHarness().create("ecosystem-policy-bar");
    bar.dispatchEvent = (ev) => {
        if (ev.type === "ecosystem-override-expired") {
            bar.policyState = { mode: "freeze", frozen: true, authority: "hub_synced",
                freeze_info: { initiated_by: "hub", reason: "expiry handler" } };
        }
        return true;
    };
    bar.policyState = expiredOverride("g-3");
    assert.ok(bar.shadowRoot.innerHTML.includes("FROZEN"));
    assert.ok(!bar.shadowRoot.innerHTML.includes("RESTRICTIONS: ON"));
    bar.disconnectedCallback();
});

// ── The bar must not destroy its Freeze control on every update ──
// A rebuild replaces <ecosystem-freeze-button> with a fresh, un-armed one. In
// ambient/confirm-tap mode that made the second tap arm again instead of
// confirming whenever a tick or a hub poll landed between the two taps.

const activeOverride = (expiresAt) => ({
    mode: "normal", frozen: false, restrictions: "off_scoped", authority: "hub_synced",
    active_override: { grant_id: "g-9", expires_at: expiresAt, issued_by: "admin", reason: "maint",
        scope: { apps: ["a"], devices: ["d"], action_classes: ["investigate"] } },
});

test("re-assigning an identical policy state does not rebuild the bar", () => {
    const bar = makeHarness().create("ecosystem-policy-bar");
    bar.setAttribute("view-mode", "ambient");
    const state = () => ({ mode: "normal", restrictions: "on", frozen: false, authority: "hub_synced" });
    bar.policyState = state();
    const freezeBtn = bar.shadowRoot.querySelector("ecosystem-freeze-button");

    bar.policyState = state();          // e.g. the next hub poll, nothing changed

    assert.strictEqual(bar.shadowRoot.querySelector("ecosystem-freeze-button"), freezeBtn);
    bar.disconnectedCallback();
});

test("the countdown ticks in place without rebuilding the bar", (t) => {
    t.mock.timers.enable({ apis: ["setTimeout", "setInterval", "Date"], now: 1_000_000 });
    const bar = makeHarness().create("ecosystem-policy-bar");
    bar.setAttribute("view-mode", "ambient");
    bar.policyState = activeOverride(new Date(1_000_000 + 10 * 60_000).toISOString());
    assert.ok(bar.shadowRoot.innerHTML.includes('data-role="countdown"'));
    const freezeBtn = bar.shadowRoot.querySelector("ecosystem-freeze-button");
    const countdown = bar.shadowRoot.querySelector('[data-role="countdown"]');

    t.mock.timers.tick(3000);

    assert.strictEqual(bar.shadowRoot.querySelector("ecosystem-freeze-button"), freezeBtn);
    assert.match(countdown.textContent, /remaining$/);
    const first = countdown.textContent;
    t.mock.timers.tick(60_000);
    assert.notStrictEqual(countdown.textContent, first);
    bar.disconnectedCallback();
});

test("a real state change still rebuilds the bar", () => {
    const bar = makeHarness().create("ecosystem-policy-bar");
    bar.policyState = { mode: "normal", restrictions: "on", frozen: false, authority: "hub_synced" };
    const before = bar.shadowRoot.querySelector("ecosystem-freeze-button");
    bar.policyState = { mode: "freeze", frozen: true, authority: "hub_synced",
        freeze_info: { initiated_by: "operator", reason: "drill" } };
    assert.notStrictEqual(bar.shadowRoot.querySelector("ecosystem-freeze-button"), before);
    assert.ok(bar.shadowRoot.innerHTML.includes("FROZEN"));
    bar.disconnectedCallback();
});

test("an expiry further out than a timer can hold is re-armed, not fired early", (t) => {
    t.mock.timers.enable({ apis: ["setTimeout", "setInterval", "Date"], now: 1_000_000 });
    const MAX = 2147483647;
    const thirtyDays = 30 * 24 * 3600 * 1000;      // > MAX
    const bar = makeHarness().create("ecosystem-policy-bar");
    bar.policyState = frozenWithOverride(new Date(1_000_000 + thirtyDays).toISOString());
    const expired = () => bar.events.filter((e) => e.type === "ecosystem-override-expired").length;

    t.mock.timers.tick(MAX);
    assert.strictEqual(expired(), 0);
    assert.ok(bar.shadowRoot.innerHTML.includes("Scoped override suspended while frozen"));
    assert.notStrictEqual(bar._expiryTimer, null);

    t.mock.timers.tick(thirtyDays - MAX + 100);
    assert.strictEqual(expired(), 1);
    assert.ok(!bar.shadowRoot.innerHTML.includes("Scoped override suspended while frozen"));
    bar.disconnectedCallback();
});

test("the expiry event fires once per grant however often the bar renders", () => {
    const bar = makeHarness().create("ecosystem-policy-bar");
    bar.policyState = expiredOverride("g-7");
    bar.render();
    bar.policyState = expiredOverride("g-7");
    assert.strictEqual(bar.events.filter((e) => e.type === "ecosystem-override-expired").length, 1);
    bar.policyState = expiredOverride("g-8");
    assert.strictEqual(bar.events.filter((e) => e.type === "ecosystem-override-expired").length, 2);
    bar.disconnectedCallback();
});
