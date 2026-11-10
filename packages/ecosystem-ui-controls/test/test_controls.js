"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { makeHarness } = require("./helpers/fake_dom");

const {
    ALWAYS_ENFORCED_INVARIANTS,
    computeEffectivePolicyBanner,
    validateOverrideForm,
    computeFreezeButtonState,
    computeMicPillState,
    registerEcosystemControls,
} = require("../src/index");

const NOW = Date.parse("2026-11-01T18:00:00Z");

test("Default policy bar renders Restrictions: On with admin actions", () => {
    const banner = computeEffectivePolicyBanner(
        {
            schema_version: 1,
            policy_version: 2,
            mode: "normal",
            restrictions: "on",
            frozen: false,
            always_enforced: ["freeze"],
            authority: "hub_synced",
            updated_at: "2026-11-01T17:59:00Z",
        },
        { viewMode: "admin", nowMs: NOW }
    );

    assert.strictEqual(banner.effectiveState, "restrictions_on");
    assert.strictEqual(banner.badgeText, "RESTRICTIONS: ON");
    assert.strictEqual(banner.icon, "lock-shield");
    assert.strictEqual(banner.actions.canFreeze, true);
    assert.strictEqual(banner.actions.canManageRestrictions, true);
    assert.strictEqual(banner.actions.canRestoreRestrictions, false);
    assert.strictEqual(banner.actions.canResume, false);
});

test("Active scoped override renders countdown, scope, 1-click restore, and flags unreachable devices", () => {
    const banner = computeEffectivePolicyBanner(
        {
            mode: "incident",
            restrictions: "off_scoped",
            frozen: false,
            authority: "hub_synced",
            active_override: {
                grant_id: "ov-01",
                issued_by: "mikel",
                reason: "Active red-team containment drill",
                scope: {
                    apps: ["openeye", "aegissiem"],
                    devices: ["nvr-01", "sensor-02"],
                    action_classes: ["contain"],
                },
                bypassed: ["approvals"],
                issued_at: "2026-11-01T17:50:00Z",
                expires_at: "2026-11-01T18:20:00Z",
                applied_devices: ["nvr-01"],
                pending_devices: [],
                unreachable_devices: ["sensor-02"],
            },
        },
        { viewMode: "admin", nowMs: NOW }
    );

    assert.strictEqual(banner.effectiveState, "restrictions_off_scoped");
    assert.strictEqual(banner.countdownText, "20m 00s remaining");
    assert.strictEqual(banner.deviceSync.hasUnreachable, true);
    assert.strictEqual(banner.deviceSync.summaryText, "1 applied · 1 unreachable");
    assert.strictEqual(banner.actions.canRestoreRestrictions, true);
    assert.strictEqual(banner.actions.canFreeze, true);
});

test("Expired scoped override fails closed immediately to Restrictions: On without server poll", () => {
    const banner = computeEffectivePolicyBanner(
        {
            mode: "normal",
            restrictions: "off_scoped",
            frozen: false,
            authority: "hub_synced",
            active_override: {
                grant_id: "ov-expired",
                issued_by: "mikel",
                reason: "Short test window",
                scope: { apps: ["openeye"], devices: ["nvr-01"], action_classes: ["investigate"] },
                bypassed: ["approvals"],
                issued_at: "2026-11-01T17:30:00Z",
                expires_at: "2026-11-01T17:45:00Z",
            },
        },
        { viewMode: "admin", nowMs: NOW }
    );

    assert.strictEqual(banner.effectiveState, "restrictions_on");
    assert.strictEqual(banner.overrideExpired, true);
    assert.ok(banner.detailText.includes("expired"));
});

test("Freeze ALWAYS supersedes an active Restrictions: Off (Scoped) session", () => {
    const banner = computeEffectivePolicyBanner(
        {
            mode: "freeze",
            restrictions: "off_scoped",
            frozen: true,
            authority: "hub_synced",
            freeze_info: {
                initiated_by: "MagicMirror Hallway HUD",
                reason: "Emergency wall tap",
                since: "2026-11-01T17:59:30Z",
                acknowledged_devices: ["hub-01", "nvr-01"],
                unreachable_devices: ["garage-pi"],
            },
            active_override: {
                grant_id: "ov-active",
                issued_by: "mikel",
                reason: "Maintenance",
                scope: { apps: ["openeye"], devices: ["nvr-01"], action_classes: ["contain"] },
                bypassed: ["approvals"],
                issued_at: "2026-11-01T17:50:00Z",
                expires_at: "2026-11-01T18:30:00Z",
            },
        },
        { viewMode: "admin", nowMs: NOW }
    );

    assert.strictEqual(banner.effectiveState, "frozen");
    assert.strictEqual(banner.badgeText, "FROZEN");
    assert.strictEqual(banner.overrideSuspended, true);
    assert.ok(banner.detailText.includes("Scoped override suspended while frozen"));
    assert.strictEqual(banner.deviceSync.summaryText, "2 frozen · 1 unreachable");
    assert.strictEqual(banner.actions.canResume, true);
});

test("Ambient display view-mode strips all admin/override/resume privileges while keeping Freeze", () => {
    const normalAmbient = computeEffectivePolicyBanner(
        { mode: "normal", restrictions: "on", frozen: false, authority: "hub_synced" },
        { viewMode: "ambient", nowMs: NOW }
    );
    assert.strictEqual(normalAmbient.actions.canFreeze, true);
    assert.strictEqual(normalAmbient.actions.canManageRestrictions, false);
    assert.strictEqual(normalAmbient.actions.canRestoreRestrictions, false);
    assert.strictEqual(normalAmbient.actions.canResume, false);

    const frozenAmbient = computeEffectivePolicyBanner(
        { mode: "freeze", restrictions: "on", frozen: true, authority: "hub_synced" },
        { viewMode: "ambient", nowMs: NOW }
    );
    assert.strictEqual(frozenAmbient.actions.canResume, false);
    assert.strictEqual(frozenAmbient.actions.canFreeze, false);
});

test("validateOverrideForm enforces scope, reason, step-up auth, until_revoked confirm, and always_enforced", () => {
    const bad = validateOverrideForm({ apps: [], devices: [], actionClasses: [], reason: "short" }, NOW);
    assert.strictEqual(bad.valid, false);
    assert.ok(bad.errors.length >= 4);

    const unconfirmedUnbounded = validateOverrideForm(
        {
            apps: ["openeye"],
            devices: ["nvr-01"],
            actionClasses: ["contain"],
            duration: "until_revoked",
            confirmUntilRevoked: false,
            reason: "Extended incident response session",
            stepUpMethod: "totp",
            stepUpCredential: "123456",
        },
        NOW
    );
    assert.strictEqual(unconfirmedUnbounded.valid, false);

    const good = validateOverrideForm(
        {
            apps: ["openeye"],
            devices: ["nvr-01"],
            actionClasses: ["contain", "investigate"],
            duration: "30m",
            reason: "Investigating perimeter camera alert burst",
            stepUpMethod: "totp",
            stepUpCredential: "654321",
        },
        NOW
    );
    assert.strictEqual(good.valid, true);
    assert.strictEqual(good.payload.expires_at, "2026-11-01T18:30:00Z");
    assert.deepStrictEqual(
        good.payload.always_enforced,
        ALWAYS_ENFORCED_INVARIANTS.map((i) => i.id)
    );
});

test("Freeze button and Mic pill view-models enforce two-tap safety and zero-audio-retention caption", () => {
    const armed = computeFreezeButtonState({ frozen: false, viewMode: "ambient", confirmTap: true, armed: true });
    assert.strictEqual(armed.mode, "armed");
    assert.strictEqual(armed.label, "Tap Again to Freeze");

    const frozenWall = computeFreezeButtonState({ frozen: true, viewMode: "ambient" });
    assert.strictEqual(frozenWall.disabled, true);

    const micDefault = computeMicPillState({});
    assert.strictEqual(micDefault.state, "muted");
    assert.strictEqual(micDefault.isMuted, true);
    assert.ok(micDefault.privacyCaption.includes("No audio retained"));

    const micUnavail = computeMicPillState({
        state: "unavailable",
        unavailableReason: "Tier T0: voice disabled",
    });
    assert.strictEqual(micUnavail.canToggleMute, false);
    assert.strictEqual(micUnavail.statusLabel, "Tier T0: voice disabled");
});

test("Custom elements register and render Shadow DOM HTML cleanly (including browser bundle)", () => {
    const { FakeElement, defined, registry: fakeRegistry } = makeHarness();

    registerEcosystemControls({ customElements: fakeRegistry, HTMLElement: FakeElement });
    assert.strictEqual(defined.size, 4);
    assert.ok(defined.has("ecosystem-policy-bar"));
    assert.ok(defined.has("ecosystem-override-modal"));
    assert.ok(defined.has("ecosystem-freeze-button"));
    assert.ok(defined.has("ecosystem-mic-pill"));

    const BarCtor = defined.get("ecosystem-policy-bar");
    const bar = new BarCtor();
    bar.setAttribute("view-mode", "ambient");
    bar.policyState = { mode: "normal", restrictions: "on", frozen: false, authority: "hub_synced" };
    assert.ok(bar.shadowRoot.innerHTML.includes("RESTRICTIONS: ON"));
    assert.ok(!bar.shadowRoot.innerHTML.includes("Manage Restrictions"));
    bar.disconnectedCallback();

    // Verify self-contained browser bundle evaluates cleanly and exposes EcosystemUIControls
    const bundleCode = fs.readFileSync(
        path.resolve(__dirname, "../dist/ecosystem-ui-controls.js"),
        "utf8"
    );
    const sandbox = {};
    sandbox.globalThis = sandbox;
    vm.runInNewContext(bundleCode, sandbox);
    assert.ok(sandbox.EcosystemUIControls);
    assert.strictEqual(typeof sandbox.EcosystemUIControls.computeEffectivePolicyBanner, "function");
});


test("Missing policy state renders STATUS: UNKNOWN with Freeze still available", () => {
    for (const raw of [null, undefined, "frozen", 42, []]) {
        const vm = computeEffectivePolicyBanner(raw, { viewMode: "admin" });
        assert.strictEqual(vm.effectiveState, "unknown");
        assert.strictEqual(vm.badgeText, "STATUS: UNKNOWN");
        assert.strictEqual(vm.severity, "warning");
        assert.strictEqual(vm.headline, "Waiting for policy state");
        assert.strictEqual(vm.overrideExpired, false);
        assert.strictEqual(vm.deviceSync.hasUnreachable, false);
        assert.deepStrictEqual(vm.actions, {
            canFreeze: true, canResume: false, canManageRestrictions: false, canRestoreRestrictions: false,
        });
    }
    assert.strictEqual(computeEffectivePolicyBanner(null, { viewMode: "ambient" }).viewMode, "ambient");
    assert.strictEqual(computeEffectivePolicyBanner({}, {}).effectiveState, "restrictions_on");
});

test("Policy bar with no state, or unparseable state, shows UNKNOWN and keeps Freeze", () => {
    const bar = makeHarness().create("ecosystem-policy-bar");
    bar.connectedCallback();
    assert.ok(bar.shadowRoot.innerHTML.includes("STATUS: UNKNOWN"));
    assert.ok(!bar.shadowRoot.innerHTML.includes("RESTRICTIONS: ON"));
    assert.ok(bar.shadowRoot.innerHTML.includes("<ecosystem-freeze-button"));
    assert.ok(!bar.shadowRoot.innerHTML.includes("Manage Restrictions"));

    bar.setAttribute("policy-state", "{not json");
    assert.ok(bar.shadowRoot.innerHTML.includes("STATUS: UNKNOWN"));
    bar.disconnectedCallback();
});

test("Unconfirmed local freeze is labelled and keeps a retry", () => {
    const base = { mode: "freeze", frozen: true, authority: "standalone_local",
        freeze_info: { initiated_by: "magicmirror_display", reason: "x" } };
    const unconfirmed = computeEffectivePolicyBanner({ ...base, freeze_confirmed: false }, { viewMode: "ambient" });
    assert.strictEqual(unconfirmed.effectiveState, "frozen");
    assert.strictEqual(unconfirmed.badgeText, "FROZEN (LOCAL ONLY)");
    assert.strictEqual(unconfirmed.severity, "critical");
    assert.strictEqual(unconfirmed.headline, "Freeze held on this display — mesh delivery not confirmed");
    assert.strictEqual(unconfirmed.freezeUnconfirmed, true);
    assert.strictEqual(unconfirmed.actions.canFreeze, true);
    assert.strictEqual(unconfirmed.actions.canResume, false);
    const confirmed = computeEffectivePolicyBanner(base, { viewMode: "ambient" });
    assert.strictEqual(confirmed.badgeText, "FROZEN");
    assert.strictEqual(confirmed.freezeUnconfirmed, false);
    assert.strictEqual(confirmed.actions.canFreeze, false);
    // Only an explicit `false` means unconfirmed; `true` is a normal freeze.
    const explicit = computeEffectivePolicyBanner({ ...base, freeze_confirmed: true }, { viewMode: "ambient" });
    assert.deepStrictEqual(explicit, confirmed);
    // The flag means nothing when not frozen.
    const notFrozen = computeEffectivePolicyBanner({ mode: "normal", restrictions: "on", freeze_confirmed: false }, {});
    assert.strictEqual(notFrozen.effectiveState, "restrictions_on");
    assert.strictEqual(notFrozen.freezeUnconfirmed, false);
});

test("Unconfirmed freeze renders a Retry Freeze control that re-sends the freeze request", () => {
    const retryVm = computeFreezeButtonState({ frozen: false, viewMode: "ambient", confirmTap: true, retry: true });
    assert.strictEqual(retryVm.label, "Retry Freeze");
    assert.strictEqual(retryVm.disabled, false);
    assert.strictEqual(computeFreezeButtonState({ retry: true, confirmTap: true, armed: true }).label, "Tap Again to Freeze");
    assert.strictEqual(computeFreezeButtonState({}).label, "Freeze");

    const h = makeHarness();
    const bar = h.create("ecosystem-policy-bar");
    bar.setAttribute("view-mode", "ambient");
    bar.policyState = { mode: "freeze", frozen: true, authority: "standalone_local", freeze_confirmed: false,
        freeze_info: { initiated_by: "magicmirror_display", reason: "x" } };
    assert.ok(bar.shadowRoot.innerHTML.includes("FROZEN (LOCAL ONLY)"));
    assert.ok(/<ecosystem-freeze-button[^>]*retry="true"/.test(bar.shadowRoot.innerHTML));
    assert.ok(!/<ecosystem-freeze-button[^>]*frozen="true"/.test(bar.shadowRoot.innerHTML));
    bar.disconnectedCallback();

    const btn = h.create("ecosystem-freeze-button");
    btn.setAttribute("retry", "true");
    assert.ok(btn.shadowRoot.innerHTML.includes("Retry Freeze"));
    btn._handleClick();
    assert.strictEqual(btn.events.filter((e) => e.type === "ecosystem-freeze-request").length, 1);
});
