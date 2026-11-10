"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const { makeHarness } = require("./helpers/fake_dom");

test("open=\"false\" is closed: Tab and Escape are ignored", () => {
    const modal = makeHarness().create("ecosystem-override-modal");
    modal.setAttribute("open", "false");
    assert.strictEqual(modal._isOpen(), false);
    let prevented = false;
    let trapped = false;
    modal._trapTab = () => { trapped = true; };
    modal._onKeyDown({ key: "Tab", preventDefault() { prevented = true; } });
    assert.strictEqual(trapped, false);
    assert.strictEqual(prevented, false);
    const cancelsBefore = modal.events.length;
    modal._onKeyDown({ key: "Escape", preventDefault() { prevented = true; } });
    assert.strictEqual(modal.events.length, cancelsBefore);
    modal.setAttribute("open", "");
    assert.strictEqual(modal._isOpen(), true);
});

test("a valid submit clears the step-up credential and method", () => {
    const modal = makeHarness().create("ecosystem-override-modal");
    const defaultMethod = modal._stepUpMethod;
    modal._stepUpMethod = "passkey";
    modal._passkeyAssertion = "assertion-token";
    modal._resetStepUp();
    assert.strictEqual(modal._passkeyAssertion, "");
    assert.strictEqual(modal._stepUpMethod, defaultMethod);
    modal.setAttribute("open", "");
    assert.ok(!modal.shadowRoot.innerHTML.includes("Passkey Ready"));
});

test("submitting a valid form clears the passkey assertion and returns focus to the opener", () => {
    const modal = makeHarness().create("ecosystem-override-modal");
    modal.setAttribute("open", "");
    let focusReturned = false;
    modal._restoreFocusTo = { isConnected: true, focus() { focusReturned = true; } };
    modal.setPasskeyAssertion("assertion-token");
    const root = modal.shadowRoot;
    root.querySelectorAll = (sel) => {
        if (!sel.includes(":checked")) return [];
        return [{ value: sel.includes("action_classes") ? "investigate" : "openeye" }];
    };
    root.querySelector('select[name="duration"]').value = "30m";
    root.querySelector('input[name="reason"]').value = "Planned maintenance window";

    modal._collectAndSubmit();

    const submits = modal.events.filter((e) => e.type === "ecosystem-override-submit");
    assert.strictEqual(submits.length, 1, JSON.stringify(modal._errors));
    assert.strictEqual(modal._passkeyAssertion, "");
    assert.strictEqual(modal._stepUpMethod, "totp");
    assert.strictEqual(modal._isOpen(), false);
    assert.strictEqual(focusReturned, true);
    assert.strictEqual(modal._restoreFocusTo, null);
});
