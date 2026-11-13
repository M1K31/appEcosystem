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

// ── Behaviour ported from the vendored copy, pinned here so it cannot be
//    silently lost again (each assertion names the thing it protects). ──

const focusTarget = (log, name) => ({ name, focus() { log.push(name); } });

test("Tab is trapped at both ends of the dialog and left alone in the middle", () => {
    const modal = makeHarness().create("ecosystem-override-modal");
    modal.setAttribute("open", "");
    const log = [];
    const [first, middle, last] = ["first", "middle", "last"].map((n) => focusTarget(log, n));
    modal._focusable = () => [first, middle, last];
    modal.shadowRoot.contains = (el) => [first, middle, last].includes(el);
    const press = (active, shiftKey) => {
        modal.shadowRoot.activeElement = active;
        let prevented = false;
        modal._onKeyDown({ key: "Tab", shiftKey, preventDefault() { prevented = true; } });
        return prevented;
    };

    assert.strictEqual(press(last, false), true);      // Tab off the end wraps…
    assert.deepStrictEqual(log, ["first"]);
    assert.strictEqual(press(first, true), true);      // …and Shift+Tab off the start
    assert.deepStrictEqual(log, ["first", "last"]);
    assert.strictEqual(press(middle, false), false);   // inside: the browser handles it
    assert.strictEqual(press(middle, true), false);
    assert.strictEqual(press(null, false), true);      // focus escaped: pull it back in
    assert.deepStrictEqual(log, ["first", "last", "first"]);
});

test("a rejected submit clears the TOTP and the passkey assertion", () => {
    const modal = makeHarness().create("ecosystem-override-modal");
    modal.setAttribute("open", "");
    const drafts = [];
    modal._restoreDraft = (draft) => { drafts.push(draft); };
    modal.shadowRoot.querySelector('input[name="totp_code"]').value = "123456";

    modal._collectAndSubmit();          // nothing ticked => invalid

    assert.strictEqual(modal.events.filter((e) => e.type === "ecosystem-override-submit").length, 0);
    assert.ok(modal._errors.length > 0);
    assert.strictEqual(drafts.at(-1).totp_code, "");   // not carried into the re-render

    modal.setPasskeyAssertion("one-shot-assertion");
    modal._collectAndSubmit();
    assert.strictEqual(modal._passkeyAssertion, "");
});

test("typed input survives a re-render but never an open/close transition", () => {
    const modal = makeHarness().create("ecosystem-override-modal");
    modal.setAttribute("open", "");
    const drafts = [];
    modal._restoreDraft = (draft) => { drafts.push(draft); };
    const type = () => { modal.shadowRoot.querySelector('input[name="totp_code"]').value = "123456"; };

    type();
    modal.render();                     // e.g. duration changed
    assert.strictEqual(drafts.at(-1).totp_code, "123456");

    type();
    modal.removeAttribute("open");      // closed by the host
    assert.strictEqual(drafts.at(-1), null);

    type();
    modal.setAttribute("open", "");     // reopened: a fresh form
    assert.strictEqual(drafts.at(-1), null);
});

test("close() drops the passkey assertion and duration choice and announces the cancel", () => {
    const modal = makeHarness().create("ecosystem-override-modal");
    modal.open();
    modal.setPasskeyAssertion("one-shot-assertion");
    modal._selectedDuration = "until_revoked";
    let returned = false;
    modal._restoreFocusTo = { isConnected: true, focus() { returned = true; } };

    modal.close();

    assert.strictEqual(modal._passkeyAssertion, "");
    assert.strictEqual(modal._selectedDuration, "30m");
    assert.strictEqual(modal._isOpen(), false);
    assert.strictEqual(returned, true);
    assert.strictEqual(modal.events.filter((e) => e.type === "ecosystem-override-cancel").length, 1);
});

test("focus moves into the dialog once, on open, and not on later re-renders", () => {
    const modal = makeHarness().create("ecosystem-override-modal");
    const log = [];
    modal._focusable = () => [focusTarget(log, "first")];

    modal.open();
    assert.deepStrictEqual(log, ["first"]);
    modal.render();
    assert.deepStrictEqual(log, ["first"]);
});

test("open=\"false\" renders the sheet hidden", () => {
    const modal = makeHarness().create("ecosystem-override-modal");
    modal.setAttribute("open", "false");
    assert.match(modal.shadowRoot.innerHTML, /class="modal-backdrop" hidden>/);
    modal.setAttribute("open", "true");
    assert.doesNotMatch(modal.shadowRoot.innerHTML, /class="modal-backdrop" hidden>/);
});
