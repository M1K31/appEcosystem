"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const { makeHarness } = require("./helpers/fake_dom");

test("arm timeout does not pull focus when the operator has moved on", (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const btn = makeHarness().create("ecosystem-freeze-button");
    btn.setAttribute("confirm-tap", "");
    btn._handleClick();                       // arms; focus restored to trigger
    btn.shadowRoot.activeElement = null;      // operator tabbed away
    btn.shadowRoot.focusCalls.length = 0;
    t.mock.timers.tick(3000);
    assert.strictEqual(btn._armed, false);
    assert.deepStrictEqual(btn.shadowRoot.focusCalls, []);
});

test("arm timeout keeps focus when the trigger still has it", (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const btn = makeHarness().create("ecosystem-freeze-button");
    btn.setAttribute("confirm-tap", "");
    btn._handleClick();
    btn.shadowRoot.focusCalls.length = 0;     // activeElement is the trigger stub
    t.mock.timers.tick(3000);
    assert.strictEqual(btn.shadowRoot.focusCalls.length, 1);
});

test("held Enter/Space cannot arm then confirm", () => {
    const btn = makeHarness().create("ecosystem-freeze-button");
    for (const key of ["Enter", " "]) {
        let prevented = false;
        btn._onTriggerKeyDown({ key, repeat: true, preventDefault() { prevented = true; } });
        assert.strictEqual(prevented, true);
    }
    let prevented = false;
    btn._onTriggerKeyDown({ key: "Enter", repeat: false, preventDefault() { prevented = true; } });
    assert.strictEqual(prevented, false);
    btn._onTriggerKeyDown({ key: "a", repeat: true, preventDefault() { prevented = true; } });
    assert.strictEqual(prevented, false);
});

test("key-repeat guard is attached while connected and removed on disconnect", () => {
    const btn = makeHarness().create("ecosystem-freeze-button");
    btn.connectedCallback();
    assert.deepStrictEqual(btn.shadowRoot.listeners.keydown, [btn._onTriggerKeyDown]);
    btn.connectedCallback();                  // re-connect must not double-register
    assert.strictEqual(btn.shadowRoot.listeners.keydown.length, 1);
    btn.disconnectedCallback();
    assert.deepStrictEqual(btn.shadowRoot.listeners.keydown, []);
});
