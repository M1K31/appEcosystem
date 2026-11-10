"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const { makeHarness } = require("./helpers/fake_dom");
const { SHARED_STYLES } = require("../src/styles");

const theme = fs.readFileSync(path.resolve(__dirname, "../../../theme/ecosystem-theme.css"), "utf8");

test("override modal traps Tab and scopes drafts (ported from MagicMirror)", () => {
    const modal = makeHarness().create("ecosystem-override-modal");
    assert.strictEqual(typeof modal._trapTab, "function");
    assert.strictEqual(typeof modal._focusable, "function");
    assert.ok("_skipDraftRestore" in modal);
});

test("primary button text colour comes from --text-on-accent", () => {
    assert.ok(SHARED_STYLES.includes("var(--text-on-accent"));
});

test("theme defines --text-on-accent for light and cyberpunk and no global body margin reset", () => {
    assert.ok(/\[data-theme="light"\][^}]*--text-on-accent/s.test(theme));
    assert.ok(/\[data-theme="cyberpunk"\][^}]*--text-on-accent:\s*hsl\(290, 80%, 6%\)/s.test(theme));
    assert.ok(!/body\s*\{[^}]*margin:\s*0/s.test(theme));
});
