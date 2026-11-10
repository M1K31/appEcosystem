"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const { SHARED_STYLES } = require("../src/styles");

const theme = fs.readFileSync(path.resolve(__dirname, "../../../theme/ecosystem-theme.css"), "utf8");

const block = (css, selectorRe) => (css.match(selectorRe) || [""])[0];
const prop = (b, name) => (b.match(new RegExp(`${name}:\\s*([^;]+);`)) || [])[1];

test("OS light preference matches explicit light theme for status colours", () => {
    const explicit = block(theme, /\[data-theme="light"\]\s*\{[^}]*\}/s);
    const media = block(theme, /@media \(prefers-color-scheme: light\)\s*\{\s*:root:not\(\[data-theme\]\)\s*\{[^}]*\}/s);
    for (const name of ["--color-success", "--color-error", "--color-warning", "--text-on-accent"]) {
        assert.ok(prop(explicit, name), `${name} missing from explicit light block`);
        assert.strictEqual(prop(media, name), prop(explicit, name), name);
    }
});

test("explicit data-theme=\"dark\" gets the base palette", () => {
    assert.ok(/:root,\s*\[data-theme="dark"\]\s*\{/.test(theme));
});

test("a dark island does not inherit another theme's on-accent text colour", () => {
    const base = block(theme, /:root,\s*\[data-theme="dark"\]\s*\{[^}]*\}/s);
    assert.strictEqual(prop(base, "--text-on-accent"), "hsl(0, 0%, 100%)");
});

test("primary button hover keeps an accent background", () => {
    const rule = block(SHARED_STYLES, /button\.hig-btn\[data-variant="primary"\]:hover:not\(:disabled\)\s*\{[^}]*\}/s);
    assert.ok(rule, "primary hover rule missing");
    assert.ok(!rule.includes("--_bg-hover"));
    assert.ok(rule.includes("var(--_accent)"));
});

test("filled-button hover darkens rather than lightens the fill", () => {
    // Lightening a fill under a white label lowers its contrast; darkening is
    // safe for white-on-fill and costs nothing for dark-on-yellow (cyberpunk).
    for (const variant of ["primary", "critical"]) {
        const rule = block(SHARED_STYLES, new RegExp(`button\\.hig-btn\\[data-variant="${variant}"\\]:hover:not\\(:disabled\\)\\s*\\{[^}]*\\}`, "s"));
        const m = rule.match(/brightness\(([\d.]+)\)/);
        assert.ok(m, `${variant} hover has no brightness filter`);
        assert.ok(Number(m[1]) < 1, `${variant} hover brightness ${m[1]} lightens the fill`);
    }
});

test("critical (armed Freeze) button hover keeps its error background", () => {
    const rule = block(SHARED_STYLES, /button\.hig-btn\[data-variant="critical"\]:hover:not\(:disabled\)\s*\{[^}]*\}/s);
    assert.ok(rule, "critical hover rule missing");
    assert.ok(!rule.includes("--_bg-hover"));
    assert.ok(rule.includes("var(--_error)"));
});
