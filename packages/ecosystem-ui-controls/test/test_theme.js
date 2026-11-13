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
    assert.ok(rule.includes("var(--_fill-accent)"));
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
    assert.ok(rule.includes("var(--_fill-critical)"));
});

// ── Filled-button label contrast (Apple HIG / WCAG 2.1 AA: 4.5:1 for text
//    under 18pt that is not bold) ─────────────────────────────────────────

function hslToRgb(h, s, l) {
    s /= 100; l /= 100;
    const k = (n) => (n + h / 30) % 12;
    const a = s * Math.min(l, 1 - l);
    const f = (n) => l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)));
    return [f(0), f(8), f(4)];
}

function parseColor(value) {
    const hsl = /hsl\(\s*([\d.]+)\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%\s*\)/.exec(value);
    if (hsl) return hslToRgb(Number(hsl[1]), Number(hsl[2]), Number(hsl[3]));
    const hex = /#([0-9a-f]{6})\b/i.exec(value);
    if (hex) return [0, 2, 4].map((i) => parseInt(hex[1].slice(i, i + 2), 16) / 255);
    throw new Error(`cannot parse colour: ${value}`);
}

function contrast(a, b) {
    const lum = ([r, g, bl]) => {
        const c = (v) => (v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4));
        return 0.2126 * c(r) + 0.7152 * c(g) + 0.0722 * c(bl);
    };
    const [x, y] = [lum(parseColor(a)), lum(parseColor(b))];
    return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

const THEME_BLOCKS = {
    dark: /:root,\s*\[data-theme="dark"\]\s*\{[^}]*\}/s,
    light: /\[data-theme="light"\]\s*\{[^}]*\}/s,
    cyberpunk: /\[data-theme="cyberpunk"\]\s*\{[^}]*\}/s,
    "OS light": /@media \(prefers-color-scheme: light\)\s*\{\s*:root:not\(\[data-theme\]\)\s*\{[^}]*\}/s,
};

for (const [name, re] of Object.entries(THEME_BLOCKS)) {
    test(`filled buttons have at least 4.5:1 label contrast in the ${name} theme`, () => {
        const css = block(theme, re);
        for (const [fill, label] of [["--fill-accent", "--text-on-accent"], ["--fill-critical", "--text-on-critical"]]) {
            const fillValue = prop(css, fill);
            const labelValue = prop(css, label);
            assert.ok(fillValue, `${fill} missing in ${name}`);
            assert.ok(labelValue, `${label} missing in ${name}`);
            const ratio = contrast(fillValue, labelValue);
            assert.ok(ratio >= 4.5, `${name} ${fill} vs ${label}: ${ratio.toFixed(2)}:1`);
        }
    });
}

test("filled buttons use the fill tokens, with compliant fallbacks when no theme is loaded", () => {
    const host = block(SHARED_STYLES, /:host\s*\{[^}]*\}/s);
    const fallback = (name) => {
        const m = new RegExp(`${name}:\\s*var\\(--[\\w-]+,\\s*(hsl\\([^)]*\\)|#[0-9a-fA-F]{6})\\)`).exec(host);
        assert.ok(m, `${name} has no literal fallback`);
        return m[1];
    };
    assert.ok(contrast(fallback("--_fill-accent"), fallback("--_text-on-accent")) >= 4.5);
    assert.ok(contrast(fallback("--_fill-critical"), fallback("--_text-on-critical")) >= 4.5);

    const primary = block(SHARED_STYLES, /button\.hig-btn\[data-variant="primary"\]\s*\{[^}]*\}/s);
    assert.ok(primary.includes("var(--_fill-accent)") && primary.includes("var(--_text-on-accent)"));
    // "critical" appears in two rules (one shared with "danger"); the later,
    // critical-only rule wins the cascade, so judge every declaration for it.
    const critical = [...SHARED_STYLES.matchAll(/button\.hig-btn\[data-variant="critical"\]\s*\{[^}]*\}/gs)]
        .map((m) => m[0]).join("\n");
    assert.ok(critical.includes("var(--_fill-critical)") && critical.includes("var(--_text-on-critical)"));
    assert.ok(!critical.includes("#ffffff"));
});
