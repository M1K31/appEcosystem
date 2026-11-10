"use strict";

/**
 * Minimal DOM stand-in for exercising the custom elements under `node --test`.
 *
 * It does not parse HTML. `shadowRoot.querySelector(sel)` returns a stub element
 * for ANY selector (the same stub for the same selector until the next
 * `innerHTML` assignment, which is how a real re-render replaces nodes), so
 * tests assert on focus bookkeeping and dispatched events, not on DOM structure.
 */
const { registerEcosystemControls } = require("../../src/index");

function makeStub(root, selector) {
    return {
        selector,
        value: "",
        checked: false,
        isConnected: true,
        listeners: {},
        addEventListener(type, fn) {
            (this.listeners[type] = this.listeners[type] || []).push(fn);
        },
        removeEventListener() {},
        focus() {
            root.activeElement = this;
            root.focusCalls.push(selector);
        },
    };
}

function makeShadowRoot() {
    const stubs = new Map();
    let html = "";
    const root = {
        activeElement: null,
        focusCalls: [],
        listeners: {},
        get innerHTML() {
            return html;
        },
        set innerHTML(value) {
            html = String(value);
            // A re-render replaces every node, so the focused one is gone.
            stubs.clear();
            root.activeElement = null;
        },
        querySelector(selector) {
            if (!stubs.has(selector)) {
                stubs.set(selector, makeStub(root, selector));
            }
            return stubs.get(selector);
        },
        querySelectorAll() {
            return [];
        },
        contains(el) {
            return Array.from(stubs.values()).includes(el);
        },
        addEventListener(type, fn) {
            (root.listeners[type] = root.listeners[type] || []).push(fn);
        },
        removeEventListener(type, fn) {
            root.listeners[type] = (root.listeners[type] || []).filter((f) => f !== fn);
        },
    };
    return root;
}

function makeHarness() {
    class FakeElement {
        constructor() {
            this._attrs = new Map();
            this.events = [];
            this.shadowRoot = null;
        }
        attachShadow() {
            this.shadowRoot = makeShadowRoot();
            return this.shadowRoot;
        }
        getAttribute(k) { return this._attrs.has(k) ? this._attrs.get(k) : null; }
        setAttribute(k, v) { this._attrs.set(k, String(v)); if (this.attributeChangedCallback) this.attributeChangedCallback(k); }
        hasAttribute(k) { return this._attrs.has(k); }
        removeAttribute(k) { this._attrs.delete(k); if (this.attributeChangedCallback) this.attributeChangedCallback(k); }
        dispatchEvent(ev) { this.events.push(ev); return true; }
    }

    const defined = new Map();
    const registry = {
        get: (name) => defined.get(name),
        define: (name, ctor) => defined.set(name, ctor),
    };

    function create(tagName) {
        if (defined.size === 0) {
            registerEcosystemControls({ customElements: registry, HTMLElement: FakeElement });
        }
        const Ctor = defined.get(tagName);
        if (!Ctor) {
            throw new Error(`Unknown element: ${tagName}`);
        }
        return new Ctor();
    }

    return { FakeElement, defined, registry, create };
}

module.exports = { makeHarness };
