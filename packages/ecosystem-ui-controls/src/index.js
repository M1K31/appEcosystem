"use strict";

const model = require("./model");
const styles = require("./styles");
const components = require("./components");

// Auto-register when loaded in a browser context with Custom Elements v1 support.
if (typeof window !== "undefined" && typeof customElements !== "undefined") {
    components.registerEcosystemControls();
}

module.exports = Object.assign({}, model, styles, components);

