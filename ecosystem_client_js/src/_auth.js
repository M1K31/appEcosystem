"use strict";

/**
 * Resolve @smartindustriesllc/ecosystem-auth from node_modules when installed
 * as a package, or fall back to the sibling monorepo auth/js source during
 * local development and testing.
 */
const path = require("path");

let authModule;
try {
    authModule = require("@smartindustriesllc/ecosystem-auth");
} catch {
    authModule = require(path.resolve(__dirname, "../../auth/js/src/tokens"));
}

module.exports = authModule;

