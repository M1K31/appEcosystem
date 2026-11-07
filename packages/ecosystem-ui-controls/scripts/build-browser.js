"use strict";

/**
 * Zero-dependency browser bundle generator for @appecosystem/ui-controls.
 * Combines src/model.js, src/styles.js, src/components.js, and src/index.js
 * into a self-contained IIFE at dist/ecosystem-ui-controls.js suitable for
 * direct <script src="..."> tags in FastAPI/Jinja2, MagicMirror, or Hub UIs.
 */
const fs = require("fs");
const path = require("path");

const rootDir = path.resolve(__dirname, "..");
const srcDir = path.join(rootDir, "src");
const distDir = path.join(rootDir, "dist");

const modules = ["model.js", "styles.js", "components.js", "index.js"];

const entries = modules
    .map((filename) => {
        const key = `./${filename.replace(/\.js$/, "")}`;
        const code = fs.readFileSync(path.join(srcDir, filename), "utf8");
        return `${JSON.stringify(key)}: function (module, exports, require) {\n${code}\n}`;
    })
    .join(",\n");

const bundle = `/* @appecosystem/ui-controls v0.1.0 | MIT License | Smart Industries LLC (Mikel Smart) */
(function (global) {
  "use strict";
  var factories = {
${entries}
  };
  var cache = {};
  function localRequire(id) {
    var normalized = id.replace(/\\.js$/, "");
    if (cache[normalized]) return cache[normalized].exports;
    if (!factories[normalized]) throw new Error("Unknown module: " + id);
    var mod = { exports: {} };
    cache[normalized] = mod;
    factories[normalized](mod, mod.exports, localRequire);
    return mod.exports;
  }
  var api = localRequire("./index");
  if (global) {
    global.EcosystemUIControls = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : typeof window !== "undefined" ? window : this);
`;

fs.mkdirSync(distDir, { recursive: true });
const outFile = path.join(distDir, "ecosystem-ui-controls.js");
fs.writeFileSync(outFile, bundle, "utf8");
console.log(`Built ${path.relative(rootDir, outFile)} (${Buffer.byteLength(bundle)} bytes)`);

