const assert = require("assert");
const { EcosystemConfig } = require("../src/config");

// Test defaults
const config = new EcosystemConfig();
assert.strictEqual(config.registryUrl, "http://localhost:8500");
assert.strictEqual(config.enabled, true);
assert.deepStrictEqual(config.peers, {});
console.log("✓ config defaults");

// Test overrides
const custom = new EcosystemConfig({ registryUrl: "http://10.0.0.1:8500", enabled: false });
assert.strictEqual(custom.registryUrl, "http://10.0.0.1:8500");
assert.strictEqual(custom.enabled, false);
console.log("✓ config overrides");

console.log("All JS tests passed");
