const { test } = require("node:test");
const assert = require("node:assert");

const { AIProfileClient } = require("../src/ai_profile");

const SECRET = "js-aiprofile-test-secret";

function mockFetch(responder) {
  const calls = [];
  global.fetch = async (url, opts) => {
    calls.push({ url, opts });
    return responder(url, opts);
  };
  return calls;
}

function jsonResp(status, payload) {
  return { ok: status >= 200 && status < 300, status, json: async () => payload };
}

test("fetch returns the shared profile and signs the request", async () => {
  const calls = mockFetch(() => jsonResp(200, { selected_model: "llama3.1:8b", version: 2 }));
  const c = new AIProfileClient("http://reg:8500", { secret: SECRET });
  const prof = await c.fetch();
  assert.strictEqual(prof.selected_model, "llama3.1:8b");
  assert.ok(calls[0].opts.headers["X-Ecosystem-Signature"]);
  assert.ok(calls[0].opts.headers["X-Ecosystem-Timestamp"]);
  assert.ok(calls[0].opts.headers["X-Ecosystem-Nonce"]);
});

test("selectedModel returns just the model", async () => {
  mockFetch(() => jsonResp(200, { selected_model: "mistral:7b" }));
  const c = new AIProfileClient("http://reg:8500", { secret: SECRET });
  assert.strictEqual(await c.selectedModel(), "mistral:7b");
});

test("update PUTs changes and returns the new profile", async () => {
  const calls = mockFetch((url, opts) =>
    jsonResp(200, Object.assign({ version: 3 }, JSON.parse(opts.body)))
  );
  const c = new AIProfileClient("http://reg:8500", { secret: SECRET, serviceName: "magicmirror" });
  const prof = await c.update({ selected_model: "llama3.1:8b" });
  assert.strictEqual(prof.selected_model, "llama3.1:8b");
  assert.strictEqual(calls[0].opts.method, "PUT");
  assert.ok(calls[0].opts.headers["X-Ecosystem-Signature"]);
});

test("fetch returns null when registry is unreachable", async () => {
  mockFetch(() => { throw new Error("ECONNREFUSED"); });
  const c = new AIProfileClient("http://reg:8500", { secret: SECRET });
  assert.strictEqual(await c.fetch(), null);
});

test("no secret => unsigned (empty auth headers)", async () => {
  const calls = mockFetch(() => jsonResp(200, {}));
  const c = new AIProfileClient("http://reg:8500", { secret: "" });
  await c.fetch();
  assert.strictEqual(calls[0].opts.headers["X-Ecosystem-Signature"], undefined);
});
