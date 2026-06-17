const { test } = require("node:test");
const assert = require("node:assert");

const {
  signRequest,
  verifyRequest,
  NonceStore,
  canonicalPath,
  createEcosystemToken,
  verifyEcosystemToken,
  SIGNATURE_HEADER,
  TIMESTAMP_HEADER,
  NONCE_HEADER,
} = require("../src/tokens");

const SECRET = "js-request-test-secret";

test("signRequest returns signature, timestamp and nonce headers", () => {
  const h = signRequest("POST", "http://h/register", SECRET, { a: 1 });
  assert.ok(h[SIGNATURE_HEADER]);
  assert.ok(h[TIMESTAMP_HEADER]);
  assert.ok(h[NONCE_HEADER]);
});

test("verifyRequest accepts a freshly signed request", () => {
  const body = { name: "svc", port: 8000 };
  const h = signRequest("POST", "http://h/register", SECRET, body);
  assert.ok(
    verifyRequest("POST", "http://h/register", SECRET,
      h[SIGNATURE_HEADER], h[TIMESTAMP_HEADER], h[NONCE_HEADER], body)
  );
});

test("verifyRequest is host-independent (canonical path)", () => {
  const body = { x: 1 };
  const h = signRequest("POST", "http://host-a:8500/register", SECRET, body);
  assert.ok(
    verifyRequest("POST", "http://host-b:9000/register", SECRET,
      h[SIGNATURE_HEADER], h[TIMESTAMP_HEADER], h[NONCE_HEADER], body)
  );
});

test("verifyRequest rejects a tampered body", () => {
  const h = signRequest("POST", "http://h/register", SECRET, { a: 1 });
  assert.ok(
    !verifyRequest("POST", "http://h/register", SECRET,
      h[SIGNATURE_HEADER], h[TIMESTAMP_HEADER], h[NONCE_HEADER], { a: 2 })
  );
});

test("verifyRequest rejects a stale timestamp", () => {
  const h = signRequest("POST", "http://h/register", SECRET, { a: 1 }, 1);
  assert.ok(
    !verifyRequest("POST", "http://h/register", SECRET,
      h[SIGNATURE_HEADER], h[TIMESTAMP_HEADER], h[NONCE_HEADER], { a: 1 })
  );
});

test("verifyRequest rejects a replayed nonce", () => {
  const store = new NonceStore();
  const body = { a: 1 };
  const h = signRequest("POST", "http://h/register", SECRET, body);
  const args = ["POST", "http://h/register", SECRET,
    h[SIGNATURE_HEADER], h[TIMESTAMP_HEADER], h[NONCE_HEADER], body, 300, store];
  assert.ok(verifyRequest(...args));
  assert.ok(!verifyRequest(...args));
});

test("canonicalPath sorts query params and drops host", () => {
  assert.strictEqual(canonicalPath("http://h:8500/register?b=2&a=1"), "/register?a=1&b=2");
});

test("verifyEcosystemToken accepts a normal token and rejects overlong lifetime", () => {
  const ok = createEcosystemToken(SECRET, "svc");
  assert.ok(verifyEcosystemToken(ok, SECRET));
  const overlong = createEcosystemToken(SECRET, "svc", 10 * 365 * 86400);
  assert.ok(!verifyEcosystemToken(overlong, SECRET));
});
