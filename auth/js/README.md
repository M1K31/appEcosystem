# @smartindustriesllc/ecosystem-auth

Shared HMAC-SHA256 request signing and verification for
[appEcosystem](https://github.com/M1K31/appEcosystem) services — the Node.js
counterpart of the Python `appecosystem-auth` package.

Every request between ecosystem services is signed with a shared secret. The
signed payload binds the method, canonical path, a timestamp and a unique nonce,
plus a digest of the body, so a captured request cannot be replayed.

## Install

```bash
npm install @smartindustriesllc/ecosystem-auth
```

Node 18+. No runtime dependencies — it uses the built-in `crypto` module.

## Signing a request

```js
const { signRequest } = require("@smartindustriesllc/ecosystem-auth");

const headers = signRequest("POST", "/events/publish", secret, {
  type: "camera.motion",
  source: "my-app",
});

await fetch("http://localhost:8500/events/publish", {
  method: "POST",
  headers: { "Content-Type": "application/json", ...headers },
  body: JSON.stringify(body),
});
```

## Verifying a request

```js
const { verifySignature } = require("@smartindustriesllc/ecosystem-auth");
```

Express-style middleware is available from the subpath export:

```js
const middleware = require("@smartindustriesllc/ecosystem-auth/middleware");
```

## Interoperability

Signatures are wire-compatible with the Python implementation, so a Node service
can verify a request signed by a Python one and vice versa. Both resolve the
shared secret from `ECOSYSTEM_SECRET`, falling back to the file-backed store at
`~/.config/ecosystem/secret.env` (mode 0600).

Every service on a machine must resolve the same secret, or signatures will not
verify.

## License

MIT — see [LICENSE](./LICENSE).
