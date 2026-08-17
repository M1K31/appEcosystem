# @smartindustriesllc/ecosystem-client

Client library for joining the
[appEcosystem](https://github.com/M1K31/appEcosystem) service mesh from Node.js:
register a service, discover peers, and publish or subscribe to events.

The Node counterpart of the Python `appecosystem-client` package. Services find
each other through a local registry, so an application can react to what other
applications on the network are doing without any of them being hard-wired to
each other.

## Install

```bash
npm install @smartindustriesllc/ecosystem-client
```

Node 18+. Pulls in `@smartindustriesllc/ecosystem-auth` for request signing.

`bonjour-service` is an *optional* dependency used for mDNS discovery; the
client falls back to the registry when it is absent.

## Join the ecosystem

```js
const { EcosystemClient } = require("@smartindustriesllc/ecosystem-client");

const eco = new EcosystemClient({
  serviceName: "my-app",
  servicePort: 9000,
});

await eco.start();                       // register, then discover peers
await eco.publish("myapp.ready", { version: "1.0" });
await eco.stop();                        // deregister cleanly
```

## Receive events

```js
eco.on("camera.*", (event) => {
  console.log(event.type, event.data);
});
```

`*` matches one namespace segment: `camera.*` matches `camera.motion` and
`camera.offline`. An event with an empty type matches nothing, so a malformed
publish from one service cannot fan out to every subscriber.

## Configuration

The registry URL and shared secret resolve the same way as every other
ecosystem service — from the environment, falling back to the file-backed store
at `~/.config/ecosystem/secret.env`.

## License

MIT — see [LICENSE](./LICENSE).
