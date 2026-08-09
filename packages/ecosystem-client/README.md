# appecosystem-client

Client library for joining the
[appEcosystem](https://github.com/M1K31/appEcosystem) service mesh: register a
service, discover peers, and publish or subscribe to events.

Services find each other through a local registry (or mDNS), so an application
can react to what other applications on the network are doing — a doorbell
camera detecting motion, a SIEM raising an alert — without any of them being
hard-wired to each other.

## Install

```bash
pip install appecosystem-client
```

Requires Python 3.9+. Pulls in `appecosystem-auth` for request signing.

Optional extras:

```bash
pip install "appecosystem-client[mdns]"   # zeroconf peer discovery
pip install "appecosystem-client[yaml]"   # YAML config files
```

## Join the ecosystem

```python
import asyncio
from ecosystem_client import EcosystemClient

async def main():
    eco = EcosystemClient(
        service_name="my-app",
        service_port=9000,
        health_endpoint="/health",
    )
    await eco.start()          # registers, then discovers peers

    await eco.publish("myapp.ready", {"version": "1.0"})

    peer = await eco.discover("openeye")
    if peer:
        print("found OpenEye at", peer)

    await eco.stop()           # deregisters cleanly

asyncio.run(main())
```

## Receive events

Register a handler for an event pattern. `*` matches one namespace segment:

```python
@eco.on("camera.*")
async def on_camera_event(event):
    print(event["type"], event["data"])
```

Deliver incoming webhooks to `eco.handle_webhook(payload)` from whatever HTTP
route your framework exposes.

## Event patterns

| Pattern | Matches |
|---|---|
| `camera.motion` | that exact type |
| `camera.*` | `camera.motion`, `camera.offline` |
| `*` | every event with a non-empty type |

An event with an empty type matches nothing — a malformed publish from one
service cannot fan out to every subscriber.

## License

MIT — see [LICENSE](https://github.com/M1K31/appEcosystem/blob/main/LICENSE).
