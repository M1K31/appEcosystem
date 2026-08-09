# appecosystem-auth

Shared HMAC-SHA256 request signing and verification for
[appEcosystem](https://github.com/M1K31/appEcosystem) services.

Every request between ecosystem services is signed with a shared secret. The
signed payload binds the method, canonical path, a timestamp and a unique
nonce, plus a digest of the body — so a captured request cannot be replayed.

Third-party applications are issued their own `key_id`, sent alongside the
signature, so their access can be identified, scoped and revoked independently
of the first-party services.

## Install

```bash
pip install appecosystem-auth
```

Requires Python 3.9+.

## Signing a request

`sign_request` returns the headers to attach; it does not send anything.

```python
import httpx
from ecosystem_auth.tokens import sign_request, get_ecosystem_secret

secret = get_ecosystem_secret()
body = {"type": "camera.motion", "source": "my-app", "data": {"camera": "front"}}

headers = sign_request(
    "POST",
    "/events/publish",
    secret,
    body=body,
    key_id="k_your_app_key",   # omit for first-party services
)

httpx.post("http://localhost:8500/events/publish", json=body, headers=headers)
```

`body` is the request body **as a dict**, not a pre-serialized string — it is
digested as part of the signature.

## Verifying a request (FastAPI)

```python
from fastapi import Depends, FastAPI
from ecosystem_auth.middleware import require_ecosystem_auth

app = FastAPI()

@app.post("/webhook")
async def webhook(principal: dict = Depends(require_ecosystem_auth)):
    # principal carries the caller's identity and granted scopes
    return {"caller": principal.get("app_id"), "scopes": principal.get("scopes")}
```

An unsigned or badly-signed request is rejected before your handler runs.

## Where the secret comes from

`get_ecosystem_secret()` resolves in this order:

1. the `ECOSYSTEM_SECRET` environment variable
2. the file-backed store at `~/.config/ecosystem/secret.env` (mode `0600`)

Every service on a machine must resolve the *same* secret, or signatures will
not verify. Use `ecosystem_auth.setup.generate_secret()` /
`apply_secret()` to provision one.

## License

MIT — see [LICENSE](https://github.com/M1K31/appEcosystem/blob/main/LICENSE).
