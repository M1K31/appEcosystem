import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "auth" / "python"))

# Secrets are fail-closed (no default). Provide one for the whole test session so
# components that resolve the secret at construction don't raise. Tests that
# exercise the resolver itself override/delete this via monkeypatch.
os.environ.setdefault("ECOSYSTEM_HMAC_SECRET", "test-ecosystem-secret")


# ── Network guard ──────────────────────────────────────────────────────────
# The registry pre-registers the ecosystem's apps at their real localhost ports
# and pushes policy changes (e.g. Freeze) to them. On a machine where those apps
# are installed, an unguarded test run delivers a real mesh Freeze to a live
# daemon. Every real HTTP transport is therefore refused during tests; the
# in-process ASGI transport used by TestClient is unaffected. A test that needs
# real sockets opts out with @pytest.mark.allow_network.
import httpx  # noqa: E402
import pytest  # noqa: E402

_GUARD_MESSAGE = "blocked by the test-suite network guard (use @pytest.mark.allow_network to opt out)"


def pytest_configure(config):
    config.addinivalue_line("markers", "allow_network: let this test open real HTTP connections")


@pytest.fixture(autouse=True)
def _no_real_http(request, monkeypatch):
    if request.node.get_closest_marker("allow_network"):
        return

    def _blocked_sync(self, req):
        raise httpx.ConnectError(f"{req.url}: {_GUARD_MESSAGE}", request=req)

    async def _blocked_async(self, req):
        raise httpx.ConnectError(f"{req.url}: {_GUARD_MESSAGE}", request=req)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", _blocked_sync)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _blocked_async)
