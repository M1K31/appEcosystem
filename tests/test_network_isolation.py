"""The test suite must never talk to services actually running on this machine.

The hub pre-registers the ecosystem's apps at their localhost ports and
propagates policy changes to them. Without a guard, a test that activates a
Freeze delivers a real mesh Freeze to a real, running daemon.
"""
import asyncio

import httpx
import pytest


def test_sync_http_to_a_real_port_is_blocked():
    with pytest.raises(httpx.ConnectError, match="blocked by the test-suite network guard"):
        httpx.get("http://127.0.0.1:8088/api/status", timeout=2)


def test_async_http_to_a_real_port_is_blocked():
    async def go():
        async with httpx.AsyncClient(timeout=2) as client:
            await client.post("http://localhost:8088/ecosystem/events", json={"type": "policy.freeze"})

    with pytest.raises(httpx.ConnectError, match="blocked by the test-suite network guard"):
        asyncio.run(go())


@pytest.mark.allow_network
def test_opt_out_marker_restores_real_transport():
    # Port 9 (discard) is closed: a real connection attempt is refused by the OS,
    # not by the guard.
    with pytest.raises(httpx.ConnectError) as excinfo:
        httpx.get("http://127.0.0.1:9/", timeout=2)
    assert "network guard" not in str(excinfo.value)
