import pytest

from ecosystem_auth.tokens import sign_payload


class TestEventSubscriber:
    def test_register_handler(self):
        from ecosystem_client.event_subscriber import EventSubscriber

        sub = EventSubscriber(hmac_secret="test-secret")
        called = []

        async def handler(event):
            called.append(event)

        sub.on("security.alert", handler)
        assert "security.alert" in sub._handlers

    def test_register_handler_decorator(self):
        from ecosystem_client.event_subscriber import EventSubscriber

        sub = EventSubscriber(hmac_secret="test-secret")

        @sub.on("security.alert")
        async def handler(event):
            pass

        assert "security.alert" in sub._handlers

    @pytest.mark.asyncio
    async def test_dispatch_event(self):
        from ecosystem_client.event_subscriber import EventSubscriber

        sub = EventSubscriber(hmac_secret="test-secret")
        received = []

        @sub.on("security.alert")
        async def handler(event):
            received.append(event)

        signable = {
            "id": "evt-1",
            "type": "security.alert",
            "source": "openeye",
            "timestamp": 1234567890.0,
            "data": {"camera_id": 1},
        }
        envelope = {
            **signable,
            "signature": sign_payload(signable, "test-secret"),
        }

        await sub.dispatch(envelope)
        assert len(received) == 1
        assert received[0]["data"]["camera_id"] == 1

    @pytest.mark.asyncio
    async def test_dispatch_rejects_bad_signature(self):
        from ecosystem_client.event_subscriber import EventSubscriber

        sub = EventSubscriber(hmac_secret="test-secret")
        received = []

        @sub.on("security.alert")
        async def handler(event):
            received.append(event)

        envelope = {
            "id": "evt-1",
            "type": "security.alert",
            "source": "openeye",
            "timestamp": 1234567890.0,
            "data": {"camera_id": 1},
            "signature": "bad-signature",
        }

        await sub.dispatch(envelope)
        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_dispatch_wildcard_handler(self):
        from ecosystem_client.event_subscriber import EventSubscriber

        sub = EventSubscriber(hmac_secret="test-secret")
        received = []

        @sub.on("security.*")
        async def handler(event):
            received.append(event)

        signable = {
            "id": "evt-1",
            "type": "security.motion_detected",
            "source": "openeye",
            "timestamp": 1234567890.0,
            "data": {},
        }
        envelope = {**signable, "signature": sign_payload(signable, "test-secret")}

        await sub.dispatch(envelope)
        assert len(received) == 1
