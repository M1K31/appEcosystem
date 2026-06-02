"""Standard logging handler that broadcasts natively via EcosystemClient."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING
import json

if TYPE_CHECKING:
    from . import EcosystemClient

class EcosystemLogHandler(logging.Handler):
    """
    A persistent logging handler that aggregates Python logging logs seamlessly 
    into the Ecosystem SIEM pipeline by natively broadcasting to 'log.<service_name>'.
    Cross-platform macOS and Linux compatible.
    """

    def __init__(self, client: EcosystemClient, loop: asyncio.AbstractEventLoop = None):
        super().__init__()
        self.client = client
        self.loop = loop or asyncio.get_event_loop()

    def emit(self, record: logging.LogRecord) -> None:
        """Route standard formatting structures via SIEM broadcast payload natively."""
        if record.levelno < logging.WARNING:
            return

        try:
            msg = self.format(record)
            payload = {
                "app": self.client._service_name,
                "level": record.levelname,
                "message": msg,
                "source_file": record.filename,
                "line_no": record.lineno,
            }
            topic = f"log.{self.client._service_name}"
            
            # Since logging is essentially synchronous globally, wrap the emit safely into the ecosystem's threaded async pipeline
            if self.loop.is_running():
                asyncio.run_coroutine_threadsafe(self.client.publish(topic, payload), self.loop)
            else:
                self.loop.run_until_complete(self.client.publish(topic, payload))
        except Exception:
            self.handleError(record)
