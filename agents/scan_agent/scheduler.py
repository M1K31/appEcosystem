"""Scheduler for periodic and baseline device scans governed by PolicyEngine."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Coroutine, Optional

from .runner import ScanRequest, ScanResult, ScanRunner

logger = logging.getLogger("ecosystem.scan_scheduler")


class ScanScheduler:
    """Evaluates enrolled devices and schedules authorized periodic scans."""

    def __init__(
        self,
        runner: ScanRunner,
        policy_engine: Any = None,
        check_interval: float = 60.0,
        is_device_reachable: Optional[Callable[[str], Coroutine[Any, Any, bool]]] = None,
    ):
        self.runner = runner
        self.policy_engine = policy_engine
        self.check_interval = check_interval
        self._is_device_reachable = is_device_reachable
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._scheduled_jobs: dict[str, dict[str, Any]] = {}

    async def is_reachable(self, device_id: str) -> bool:
        if device_id in ("local", "localhost", "127.0.0.1", ""):
            return True
        if self._is_device_reachable is not None:
            try:
                return await self._is_device_reachable(device_id)
            except Exception:
                return False
        return True

    async def check_enrolled_targets(self) -> list[dict[str, Any]]:
        """Review enrolled devices and determine auto-scan eligibility."""
        results = []
        if self.policy_engine is None:
            return results

        enrolled = self.policy_engine.list_enrolled_devices()
        for dev in enrolled:
            dev_id = dev["device_id"]
            fp = dev.get("public_key_fingerprint")
            valid, reason = self.policy_engine.has_valid_auto_scan_grant(
                device_id=dev_id,
                public_key_fingerprint=fp,
                profile="quick",
                initiator="ecosystem-scan-scheduler",
            )
            reachable = await self.is_reachable(dev_id)
            status = "eligible" if valid and reachable else ("deferred" if valid and not reachable else "unauthorized")
            results.append({
                "device_id": dev_id,
                "hostname": dev.get("hostname"),
                "public_key_fingerprint": fp,
                "auto_scan_authorized": valid,
                "reachable": reachable,
                "status": status,
                "reason": reason if not valid else ("Endpoint offline / unreachable" if not reachable else "Ready"),
            })
        return results

    async def run_due_scans(self) -> list[ScanResult]:
        """Trigger quick scans for reachable devices with valid auto_scan grants."""
        targets = await self.check_enrolled_targets()
        executed = []
        for target in targets:
            dev_id = target["device_id"]
            if target["status"] == "eligible":
                logger.info("Triggering scheduled quick scan for enrolled device: %s", dev_id)
                req = ScanRequest(
                    device_id=dev_id,
                    public_key_fingerprint=target.get("public_key_fingerprint"),
                    profile="quick",
                    trigger="schedule",
                    initiator="ecosystem-scan-scheduler",
                )
                res = await self.runner.run_scan(req)
                executed.append(res)
            elif target["status"] == "deferred":
                logger.info("Deferred scheduled scan for unreachable device: %s", dev_id)
                req = ScanRequest(
                    device_id=dev_id,
                    profile="quick",
                    trigger="schedule",
                    initiator="ecosystem-scan-scheduler",
                )
                res = ScanResult(
                    scan_id=req.scan_id,
                    device_id=dev_id,
                    status="deferred",
                    exit_code=4,
                    exit_description=target["reason"],
                    share={"verdict": "deferred", "reason": target["reason"]},
                    report_ref="",
                    started_at="",
                    completed_at="",
                    duration_seconds=0.0,
                    error_message=target["reason"],
                )
                self.runner._results_history[req.scan_id] = res
                self.runner._persist_history()
                executed.append(res)
        return executed

    async def _loop(self) -> None:
        while self._running:
            try:
                await self.run_due_scans()
            except Exception as exc:
                logger.error("Error in scan scheduler loop: %r", exc)
            await asyncio.sleep(self.check_interval)

    async def start(self) -> None:
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._loop())
            logger.info("ScanScheduler started (interval: %.1fs)", self.check_interval)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("ScanScheduler stopped")

