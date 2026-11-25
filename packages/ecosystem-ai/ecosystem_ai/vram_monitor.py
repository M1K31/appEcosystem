"""ECO-05: Dynamic VRAM Model Quantization Down-Shifting.

Monitors real-time GPU VRAM / unified-memory headroom and automatically signals
local inference runtimes (Ollama / llama.cpp) to step down quantization levels
(e.g. from ``Q8_0`` to ``Q4_K_M``) when available memory headroom dips below a
configurable threshold (default 2.0 GB), with hysteresis and cooldown to avoid
oscillation.
"""
from __future__ import annotations

import asyncio
import inspect
import logging
import os
import platform
import re
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Awaitable, Callable, Union

logger = logging.getLogger("ecosystem.vram_monitor")

QUANTIZATION_LADDER: tuple[str, ...] = (
    "F16",
    "Q8_0",
    "Q6_K",
    "Q5_K_M",
    "Q4_K_M",
    "Q3_K_M",
    "Q2_K",
)

_QUANT_ALIASES: dict[str, str] = {
    "FP16": "F16",
    "F16": "F16",
    "Q8": "Q8_0",
    "Q8_0": "Q8_0",
    "Q6": "Q6_K",
    "Q6_K": "Q6_K",
    "Q5": "Q5_K_M",
    "Q5_0": "Q5_K_M",
    "Q5_K_S": "Q5_K_M",
    "Q5_K_M": "Q5_K_M",
    "Q4": "Q4_K_M",
    "Q4_0": "Q4_K_M",
    "Q4_K_S": "Q4_K_M",
    "Q4_K_M": "Q4_K_M",
    "Q3": "Q3_K_M",
    "Q3_K_M": "Q3_K_M",
    "Q2": "Q2_K",
    "Q2_K": "Q2_K",
}

_QUANT_TAG_RE = re.compile(
    r"(?i)(?:^|[-_:.])(f16|fp16|q8_0|q8|q6_k|q6|q5_k_m|q5_k_s|q5_0|q5|q4_k_m|q4_k_s|q4_0|q4|q3_k_m|q3|q2_k|q2)(?=$|[-:]|\.gguf$|_(?![0-9]|k(?:_|$)))"
)


def extract_model_quantization(model_name: str, *, default: str | None = None) -> str | None:
    """Extract and normalize the quantization tag from a model identifier, if present."""
    raw = str(model_name or "").strip()
    if not raw or raw.lower() == "auto":
        return default
    m = _QUANT_TAG_RE.search(raw)
    if not m:
        return default
    token = m.group(1).upper()
    return _QUANT_ALIASES.get(token, default)


def normalize_quantization(quant: str) -> str:
    cleaned = str(quant or "").strip().upper()
    if cleaned in _QUANT_ALIASES:
        return _QUANT_ALIASES[cleaned]
    raise ValueError(f"Unsupported quantization level: {quant!r} (expected one of {QUANTIZATION_LADDER})")


def step_down_quantization(
    current: str,
    *,
    min_quant: str = "Q4_K_M",
    direct_to_target: str | None = None,
) -> str | None:
    """Return the next lower quantization level, or None if already at/below ``min_quant``."""
    cur = normalize_quantization(current)
    floor = normalize_quantization(min_quant)
    cur_idx = QUANTIZATION_LADDER.index(cur)
    floor_idx = QUANTIZATION_LADDER.index(floor)
    if cur_idx >= floor_idx:
        return None
    if direct_to_target is not None:
        target = normalize_quantization(direct_to_target)
        t_idx = QUANTIZATION_LADDER.index(target)
        if t_idx > cur_idx:
            return QUANTIZATION_LADDER[min(t_idx, floor_idx)]
    return QUANTIZATION_LADDER[min(cur_idx + 1, floor_idx)]


def rewrite_model_quantization(model_name: str, target_quant: str) -> str:
    """Rewrite or append a quantization suffix on an Ollama/GGUF model identifier."""
    raw = str(model_name or "").strip()
    if not raw or raw.lower() == "auto":
        return raw
    q_lower = normalize_quantization(target_quant).lower()
    if _QUANT_TAG_RE.search(raw):
        def _repl(match: re.Match[str]) -> str:
            full = match.group(0)
            prefix = full[: len(full) - len(match.group(1))]
            return f"{prefix}{q_lower}"

        return _QUANT_TAG_RE.sub(_repl, raw, count=1)
    if ":" in raw:
        return f"{raw}-{q_lower}"
    return f"{raw}:{q_lower}"


@dataclass(frozen=True)
class MemorySample:
    """Point-in-time memory/VRAM headroom sample."""

    available_gb: float
    total_gb: float
    source: str  # nvidia_smi | macos_vm_stat | linux_proc_meminfo | fallback
    unified_memory: bool = False
    sampled_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class QuantizationShiftEvent:
    """Signal emitted to local inference runtimes when quantization changes."""

    action: str  # downshift | restore
    from_quant: str
    to_quant: str
    available_gb: float
    threshold_gb: float
    recommended_model: str = ""
    timestamp: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sample_nvidia_vram() -> MemorySample | None:
    try:
        out = subprocess.check_output(
            [
                "nvidia-smi",
                "--query-gpu=memory.free,memory.total",
                "--format=csv,noheader,nounits",
            ],
            stderr=subprocess.DEVNULL,
            timeout=2.0,
            text=True,
        )
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        if not lines:
            return None
        free_mib, total_mib = [float(x.strip()) for x in lines[0].split(",")[:2]]
        return MemorySample(
            available_gb=round(free_mib / 1024.0, 3),
            total_gb=round(total_mib / 1024.0, 3),
            source="nvidia_smi",
            unified_memory=False,
            sampled_at=time.time(),
        )
    except Exception:
        return None


def _sample_macos_memory() -> MemorySample | None:
    try:
        total_bytes = int(
            subprocess.check_output(["sysctl", "-n", "hw.memsize"], stderr=subprocess.DEVNULL, timeout=2.0, text=True).strip()
        )
        vm_out = subprocess.check_output(["vm_stat"], stderr=subprocess.DEVNULL, timeout=2.0, text=True)
        page_match = re.search(r"page size of (\d+) bytes", vm_out)
        page_size = int(page_match.group(1)) if page_match else 4096

        def _pages(label: str) -> int:
            m = re.search(rf"{re.escape(label)}:\s+(\d+)\.", vm_out)
            return int(m.group(1)) if m else 0

        avail_pages = _pages("Pages free") + _pages("Pages inactive") + _pages("Pages speculative") + _pages("Pages purgeable")
        avail_gb = (avail_pages * page_size) / (1024.0 ** 3)
        total_gb = total_bytes / (1024.0 ** 3)
        is_apple_silicon = platform.machine().lower() in ("arm64", "aarch64")
        return MemorySample(
            available_gb=round(avail_gb, 3),
            total_gb=round(total_gb, 3),
            source="macos_vm_stat",
            unified_memory=is_apple_silicon,
            sampled_at=time.time(),
        )
    except Exception:
        return None


def _sample_linux_meminfo() -> MemorySample | None:
    try:
        text = open("/proc/meminfo", encoding="utf-8").read()
        m_avail = re.search(r"^MemAvailable:\s+(\d+)\s+kB", text, re.MULTILINE)
        m_total = re.search(r"^MemTotal:\s+(\d+)\s+kB", text, re.MULTILINE)
        if not m_avail or not m_total:
            return None
        return MemorySample(
            available_gb=round(int(m_avail.group(1)) / (1024.0 ** 2), 3),
            total_gb=round(int(m_total.group(1)) / (1024.0 ** 2), 3),
            source="linux_proc_meminfo",
            unified_memory=False,
            sampled_at=time.time(),
        )
    except Exception:
        return None


def sample_memory_headroom() -> MemorySample:
    """Sample real-time available GPU VRAM or unified/system RAM headroom in GB."""
    nv = _sample_nvidia_vram()
    if nv is not None:
        return nv
    sys_name = platform.system()
    if sys_name == "Darwin":
        mac = _sample_macos_memory()
        if mac is not None:
            return mac
    if sys_name == "Linux":
        lin = _sample_linux_meminfo()
        if lin is not None:
            return lin
    return MemorySample(
        available_gb=0.0,
        total_gb=0.0,
        source="unavailable",
        unified_memory=False,
        sampled_at=time.time(),
    )


ShiftCallback = Callable[[QuantizationShiftEvent], Union[Any, Awaitable[Any]]]


class VramQuantizationMonitor:
    """Monitors memory headroom and signals quantization down-shifting with hysteresis."""

    def __init__(
        self,
        *,
        baseline_quant: str = "Q8_0",
        downshift_target_quant: str = "Q4_K_M",
        min_quant: str = "Q4_K_M",
        low_headroom_gb: float = 2.0,
        restore_headroom_gb: float | None = None,
        consecutive_low_samples: int = 2,
        consecutive_restore_samples: int = 3,
        cooldown_seconds: float = 60.0,
        interval_seconds: float = 15.0,
        model_name: str = "auto",
        probe_fn: Callable[[], MemorySample] | None = None,
        on_shift: ShiftCallback | None = None,
    ):
        self.baseline_quant = normalize_quantization(baseline_quant)
        self.downshift_target_quant = normalize_quantization(downshift_target_quant)
        self.min_quant = normalize_quantization(min_quant)
        self.low_headroom_gb = max(0.25, float(low_headroom_gb))
        self.restore_headroom_gb = (
            max(self.low_headroom_gb + 0.5, float(restore_headroom_gb))
            if restore_headroom_gb is not None
            else self.low_headroom_gb + 1.5
        )
        self.consecutive_low_samples = max(1, int(consecutive_low_samples))
        self.consecutive_restore_samples = max(1, int(consecutive_restore_samples))
        self.cooldown_seconds = max(0.0, float(cooldown_seconds))
        self.interval_seconds = max(0.0, float(interval_seconds))
        self.model_name = str(model_name or "auto").strip()
        self._probe_fn = probe_fn or sample_memory_headroom
        self._on_shift = on_shift

        self._lock = threading.RLock()
        self._active_quant = self.baseline_quant
        self._low_streak = 0
        self._restore_streak = 0
        self._last_shift_ts: float = 0.0
        self._config_generation: int = 0
        self._last_sample: MemorySample | None = None
        self._history: list[dict[str, Any]] = []
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()

    def configure_model(self, model_name: str, *, baseline_quant: str | None = None) -> None:
        """Synchronize the monitor with a new selected model and reset shift/streak state."""
        cleaned = str(model_name or "auto").strip()
        resolved_baseline = (
            normalize_quantization(baseline_quant)
            if baseline_quant is not None
            else (extract_model_quantization(cleaned, default="Q8_0") or "Q8_0")
        )
        with self._lock:
            self.model_name = cleaned
            self.baseline_quant = resolved_baseline
            self._active_quant = resolved_baseline
            self._low_streak = 0
            self._restore_streak = 0
            self._last_shift_ts = 0.0
            self._config_generation += 1

    def evaluate_sample(
        self,
        sample: MemorySample,
        *,
        now: float | None = None,
    ) -> QuantizationShiftEvent | None:
        """Feed one headroom sample into the hysteresis state machine."""
        ts = time.time() if now is None else float(now)
        with self._lock:
            self._last_sample = sample
            if sample.source == "unavailable" and sample.total_gb <= 0:
                return None

            in_cooldown = self._last_shift_ts > 0 and (ts - self._last_shift_ts) < self.cooldown_seconds

            if sample.available_gb < self.low_headroom_gb:
                self._low_streak += 1
                self._restore_streak = 0
                if self._low_streak >= self.consecutive_low_samples and not in_cooldown:
                    next_q = step_down_quantization(
                        self._active_quant,
                        min_quant=self.min_quant,
                        direct_to_target=self.downshift_target_quant,
                    )
                    if next_q and next_q != self._active_quant:
                        prev_q = self._active_quant
                        self._active_quant = next_q
                        self._last_shift_ts = ts
                        self._low_streak = 0
                        ev = QuantizationShiftEvent(
                            action="downshift",
                            from_quant=prev_q,
                            to_quant=next_q,
                            available_gb=sample.available_gb,
                            threshold_gb=self.low_headroom_gb,
                            recommended_model=rewrite_model_quantization(self.model_name, next_q),
                            timestamp=ts,
                        )
                        self._history.append(ev.to_dict())
                        self._history = self._history[-50:]
                        return ev
                return None

            self._low_streak = 0
            if self._active_quant != self.baseline_quant and sample.available_gb >= self.restore_headroom_gb:
                self._restore_streak += 1
                if self._restore_streak >= self.consecutive_restore_samples and not in_cooldown:
                    prev_q = self._active_quant
                    self._active_quant = self.baseline_quant
                    self._last_shift_ts = ts
                    self._restore_streak = 0
                    ev = QuantizationShiftEvent(
                        action="restore",
                        from_quant=prev_q,
                        to_quant=self.baseline_quant,
                        available_gb=sample.available_gb,
                        threshold_gb=self.restore_headroom_gb,
                        recommended_model=rewrite_model_quantization(self.model_name, self.baseline_quant),
                        timestamp=ts,
                    )
                    self._history.append(ev.to_dict())
                    self._history = self._history[-50:]
                    return ev
            else:
                self._restore_streak = 0
            return None

    async def poll_once(self) -> QuantizationShiftEvent | None:
        sample = await asyncio.to_thread(self._probe_fn)
        with self._lock:
            gen = self._config_generation
            prev_active = self._active_quant
            prev_last_shift_ts = self._last_shift_ts
            prev_low_streak = self._low_streak
            prev_restore_streak = self._restore_streak
            event = self.evaluate_sample(sample)
        if event is not None and self._on_shift is not None:
            delivered = True
            try:
                res = self._on_shift(event)
                if inspect.isawaitable(res):
                    res = await res
                if res is False:
                    delivered = False
            except Exception as exc:
                logger.warning("VRAM quantization shift callback failed: %s", exc)
                delivered = False
            if not delivered:
                with self._lock:
                    if self._config_generation == gen:
                        self._active_quant = prev_active
                        self._last_shift_ts = prev_last_shift_ts
                        self._low_streak = prev_low_streak
                        self._restore_streak = prev_restore_streak
                        if self._history and self._history[-1].get("timestamp") == event.timestamp:
                            self._history.pop()
                return None
        return event

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "model_name": self.model_name,
                "baseline_quant": self.baseline_quant,
                "active_quant": self._active_quant,
                "downshifted": self._active_quant != self.baseline_quant,
                "low_headroom_gb": self.low_headroom_gb,
                "restore_headroom_gb": self.restore_headroom_gb,
                "last_sample": self._last_sample.to_dict() if self._last_sample else None,
                "recent_shifts": list(self._history[-10:]),
            }

    async def start(self) -> None:
        if self.interval_seconds <= 0 or self._task is not None:
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(self._loop(), name="vram-quant-monitor")

    async def stop(self, *, timeout_seconds: float = 10.0) -> None:
        if self._task is None:
            return
        self._stop_event.set()
        try:
            await asyncio.wait_for(self._task, timeout=float(timeout_seconds))
        except asyncio.TimeoutError:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        except asyncio.CancelledError:
            pass
        self._task = None

    async def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval_seconds)
                break
            except asyncio.TimeoutError:
                pass
            try:
                ev = await self.poll_once()
                if ev is not None:
                    logger.warning(
                        "VRAM quantization %s: %s -> %s (available=%.2fGB, threshold=%.2fGB)",
                        ev.action,
                        ev.from_quant,
                        ev.to_quant,
                        ev.available_gb,
                        ev.threshold_gb,
                    )
            except Exception as exc:
                logger.debug("VRAM headroom poll failed: %s", exc)
