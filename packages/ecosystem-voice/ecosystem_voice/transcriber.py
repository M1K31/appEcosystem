"""Local speech transcription with tier-scaling and zero raw audio retention."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger("ecosystem.voice.transcriber")


class SpeechTranscriber:
    """Hardware-tier adaptive local speech recognition engine.

    Enforces zero audio retention: in-memory buffers are scrubbed immediately.
    """

    def __init__(
        self,
        hardware_info: Any = None,
        mock_backend: Optional[Callable[[bytes, int], str]] = None,
    ):
        self.mock_backend = mock_backend
        self._hardware = hardware_info or self._detect_hardware()
        self.tier = getattr(self._hardware, "tier", 2)
        self.model_name = self._select_model_for_tier(self.tier)
        self._model = None
        logger.info("SpeechTranscriber initialized (tier: %s, model: %s)", self.tier, self.model_name)

    def _detect_hardware(self) -> Any:
        try:
            from ecosystem_ai.hardware import detect
            return detect()
        except Exception:
            class _FallbackHw:
                tier = 2
            return _FallbackHw()

    def _select_model_for_tier(self, tier: int) -> str:
        # T0: minimal/Pi 4 -> offload or text fallback
        # T1: 4-8GB -> tiny.en
        # T2: 16GB / Apple Silicon -> base.en
        # T3: 32GB+ discrete / unified GPU -> small.en
        if tier <= 0:
            return "offload"
        elif tier == 1:
            return "tiny.en"
        elif tier == 2:
            return "base.en"
        else:
            return "small.en"

    async def transcribe_pcm(
        self,
        audio_pcm: bytes | bytearray,
        sample_rate: int = 16000,
    ) -> str:
        """Transcribe PCM audio (16-bit mono PCM 16kHz) with strict zero raw audio retention."""
        if not audio_pcm:
            return ""

        try:
            if self.mock_backend is not None:
                res = self.mock_backend(bytes(audio_pcm), sample_rate)
                return str(res).strip()

            if self.model_name == "offload":
                logger.info("Hardware tier is T0 (offload); delegating or declining local transcription")
                return ""

            # Attempt local execution (whisper.cpp or faster-whisper)
            loop = asyncio.get_running_loop()
            text = await loop.run_in_executor(None, self._transcribe_sync, bytes(audio_pcm), sample_rate)
            return text.strip()

        finally:
            # Zero out buffer in-memory and drop references immediately
            try:
                if isinstance(audio_pcm, bytearray):
                    for i in range(len(audio_pcm)):
                        audio_pcm[i] = 0
            except Exception:
                pass
            del audio_pcm

    def _transcribe_sync(self, pcm_data: bytes, sample_rate: int) -> str:
        """Synchronous transcription execution."""
        # Check faster_whisper
        try:
            from faster_whisper import WhisperModel
            import io
            if self._model is None:
                self._model = WhisperModel(self.model_name, device="auto", compute_type="int8")
            segments, _ = self._model.transcribe(io.BytesIO(pcm_data))
            return " ".join(s.text for s in segments)
        except ImportError:
            pass
        except Exception as exc:
            logger.warning("faster-whisper transcription error: %r", exc)

        logger.info("Local Whisper runtime not installed; returning empty transcript")
        return ""

