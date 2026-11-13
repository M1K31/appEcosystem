# ecosystem-voice

Tier-scaled local speech recognition and voice intent parsing for `appEcosystem`.

## Invariants

1. **Local first & zero raw audio retention:** Transcriptions are performed in-memory using `whisper.cpp` or `faster-whisper`. Audio frames are scrubbed immediately after processing; no raw PCM or audio files are retained on disk.
2. **Hardware tier scaling:**
   - `T0_MINIMAL`: Offload to local LAN node or text-only fallback.
   - `T1_MODEST`: `tiny.en` int8.
   - `T2_CAPABLE`: `base.en`.
   - `T3_HIGH_END`: `small.en`.
3. **Strict privilege boundary:** Voice intents can trigger `ecosystem.freeze`, `scan.request`, `scan.results`, and `automation.run`. Voice intents can **NEVER** resume from Freeze, approve checkpoints, or disable restrictions (`Restrictions: Off`). Privileged transitions strictly require authenticated operator step-up.

