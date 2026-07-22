"""Is a local model strong enough for security analysis?

Lives in the shared package because this is ecosystem-wide policy, not one app's:
the harness daemon performs security analysis and auto-falls-back to whatever
model is installed, so it needs the same judgement AI-for-Survival applies at
model-selection time. Without it the component most likely to run on an
inadequate model is the one that never warns.

Security analysis (threat triage, intrusion/malware assessment, recon summaries)
asks a model to reason over structured evidence and produce actionable findings.
Very small models will answer confidently and badly — which is worse than not
answering, because the output looks like analysis. The fallback model chosen when
a recommendation is not installed can easily be a 1B model, so the user needs to
be told before they rely on it.

Parameter count is the signal used because Ollama reports it for every model
(details.parameter_size), unlike the hand-maintained model catalog which only
covers a handful of names.
"""
from __future__ import annotations

import re
from typing import Any, Optional

# Below this, a model is not credible for security reasoning.
INADEQUATE_BELOW_B = 3.0
# Below this it can produce something usable but should not be trusted alone.
MARGINAL_BELOW_B = 7.0

LEVEL_ADEQUATE = "adequate"
LEVEL_MARGINAL = "marginal"
LEVEL_INADEQUATE = "inadequate"
LEVEL_UNKNOWN = "unknown"


def parse_parameter_size(value: Any) -> Optional[float]:
    """Parse Ollama's parameter_size ("1.1B", "30.5B", "7B", "540M") to billions.

    Returns None when it cannot be determined, which callers must treat as
    "unknown" rather than assuming the model is fine.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    m = re.match(r"\s*([0-9]*\.?[0-9]+)\s*([BbMm])?\s*$", str(value))
    if not m:
        return None
    num = float(m.group(1))
    unit = (m.group(2) or "B").upper()
    return num / 1000.0 if unit == "M" else num


def assess_for_security(model_name: str, parameter_size: Any = None) -> dict:
    """Classify a model's fitness for security analysis.

    Returns {level, params_b, warning}. `warning` is None when no warning is
    warranted, so callers can render it directly.
    """
    params = parse_parameter_size(parameter_size)

    if params is None:
        return {
            "level": LEVEL_UNKNOWN,
            "params_b": None,
            "warning": (
                f"Could not determine the size of “{model_name}”. If it is a small "
                f"model, security analysis may be unreliable."
            ),
        }

    if params < INADEQUATE_BELOW_B:
        return {
            "level": LEVEL_INADEQUATE,
            "params_b": params,
            "warning": (
                f"“{model_name}” is a {params:g}B model — too small for reliable "
                f"security analysis. It will still answer, but findings may be "
                f"confidently wrong. Use a {MARGINAL_BELOW_B:g}B+ model, or route "
                f"Security analysis to a cloud provider."
            ),
        }

    if params < MARGINAL_BELOW_B:
        return {
            "level": LEVEL_MARGINAL,
            "params_b": params,
            "warning": (
                f"“{model_name}” is a {params:g}B model. Usable for chat, but "
                f"marginal for security analysis — treat its findings as hints, "
                f"not conclusions."
            ),
        }

    return {"level": LEVEL_ADEQUATE, "params_b": params, "warning": None}


def annotate_models(models: list[dict]) -> list[dict]:
    """Attach a `security_capability` block to Ollama /api/tags entries."""
    out = []
    for m in models or []:
        entry = dict(m)
        details = entry.get("details") or {}
        entry["security_capability"] = assess_for_security(
            entry.get("name", "unknown"), details.get("parameter_size")
        )
        out.append(entry)
    return out
