#!/usr/bin/env python3
"""Vendor the Inter and Outfit web fonts for self-hosting.

Inter and Outfit on Google Fonts are variable fonts: every weight maps to the
same WOFF2 file. This downloads ONE latin-subset variable WOFF2 per family into
``theme/fonts/`` (``inter-var.woff2``, ``outfit-var.woff2``) so the UI can
self-host fonts instead of hot-linking fonts.googleapis.com at runtime. The
theme CSS references each with a single weight-range ``@font-face``.

Run from anywhere:  python scripts/fetch_fonts.py
Idempotent: existing files are overwritten with fresh copies.
"""

from __future__ import annotations

import re
import sys
import urllib.request
from pathlib import Path

FONTS_DIR = Path(__file__).resolve().parent.parent / "theme" / "fonts"

# family -> (min_weight, max_weight) for the variable-font range request.
FAMILIES = {
    "Inter": (300, 700),
    "Outfit": (400, 700),
}

# A modern UA makes the CSS API return WOFF2 (the most compact format).
_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    return urllib.request.urlopen(req, timeout=30).read()


def _css_url(family: str, lo: int, hi: int) -> str:
    # Range syntax (lo..hi) returns a single variable-font @font-face per subset.
    return f"https://fonts.googleapis.com/css2?family={family}:wght@{lo}..{hi}&display=swap"


def fetch_family(family: str, lo: int, hi: int) -> bool:
    css = _get(_css_url(family, lo, hi)).decode()

    # Pick the latin subset block when subsets are labelled, else the first.
    url = None
    for block_match in re.finditer(r"@font-face\s*\{(.*?)\}", css, re.DOTALL):
        body = block_match.group(1)
        comment = re.findall(r"/\*\s*([\w-]+)\s*\*/", css[: block_match.start()])
        subset = comment[-1] if comment else None
        url_match = re.search(r"src:\s*url\(([^)]+\.woff2)\)", body)
        if not url_match:
            continue
        if subset is None or subset == "latin":
            url = url_match.group(1)
            break

    if not url:
        print(f"  WARNING: no WOFF2 url found for {family}")
        return False

    out = FONTS_DIR / f"{family.lower()}-var.woff2"
    out.write_bytes(_get(url))
    print(f"  {out.name}  ({out.stat().st_size} bytes)")
    return True


def main() -> int:
    FONTS_DIR.mkdir(parents=True, exist_ok=True)
    total = 0
    for family, (lo, hi) in FAMILIES.items():
        print(f"Fetching {family} (variable {lo}-{hi}) ...")
        if fetch_family(family, lo, hi):
            total += 1
    print(f"Done. Vendored {total} variable font files into {FONTS_DIR}")
    return 0 if total == len(FAMILIES) else 1


if __name__ == "__main__":
    sys.exit(main())
