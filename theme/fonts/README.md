# Self-hosted fonts

These WOFF2 files are vendored so the ecosystem UI loads fonts locally with no
external requests (privacy, offline operation — e.g. the MagicMirror HUD — and
no render-blocking call to `fonts.googleapis.com`).

| File | Family | Type | Weights |
|------|--------|------|---------|
| `inter-var.woff2` | Inter | variable | 300–700 |
| `outfit-var.woff2` | Outfit | variable | 400–700 |

Both are variable fonts, so a single file covers the whole weight range. They
are referenced by the `@font-face` rules in `../ecosystem-theme.css`; the
font-family stacks fall back to system fonts when these files are absent.

## Updating

Re-download the latin-subset variable fonts at any time:

```bash
python scripts/fetch_fonts.py
```

## Licensing

- **Inter** — © The Inter Project Authors. SIL Open Font License 1.1.
  https://github.com/rsms/inter
- **Outfit** — © The Outfit Project Authors. SIL Open Font License 1.1.
  https://github.com/Outfitio/Outfit-Fonts

The SIL OFL 1.1 permits embedding and redistribution of these font files,
including bundling with this software. Full license text:
https://openfontlicense.org
