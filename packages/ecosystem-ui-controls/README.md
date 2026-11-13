# `@appecosystem/ui-controls`

Zero-dependency, Apple Human Interface Guidelines (HIG) compliant Web Components shared across all `appEcosystem` dashboards and ambient displays:

- `<ecosystem-policy-bar>` — Persistent policy mode, authority, device-sync, scoped-override countdown, and emergency Freeze banner (`view-mode="admin"` or `view-mode="ambient"`).
- `<ecosystem-override-modal>` — Accessible step-up verification modal for timed/scoped `Restrictions: Off (Scoped)` sessions, contrasting bypassed gates against immutable `Always Enforced` invariants.
- `<ecosystem-freeze-button>` — `44px+` emergency preemption button with optional 3-second two-tap guard (`confirm-tap`) for shared touch displays.
- `<ecosystem-mic-pill>` — Local-only Whisper voice control (`muted`, `push_to_talk`, `listening`, `processing`, `unavailable`) with zero-audio-retention disclosure.

## Design & Accessibility Guarantees

1. **Clarity, Deference & Depth:** Consumes tokens from [`theme/ecosystem-theme.css`](../../theme/ecosystem-theme.css) (`--glass-bg`, `--glass-blur`, `--color-accent`, `--touch-target-min: 44px`, `--anim-ease`), automatically adapting to Dark, Light, OS `prefers-color-scheme`, and Cyberpunk themes.
2. **Non-Color Status Indicators:** Every state pairs a distinct SVG icon, uppercase semantic badge, and `role="status"` / `aria-live` announcement.
3. **Fail-Closed Precedence:** `Freeze` always supersedes `Restrictions: Off (Scoped)`. Expired override timestamps revert locally to `Restrictions: On` immediately without waiting for a server poll. Unreachable devices are explicitly surfaced and never counted as updated or frozen.
4. **Ambient Display Privilege Boundary:** Setting `view-mode="ambient"` (e.g. on `MagicMirror` or unauthenticated wall views) strips all override, resume, and approval controls while keeping `Freeze` accessible.

