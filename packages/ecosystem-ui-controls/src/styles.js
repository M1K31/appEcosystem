"use strict";

/**
 * Apple HIG Shadow DOM design stylesheet and crisp inline SVG icon map.
 * Consumes CSS custom properties defined in theme/ecosystem-theme.css with
 * high-contrast fallbacks so components work standalone or themed.
 */

const ICONS = Object.freeze({
    "lock-shield": `<svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 2.2 16 4.8v4.7c0 4.1-2.6 7.3-6 8.6-3.4-1.3-6-4.5-6-8.6V4.8L10 2.2Z"/><rect x="7.5" y="9.2" width="5" height="4" rx="1"/><path d="M8.5 9.2V7.8a1.5 1.5 0 0 1 3 0v1.4"/></svg>`,
    "lock-open-clock": `<svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="9" width="9" height="7.5" rx="1.6"/><path d="M5.5 9V6.2a2.6 2.6 0 0 1 5.1-.6"/><circle cx="15" cy="14" r="3.5"/><path d="M15 12.4V14l1.1.8"/></svg>`,
    "shield-octagon": `<svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="6.6 2.2 13.4 2.2 17.8 6.6 17.8 13.4 13.4 17.8 6.6 17.8 2.2 13.4 2.2 6.6"/><path d="M10 6.2v4.3"/><circle cx="10" cy="13.5" r="0.7" fill="currentColor"/></svg>`,
    "octagon-pause": `<svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="6.6 2.2 13.4 2.2 17.8 6.6 17.8 13.4 13.4 17.8 6.6 17.8 2.2 13.4 2.2 6.6"/><path d="M8.3 7.5v5M11.7 7.5v5"/></svg>`,
    "play-shield": `<svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 2.2 16 4.8v4.7c0 4.1-2.6 7.3-6 8.6-3.4-1.3-6-4.5-6-8.6V4.8L10 2.2Z"/><polygon points="8.6 7.6 12.8 10 8.6 12.4" fill="currentColor" stroke="none"/></svg>`,
    "mic-off": `<svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 3l14 14"/><path d="M12.5 8.8V6a2.5 2.5 0 0 0-4.6-1.3"/><path d="M7.5 7.5V10a2.5 2.5 0 0 0 4.2 1.8"/><path d="M5 10a5 5 0 0 0 8.3 3.7M10 15v2.8M7.2 17.8h5.6"/></svg>`,
    "mic-ready": `<svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="7.5" y="3" width="5" height="9" rx="2.5"/><path d="M5 9.8a5 5 0 0 0 10 0M10 14.8v3M7.2 17.8h5.6"/></svg>`,
    "mic-live": `<svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="7.5" y="3" width="5" height="9" rx="2.5" fill="currentColor" fill-opacity="0.25"/><path d="M5 9.8a5 5 0 0 0 10 0M10 14.8v3M7.2 17.8h5.6"/></svg>`,
    "waveform": `<svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M3 10h1.5M7 6v8M10 4v12M13 7v6M15.5 10H17"/></svg>`,
});

const SHARED_STYLES = `
:host {
  display: block;
  box-sizing: border-box;
  font-family: var(--font-body, 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif);
  color: var(--text-primary, hsl(220, 20%, 96%));
  --_touch-min: var(--touch-target-min, 44px);
  --_radius-sm: var(--radius-sm, 6px);
  --_radius-md: var(--radius-md, 12px);
  --_radius-lg: var(--radius-lg, 20px);
  --_radius-pill: var(--radius-pill, 9999px);
  --_bg-panel: var(--bg-panel, hsl(220, 16%, 13%));
  --_bg-input: var(--bg-input, hsl(220, 14%, 18%));
  --_bg-hover: var(--bg-hover, hsl(220, 15%, 22%));
  --_glass-bg: var(--glass-bg, hsla(220, 16%, 13%, 0.78));
  --_glass-blur: var(--glass-blur, blur(20px));
  --_glass-border: var(--glass-border, hsla(220, 20%, 96%, 0.12));
  --_text-primary: var(--text-primary, hsl(220, 20%, 96%));
  --_text-secondary: var(--text-secondary, hsl(220, 10%, 75%));
  --_text-tertiary: var(--text-tertiary, hsl(220, 8%, 58%));
  --_accent: var(--color-accent, hsl(210, 100%, 52%));
  --_text-on-accent: var(--text-on-accent, hsl(0, 0%, 100%));
  --_fill-accent: var(--fill-accent, hsl(211, 100%, 44%));
  --_fill-critical: var(--fill-critical, hsl(0, 78%, 48%));
  --_text-on-critical: var(--text-on-critical, hsl(0, 0%, 100%));
  --_success: var(--color-success, hsl(120, 60%, 48%));
  --_warning: var(--color-warning, hsl(35, 100%, 55%));
  --_error: var(--color-error, hsl(0, 85%, 60%));
  --_ease: var(--anim-ease, cubic-bezier(0.16, 1, 0.3, 1));
  --_fast: var(--anim-fast, 0.14s);
}

*, *::before, *::after {
  box-sizing: border-box;
}

:focus-visible {
  outline: 2px solid var(--_accent);
  outline-offset: 2px;
}

.policy-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem 1rem;
  padding: 0.5rem 1rem;
  min-height: 52px;
  background: var(--_glass-bg);
  backdrop-filter: var(--_glass-blur);
  -webkit-backdrop-filter: var(--_glass-blur);
  border-bottom: 1px solid var(--_glass-border);
  transition: background-color 0.25s var(--_ease), border-color 0.25s var(--_ease);
}

.policy-bar[data-state="restrictions_off_scoped"] {
  border-bottom: 2px solid var(--_warning);
  background: linear-gradient(90deg, hsla(35, 100%, 50%, 0.16), var(--_glass-bg) 55%);
}

.policy-bar[data-state="frozen"] {
  border-bottom: 2px solid var(--_error);
  background: linear-gradient(90deg, hsla(0, 85%, 55%, 0.22), var(--_glass-bg) 65%);
}

.status-cluster {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.65rem;
  min-width: 0;
  flex: 1 1 320px;
}

.badge {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.3rem 0.7rem;
  border-radius: var(--_radius-pill);
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  white-space: nowrap;
  border: 1px solid var(--_glass-border);
  background: var(--_bg-input);
  color: var(--_text-primary);
}

.badge[data-severity="normal"] {
  border-color: hsla(120, 60%, 48%, 0.45);
  color: var(--_success);
}

.badge[data-severity="warning"] {
  border-color: hsla(35, 100%, 55%, 0.6);
  color: var(--_warning);
}

.badge[data-severity="critical"] {
  border-color: hsla(0, 85%, 60%, 0.75);
  background: hsla(0, 85%, 52%, 0.2);
  color: var(--_error);
}

.copy-stack {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.headline {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--_text-primary);
  line-height: 1.3;
}

.detail {
  font-size: 0.76rem;
  color: var(--_text-secondary);
  line-height: 1.3;
}

.sync-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.22rem 0.6rem;
  border-radius: var(--_radius-pill);
  font-size: 0.74rem;
  color: var(--_text-secondary);
  background: var(--_bg-input);
  border: 1px solid var(--_glass-border);
  white-space: nowrap;
}

.sync-pill[data-unreachable="true"] {
  border-color: var(--_warning);
  color: var(--_warning);
  font-weight: 600;
}

.actions-cluster {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
}

button.hig-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.45rem;
  min-height: var(--_touch-min);
  min-width: var(--_touch-min);
  padding: 0 0.95rem;
  border-radius: var(--_radius-md);
  border: 1px solid var(--_glass-border);
  background: var(--_bg-input);
  color: var(--_text-primary);
  font-family: inherit;
  font-size: 0.84rem;
  font-weight: 600;
  cursor: pointer;
  transition: transform var(--_fast) var(--_ease), background-color var(--_fast) var(--_ease), border-color var(--_fast) var(--_ease);
}

button.hig-btn:hover:not(:disabled) {
  background: var(--_bg-hover);
}

button.hig-btn:active:not(:disabled) {
  transform: scale(0.98);
}

button.hig-btn:disabled {
  opacity: 0.58;
  cursor: not-allowed;
}

button.hig-btn[data-variant="primary"] {
  background: var(--_fill-accent);
  border-color: transparent;
  color: var(--_text-on-accent);
}

button.hig-btn[data-variant="restore"] {
  background: hsla(120, 60%, 42%, 0.2);
  border-color: var(--_success);
  color: var(--_text-primary);
}

button.hig-btn[data-variant="danger"],
button.hig-btn[data-variant="critical"] {
  background: hsla(0, 85%, 52%, 0.18);
  border-color: var(--_error);
  color: var(--_text-primary);
}

button.hig-btn[data-variant="critical"] {
  background: var(--_fill-critical);
  border-color: transparent;
  color: var(--_text-on-critical);
}

/* Filled variants keep their fill on hover. The generic hover rule above would
   swap in --_bg-hover while the label keeps its on-fill colour, which drops
   contrast to ~1.4:1 (dark label on dark purple in cyberpunk; white label on
   light grey in the light theme). Hover darkens the fill: lightening it
   would lower the contrast of a white label. */
button.hig-btn[data-variant="primary"]:hover:not(:disabled) {
  background: var(--_fill-accent);
  filter: brightness(0.92);
}

button.hig-btn[data-variant="critical"]:hover:not(:disabled) {
  background: var(--_fill-critical);
  filter: brightness(0.92);
}

/* Modal Backdrop & HIG Sheet */
.modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 9999;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1rem;
  background: hsla(220, 25%, 5%, 0.66);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
}

.modal-backdrop[hidden] {
  display: none !important;
}

.modal-sheet {
  width: min(680px, 100%);
  max-height: 90vh;
  overflow-y: auto;
  background: var(--_bg-panel);
  border: 1px solid var(--_glass-border);
  border-radius: var(--_radius-lg);
  padding: 1.5rem;
  box-shadow: var(--shadow-lg, 0 16px 36px rgba(0, 0, 0, 0.45));
}

.modal-title {
  margin: 0 0 0.35rem 0;
  font-size: 1.2rem;
  font-weight: 700;
}

.modal-subtitle {
  margin: 0 0 1.1rem 0;
  font-size: 0.86rem;
  color: var(--_text-secondary);
}

.invariant-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 0.85rem;
  margin-bottom: 1.1rem;
}

.inset-card {
  padding: 0.85rem 1rem;
  border-radius: var(--_radius-md);
  background: var(--_bg-input);
  border: 1px solid var(--_glass-border);
}

.inset-card h4 {
  margin: 0 0 0.45rem 0;
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.inset-card[data-kind="bypassed"] h4 {
  color: var(--_warning);
}

.inset-card[data-kind="enforced"] h4 {
  color: var(--_success);
}

.inset-card ul {
  margin: 0;
  padding-left: 1.1rem;
  font-size: 0.8rem;
  color: var(--_text-secondary);
  line-height: 1.45;
}

.field-group {
  margin-bottom: 1rem;
}

.field-label {
  display: block;
  font-size: 0.82rem;
  font-weight: 600;
  margin-bottom: 0.4rem;
}

.pill-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem;
}

label.check-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  min-height: var(--_touch-min);
  padding: 0 0.8rem;
  border-radius: var(--_radius-md);
  background: var(--_bg-input);
  border: 1px solid var(--_glass-border);
  font-size: 0.82rem;
  cursor: pointer;
}

input.text-input,
select.select-input {
  width: 100%;
  min-height: var(--_touch-min);
  padding: 0 0.8rem;
  border-radius: var(--_radius-md);
  border: 1px solid var(--_glass-border);
  background: var(--_bg-input);
  color: var(--_text-primary);
  font-family: inherit;
  font-size: 0.88rem;
}

.error-box {
  margin: 0.75rem 0;
  padding: 0.75rem 0.9rem;
  border-radius: var(--_radius-md);
  background: hsla(0, 85%, 52%, 0.16);
  border: 1px solid var(--_error);
  color: var(--_text-primary);
  font-size: 0.82rem;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 0.6rem;
  margin-top: 1.2rem;
}

/* Mic Pill */
.mic-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.25rem 0.5rem;
  border-radius: var(--_radius-pill);
  background: var(--_glass-bg);
  border: 1px solid var(--_glass-border);
}

.mic-meta {
  display: flex;
  flex-direction: column;
  padding: 0 0.35rem;
}

.mic-status {
  font-size: 0.78rem;
  font-weight: 600;
  line-height: 1.2;
}

.mic-privacy {
  font-size: 0.68rem;
  color: var(--_text-tertiary);
  line-height: 1.2;
}

.mic-pill[data-state="listening"] {
  border-color: var(--_accent);
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    transition-duration: 0.001ms !important;
    animation-duration: 0.001ms !important;
  }
}
`;

function renderIcon(name) {
    return ICONS[name] || ICONS["lock-shield"];
}

module.exports = {
    ICONS,
    SHARED_STYLES,
    renderIcon,
};

