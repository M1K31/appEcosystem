"use strict";

const {
    ALWAYS_ENFORCED_INVARIANTS,
    BYPASSED_GATES_DEFAULT,
    ACTION_CLASS_OPTIONS,
    DURATION_PRESETS,
    computeEffectivePolicyBanner,
    validateOverrideForm,
    computeFreezeButtonState,
    computeMicPillState,
} = require("./model");
const { SHARED_STYLES, renderIcon } = require("./styles");

function escapeHtml(value) {
    return String(value == null ? "" : value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

/**
 * Define and optionally register the 4 ecosystem Web Components against a
 * CustomElementRegistry + HTMLElement constructor (browser globals by default,
 * or lightweight test doubles in Node unit tests).
 */
function createComponentClasses(BaseElement) {
    class EcosystemFreezeButton extends BaseElement {
        static get observedAttributes() {
            return ["frozen", "view-mode", "confirm-tap"];
        }

        constructor() {
            super();
            this._armed = false;
            this._armTimer = null;
            this.attachShadow({ mode: "open" });
        }

        connectedCallback() {
            this.render();
        }

        disconnectedCallback() {
            this._clearArmTimer();
        }

        attributeChangedCallback() {
            if (this.hasAttribute("frozen")) {
                this._armed = false;
                this._clearArmTimer();
            }
            this.render();
        }

        _clearArmTimer() {
            if (this._armTimer) {
                clearTimeout(this._armTimer);
                this._armTimer = null;
            }
        }

        _handleClick() {
            const frozen = this.hasAttribute("frozen") && this.getAttribute("frozen") !== "false";
            const viewMode = this.getAttribute("view-mode") === "ambient" ? "ambient" : "admin";
            const confirmTap = this.hasAttribute("confirm-tap") && this.getAttribute("confirm-tap") !== "false";

            if (frozen) {
                if (viewMode === "admin") {
                    this.dispatchEvent(
                        new CustomEvent("ecosystem-resume-request", {
                            bubbles: true,
                            composed: true,
                            detail: { requestedAt: Date.now() },
                        })
                    );
                }
                return;
            }

            if (confirmTap && !this._armed) {
                this._armed = true;
                this._clearArmTimer();
                this._armTimer = setTimeout(() => {
                    this._armed = false;
                    this.render();
                    // The expiry re-render also removes the focused trigger; keep a
                    // keyboard user on it so they can re-arm without hunting for focus.
                    this.shadowRoot.querySelector('[data-action="freeze-trigger"]')?.focus();
                }, 3000);
                this.render();
                // render() replaces the focused trigger; restore focus so a
                // keyboard user's second Enter/Space confirms Freeze.
                this.shadowRoot.querySelector('[data-action="freeze-trigger"]')?.focus();
                return;
            }

            this._armed = false;
            this._clearArmTimer();
            this.render();
            this.dispatchEvent(
                new CustomEvent("ecosystem-freeze-request", {
                    bubbles: true,
                    composed: true,
                    detail: {
                        viewMode,
                        requestedAt: Date.now(),
                    },
                })
            );
        }

        render() {
            const frozen = this.hasAttribute("frozen") && this.getAttribute("frozen") !== "false";
            const viewMode = this.getAttribute("view-mode") === "ambient" ? "ambient" : "admin";
            const confirmTap = this.hasAttribute("confirm-tap") && this.getAttribute("confirm-tap") !== "false";
            const vm = computeFreezeButtonState({
                frozen,
                viewMode,
                confirmTap,
                armed: this._armed,
            });

            this.shadowRoot.innerHTML = `
                <style>${SHARED_STYLES}</style>
                <button
                    type="button"
                    class="hig-btn"
                    data-action="freeze-trigger"
                    data-variant="${escapeHtml(vm.severity)}"
                    aria-label="${escapeHtml(vm.ariaLabel)}"
                    ${vm.disabled ? "disabled" : ""}
                >
                    ${renderIcon(vm.icon)}
                    <span>${escapeHtml(vm.label)}</span>
                </button>
            `;
            const btn = this.shadowRoot.querySelector('[data-action="freeze-trigger"]');
            if (btn) {
                btn.addEventListener("click", () => this._handleClick());
            }
        }
    }

    class EcosystemPolicyBar extends BaseElement {
        static get observedAttributes() {
            return ["view-mode", "policy-state", "confirm-freeze-tap"];
        }

        constructor() {
            super();
            this._policyState = null;
            this._tickTimer = null;
            this._notifiedExpiryForGrant = null;
            this.attachShadow({ mode: "open" });
        }

        get policyState() {
            if (this._policyState) return this._policyState;
            const attr = this.getAttribute("policy-state");
            if (attr) {
                try {
                    return JSON.parse(attr);
                } catch {
                    return null;
                }
            }
            return null;
        }

        set policyState(nextState) {
            this._policyState = nextState && typeof nextState === "object" ? nextState : null;
            this._syncCountdownTimer();
            this.render();
        }

        connectedCallback() {
            this._syncCountdownTimer();
            this.render();
        }

        disconnectedCallback() {
            this._stopCountdownTimer();
        }

        attributeChangedCallback(name) {
            if (name === "policy-state") {
                this._policyState = null;
                this._syncCountdownTimer();
            }
            this.render();
        }

        _stopCountdownTimer() {
            if (this._tickTimer) {
                clearInterval(this._tickTimer);
                this._tickTimer = null;
            }
        }

        _syncCountdownTimer() {
            this._stopCountdownTimer();
            const st = this.policyState;
            if (
                st &&
                !st.frozen &&
                st.restrictions === "off_scoped" &&
                st.active_override &&
                st.active_override.expires_at
            ) {
                this._tickTimer = setInterval(() => this.render(), 1000);
            }
        }

        render() {
            const viewMode = this.getAttribute("view-mode") === "ambient" ? "ambient" : "admin";
            const raw = this.policyState;
            const vm = computeEffectivePolicyBanner(raw, { viewMode });

            if (vm.overrideExpired && raw && raw.active_override) {
                const grantId = raw.active_override.grant_id || "expired";
                if (this._notifiedExpiryForGrant !== grantId) {
                    this._notifiedExpiryForGrant = grantId;
                    this._stopCountdownTimer();
                    this.dispatchEvent(
                        new CustomEvent("ecosystem-override-expired", {
                            bubbles: true,
                            composed: true,
                            detail: { grantId },
                        })
                    );
                }
            }

            const showSync =
                vm.effectiveState === "frozen" ||
                vm.effectiveState === "restrictions_off_scoped" ||
                vm.deviceSync.hasUnreachable;

            const syncHtml = showSync
                ? `<span class="sync-pill" data-unreachable="${vm.deviceSync.hasUnreachable ? "true" : "false"}">${escapeHtml(vm.deviceSync.summaryText)}</span>`
                : "";

            const restoreBtn = vm.actions.canRestoreRestrictions
                ? `<button type="button" class="hig-btn" data-action="restore" data-variant="restore">Restore Restrictions</button>`
                : "";

            const manageBtn = vm.actions.canManageRestrictions
                ? `<button type="button" class="hig-btn" data-action="manage">${vm.effectiveState === "restrictions_off_scoped" ? "Inspect Scope..." : "Manage Restrictions..."}</button>`
                : "";

            const resumeBtn = vm.actions.canResume
                ? `<button type="button" class="hig-btn" data-action="resume" data-variant="primary">${renderIcon("play-shield")}<span>Resume Operations...</span></button>`
                : "";

            const confirmTapAttr =
                viewMode === "ambient" || this.hasAttribute("confirm-freeze-tap")
                    ? 'confirm-tap="true"'
                    : "";

            const freezeBtn = vm.actions.canFreeze
                ? `<ecosystem-freeze-button view-mode="${escapeHtml(viewMode)}" ${confirmTapAttr}></ecosystem-freeze-button>`
                : viewMode === "ambient" && vm.effectiveState === "frozen"
                    ? `<ecosystem-freeze-button frozen="true" view-mode="ambient"></ecosystem-freeze-button>`
                    : "";

            this.shadowRoot.innerHTML = `
                <style>${SHARED_STYLES}</style>
                <div class="policy-bar" role="region" aria-label="Ecosystem Policy & Safety Status" data-state="${escapeHtml(vm.effectiveState)}">
                    <div class="status-cluster" role="status" aria-live="polite">
                        <span class="badge" data-severity="${escapeHtml(vm.severity)}">
                            ${renderIcon(vm.icon)}
                            <span>${escapeHtml(vm.badgeText)}</span>
                        </span>
                        <div class="copy-stack">
                            <span class="headline">${escapeHtml(vm.headline)}</span>
                            <span class="detail">${escapeHtml(vm.detailText)}</span>
                        </div>
                        ${syncHtml}
                    </div>
                    <div class="actions-cluster">
                        ${restoreBtn}
                        ${manageBtn}
                        ${resumeBtn}
                        ${freezeBtn}
                    </div>
                </div>
            `;

            const onBtn = (selector, eventName) => {
                const el = this.shadowRoot.querySelector(selector);
                if (el) {
                    el.addEventListener("click", () => {
                        this.dispatchEvent(
                            new CustomEvent(eventName, {
                                bubbles: true,
                                composed: true,
                                detail: { effectiveState: vm.effectiveState, requestedAt: Date.now() },
                            })
                        );
                    });
                }
            };
            onBtn('[data-action="restore"]', "ecosystem-restore-restrictions");
            onBtn('[data-action="manage"]', "ecosystem-manage-restrictions");
            onBtn('[data-action="resume"]', "ecosystem-resume-request");
        }
    }

    class EcosystemOverrideModal extends BaseElement {
        static get observedAttributes() {
            return ["open"];
        }

        constructor() {
            super();
            this._availableApps = ["openeye", "aegissiem", "cyber-agents", "ai-for-survival"];
            this._availableDevices = ["local-device"];
            this._errors = [];
            this._stepUpMethod = "totp";
            this._passkeyAssertion = "";
            this._selectedDuration = "30m";
            // When true, the next render() starts from a fresh form instead of
            // restoring captured input. Set on every open/close transition and
            // after a submit so a single-use TOTP code or an "until revoked"
            // consent never carries across a modal session.
            this._skipDraftRestore = true;
            // Pull focus into the sheet on the next render after an open
            // transition only (not on every re-render, which would steal focus
            // while the operator is typing or changing the duration).
            this._focusOnOpen = false;
            // Best-effort element to return focus to when the modal closes.
            this._restoreFocusTo = null;
            this.attachShadow({ mode: "open" });
            // keydown composes out of the shadow DOM, so this window-level
            // listener sees Escape and Tab while focus is inside the sheet.
            this._onKeyDown = (ev) => {
                // Must agree with render(): open="false" is a closed modal, and a
                // closed modal must never swallow Tab for the whole page.
                if (!this._isOpen()) {
                    return;
                }
                if (ev.key === "Escape") {
                    this.close();
                    return;
                }
                if (ev.key === "Tab") {
                    this._trapTab(ev);
                }
            };
        }

        // Single definition of "open", shared by render() and the key handler.
        _isOpen() {
            return this.hasAttribute("open") && this.getAttribute("open") !== "false";
        }

        // Forget the step-up credential and method, and start the next render
        // from a fresh form.
        _resetStepUp() {
            this._passkeyAssertion = "";
            this._stepUpMethod = "totp";
            this._skipDraftRestore = true;
        }

        // Return focus to whatever opened the modal so a keyboard user is not
        // stranded. Best-effort: the opener may be gone or not focusable.
        _returnFocus() {
            const target = this._restoreFocusTo;
            this._restoreFocusTo = null;
            if (target && target.isConnected && typeof target.focus === "function") {
                try {
                    target.focus();
                } catch (_e) {
                    /* element no longer focusable; ignore */
                }
            }
        }

        // Focusable controls inside the sheet, in DOM/tab order. Conditionally
        // rendered fields (until-revoked consent, error box) are simply absent
        // from the tree when not shown, so no visibility filtering is needed.
        _focusable() {
            const root = this.shadowRoot;
            if (!root) {
                return [];
            }
            return Array.from(
                root.querySelectorAll(
                    'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
                )
            );
        }

        // Keep Tab / Shift+Tab cycling within the modal so keyboard focus cannot
        // land on the backdrop or page behind this aria-modal step-up dialog.
        _trapTab(ev) {
            const focusable = this._focusable();
            if (focusable.length === 0) {
                return;
            }
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            const active = this.shadowRoot.activeElement;
            const inside = active && this.shadowRoot.contains(active);
            if (ev.shiftKey) {
                if (!inside || active === first) {
                    ev.preventDefault();
                    last.focus();
                }
            } else if (!inside || active === last) {
                ev.preventDefault();
                first.focus();
            }
        }

        set availableApps(list) {
            // Accept an empty array so clearing the inventory (discovery returned
            // no targets) actually clears the modal instead of keeping stale items.
            if (Array.isArray(list)) {
                this._availableApps = list.map(String);
                this.render();
            }
        }

        get availableApps() {
            return this._availableApps;
        }

        set availableDevices(list) {
            if (Array.isArray(list)) {
                this._availableDevices = list.map(String);
                this.render();
            }
        }

        get availableDevices() {
            return this._availableDevices;
        }

        setPasskeyAssertion(assertionToken) {
            this._stepUpMethod = "passkey";
            this._passkeyAssertion = String(assertionToken || "");
            this._errors = [];
            this.render();
        }

        open() {
            this._errors = [];
            // Remember who opened us so focus can return there on close. In a
            // nested shadow tree document.activeElement resolves to the outer
            // host; focusing it is a best-effort no-op when it is not focusable.
            try {
                this._restoreFocusTo =
                    typeof document !== "undefined" ? document.activeElement : null;
            } catch (_e) {
                this._restoreFocusTo = null;
            }
            this._focusOnOpen = true;
            this.setAttribute("open", "true");
        }

        close() {
            // Drop sensitive session state so it cannot be restored on reopen.
            this._passkeyAssertion = "";
            this._selectedDuration = "30m";
            this._skipDraftRestore = true;
            this._focusOnOpen = false;
            this.removeAttribute("open");
            this._returnFocus();
            this.dispatchEvent(
                new CustomEvent("ecosystem-override-cancel", { bubbles: true, composed: true })
            );
        }

        connectedCallback() {
            if (typeof window !== "undefined" && window.addEventListener) {
                window.addEventListener("keydown", this._onKeyDown);
            }
            this.render();
        }

        disconnectedCallback() {
            if (typeof window !== "undefined" && window.removeEventListener) {
                window.removeEventListener("keydown", this._onKeyDown);
            }
        }

        attributeChangedCallback() {
            // The only observed attribute is "open"; an open/close transition must
            // present a fresh form, not restore the previous session's input.
            this._skipDraftRestore = true;
            this.render();
        }

        _collectAndSubmit() {
            const root = this.shadowRoot;
            const checkedValues = (name) =>
                Array.from(root.querySelectorAll(`input[name="${name}"]:checked`)).map((el) => el.value);

            const durationEl = root.querySelector('select[name="duration"]');
            const reasonEl = root.querySelector('input[name="reason"]');
            const totpEl = root.querySelector('input[name="totp_code"]');
            const confirmUnboundedEl = root.querySelector('input[name="confirm_until_revoked"]');

            const duration = durationEl ? durationEl.value : this._selectedDuration;
            const stepUpCredential =
                this._stepUpMethod === "passkey"
                    ? this._passkeyAssertion
                    : totpEl
                        ? totpEl.value
                        : "";

            const result = validateOverrideForm({
                apps: checkedValues("apps"),
                devices: checkedValues("devices"),
                actionClasses: checkedValues("action_classes"),
                duration,
                confirmUntilRevoked: Boolean(confirmUnboundedEl && confirmUnboundedEl.checked),
                reason: reasonEl ? reasonEl.value : "",
                stepUpMethod: this._stepUpMethod,
                stepUpCredential,
            });

            if (!result.valid) {
                this._errors = result.errors;
                // Clear the step-up credential after every submit attempt: a TOTP is
                // single-use/time-boxed and a passkey assertion is one-shot, so the
                // operator should re-enter one rather than reuse a stale value.
                if (totpEl) totpEl.value = "";
                this._passkeyAssertion = "";
                this.render();
                return;
            }

            this._errors = [];
            // The credential has been handed to the payload; drop it so a reopened
            // modal cannot show "Passkey Ready" or re-emit a one-shot assertion.
            this._resetStepUp();
            this.removeAttribute("open");
            this.dispatchEvent(
                new CustomEvent("ecosystem-override-submit", {
                    bubbles: true,
                    composed: true,
                    detail: result.payload,
                })
            );
            this._returnFocus();
        }

        _captureDraft() {
            // Snapshot in-progress form input so a re-render (duration change,
            // passkey verification, validation failure) does not wipe it.
            const root = this.shadowRoot;
            if (!root) return null;
            if (!root.querySelector('input[name="reason"], input[name="totp_code"], input[name="apps"]')) {
                return null; // nothing rendered yet (first render)
            }
            const checked = (name) =>
                Array.from(root.querySelectorAll(`input[name="${name}"]:checked`)).map((el) => el.value);
            const confEl = root.querySelector('input[name="confirm_until_revoked"]');
            const reasonEl = root.querySelector('input[name="reason"]');
            const totpEl = root.querySelector('input[name="totp_code"]');
            return {
                apps: checked("apps"),
                devices: checked("devices"),
                action_classes: checked("action_classes"),
                reason: reasonEl ? reasonEl.value : undefined,
                totp_code: totpEl ? totpEl.value : undefined,
                confirm: confEl ? confEl.checked : undefined,
            };
        }

        _restoreDraft(draft) {
            if (!draft) return;
            const root = this.shadowRoot;
            ["apps", "devices", "action_classes"].forEach((name) => {
                const want = new Set(draft[name] || []);
                root.querySelectorAll(`input[name="${name}"]`).forEach((el) => {
                    el.checked = want.has(el.value);
                });
            });
            const reasonEl = root.querySelector('input[name="reason"]');
            if (reasonEl && draft.reason !== undefined) reasonEl.value = draft.reason;
            const totpEl = root.querySelector('input[name="totp_code"]');
            if (totpEl && draft.totp_code !== undefined) totpEl.value = draft.totp_code;
            const confEl = root.querySelector('input[name="confirm_until_revoked"]');
            if (confEl && draft.confirm !== undefined) confEl.checked = draft.confirm;
        }

        render() {
            // Skip the capture/restore on an open/close transition or just after a
            // submit, so a fresh form is shown and no TOTP/consent is carried over.
            const _draft = this._skipDraftRestore ? null : this._captureDraft();
            this._skipDraftRestore = false;
            const isOpen = this._isOpen();
            const bypassedItems = BYPASSED_GATES_DEFAULT.map(
                (item) => `<li>${escapeHtml(item)}</li>`
            ).join("");
            const enforcedItems = ALWAYS_ENFORCED_INVARIANTS.map(
                (item) => `<li>${escapeHtml(item.label)}</li>`
            ).join("");

            const appPills = this._availableApps
                .map(
                    (app) => `
                    <label class="check-pill">
                        <input type="checkbox" name="apps" value="${escapeHtml(app)}" />
                        <span>${escapeHtml(app)}</span>
                    </label>`
                )
                .join("");

            const devicePills = this._availableDevices
                .map(
                    (dev, idx) => `
                    <label class="check-pill">
                        <input type="checkbox" name="devices" value="${escapeHtml(dev)}" ${idx === 0 ? "checked" : ""} />
                        <span>${escapeHtml(dev)}</span>
                    </label>`
                )
                .join("");

            const actionPills = ACTION_CLASS_OPTIONS.map(
                (ac) => `
                <label class="check-pill">
                    <input type="checkbox" name="action_classes" value="${escapeHtml(ac.id)}" />
                    <span>${escapeHtml(ac.label)}</span>
                </label>`
            ).join("");

            const durationOptions = DURATION_PRESETS.map(
                (d) =>
                    `<option value="${escapeHtml(d.id)}" ${d.id === this._selectedDuration ? "selected" : ""}>${escapeHtml(d.label)}</option>`
            ).join("");

            const untilRevokedConfirmHtml =
                this._selectedDuration === "until_revoked"
                    ? `
                    <div class="field-group">
                        <label class="check-pill">
                            <input type="checkbox" name="confirm_until_revoked" value="true" />
                            <span>I understand this override will remain active until manually restored or preempted by Freeze.</span>
                        </label>
                    </div>`
                    : "";

            const errorHtml =
                this._errors.length > 0
                    ? `<div class="error-box" role="alert">${this._errors.map(escapeHtml).join("<br/>")}</div>`
                    : "";

            this.shadowRoot.innerHTML = `
                <style>${SHARED_STYLES}</style>
                <div class="modal-backdrop" ${isOpen ? "" : "hidden"}>
                    <div class="modal-sheet" role="dialog" aria-modal="true" aria-labelledby="override-modal-title">
                        <h3 class="modal-title" id="override-modal-title">Scoped Restriction Override</h3>
                        <p class="modal-subtitle">
                            Temporarily relax approval &amp; threshold gates for an explicit scope and duration. Core authentication, target consent, audit, and Freeze invariants remain strictly enforced.
                        </p>

                        <div class="invariant-grid">
                            <div class="inset-card" data-kind="bypassed">
                                <h4>Temporarily Bypassed in Scope</h4>
                                <ul>${bypassedItems}</ul>
                            </div>
                            <div class="inset-card" data-kind="enforced">
                                <h4>Always Enforced (Immutable)</h4>
                                <ul>${enforcedItems}</ul>
                            </div>
                        </div>

                        <div class="field-group">
                            <span class="field-label">1. Target Applications</span>
                            <div class="pill-grid">${appPills}</div>
                        </div>

                        <div class="field-group">
                            <span class="field-label">2. Target Devices</span>
                            <div class="pill-grid">${devicePills}</div>
                        </div>

                        <div class="field-group">
                            <span class="field-label">3. Permitted Action Classes</span>
                            <div class="pill-grid">${actionPills}</div>
                        </div>

                        <div class="field-group">
                            <label class="field-label" for="override-duration">4. Session Duration</label>
                            <select class="select-input" id="override-duration" name="duration">
                                ${durationOptions}
                            </select>
                        </div>

                        ${untilRevokedConfirmHtml}

                        <div class="field-group">
                            <label class="field-label" for="override-reason">5. Audit Reason (required)</label>
                            <input
                                class="text-input"
                                id="override-reason"
                                type="text"
                                name="reason"
                                placeholder="e.g. Active incident containment drill on edge NVR"
                                autocomplete="off"
                            />
                        </div>

                        <div class="field-group">
                            <label class="field-label" for="override-totp">6. Step-Up Verification (TOTP 2FA or Passkey)</label>
                            <div class="pill-grid">
                                <input
                                    class="text-input"
                                    style="flex: 1 1 200px;"
                                    id="override-totp"
                                    type="text"
                                    inputmode="numeric"
                                    pattern="[0-9]*"
                                    name="totp_code"
                                    placeholder="${this._stepUpMethod === "passkey" && this._passkeyAssertion ? "Passkey verified" : "6-digit TOTP code"}"
                                    autocomplete="one-time-code"
                                />
                                <button type="button" class="hig-btn" data-action="passkey">
                                    ${this._stepUpMethod === "passkey" && this._passkeyAssertion ? "Passkey Ready" : "Use Passkey..."}
                                </button>
                            </div>
                        </div>

                        ${errorHtml}

                        <div class="modal-footer">
                            <button type="button" class="hig-btn" data-action="cancel">Cancel</button>
                            <button type="button" class="hig-btn" data-variant="primary" data-action="submit">
                                Authorize Scoped Override
                            </button>
                        </div>
                    </div>
                </div>
            `;

            const durationSelect = this.shadowRoot.querySelector('select[name="duration"]');
            if (durationSelect) {
                durationSelect.addEventListener("change", (ev) => {
                    this._selectedDuration = ev.target.value;
                    this.render();
                });
            }

            const totpInput = this.shadowRoot.querySelector('input[name="totp_code"]');
            if (totpInput) {
                totpInput.addEventListener("input", () => {
                    this._stepUpMethod = "totp";
                });
            }

            const passkeyBtn = this.shadowRoot.querySelector('[data-action="passkey"]');
            if (passkeyBtn) {
                passkeyBtn.addEventListener("click", () => {
                    this.dispatchEvent(
                        new CustomEvent("ecosystem-passkey-request", {
                            bubbles: true,
                            composed: true,
                        })
                    );
                });
            }

            const cancelBtn = this.shadowRoot.querySelector('[data-action="cancel"]');
            if (cancelBtn) {
                cancelBtn.addEventListener("click", () => this.close());
            }

            const submitBtn = this.shadowRoot.querySelector('[data-action="submit"]');
            if (submitBtn) {
                submitBtn.addEventListener("click", () => this._collectAndSubmit());
            }

            // Restore any in-progress input captured before this re-render.
            this._restoreDraft(_draft);

            // On the open transition only, move focus to the first interactive
            // control so a keyboard user starts inside the dialog and the trap is
            // airtight at both Tab boundaries. The dialog name is conveyed via
            // aria-modal + aria-labelledby rather than by focusing the title.
            if (this._focusOnOpen && isOpen) {
                this._focusOnOpen = false;
                this._focusable()[0]?.focus();
            }
        }
    }

    class EcosystemMicPill extends BaseElement {
        static get observedAttributes() {
            return ["state", "unavailable-reason", "backend-label"];
        }

        constructor() {
            super();
            this.attachShadow({ mode: "open" });
        }

        connectedCallback() {
            this.render();
        }

        attributeChangedCallback() {
            this.render();
        }

        render() {
            const vm = computeMicPillState({
                state: this.getAttribute("state") || "muted",
                unavailableReason: this.getAttribute("unavailable-reason") || "",
                backendLabel: this.getAttribute("backend-label") || "Local Whisper",
            });

            const pttButtonHtml = vm.canPushToTalk
                ? `<button
                        type="button"
                        class="hig-btn"
                        data-action="ptt"
                        data-variant="${vm.state === "listening" ? "primary" : "default"}"
                        aria-pressed="${vm.state === "listening" ? "true" : "false"}"
                   >
                        ${vm.state === "listening" ? "Release / Stop" : "Push to Talk"}
                   </button>`
                : "";

            this.shadowRoot.innerHTML = `
                <style>${SHARED_STYLES}</style>
                <div class="mic-pill" data-state="${escapeHtml(vm.state)}" role="group" aria-label="Local Voice Assistant Control">
                    <button
                        type="button"
                        class="hig-btn"
                        data-action="mute-toggle"
                        aria-pressed="${vm.isMuted ? "true" : "false"}"
                        aria-label="${vm.isMuted ? "Unmute local microphone (Push-to-Talk mode)" : "Mute local microphone"}"
                        ${vm.canToggleMute ? "" : "disabled"}
                    >
                        ${renderIcon(vm.icon)}
                        <span>${vm.isMuted ? "Muted" : "Mute"}</span>
                    </button>
                    <div class="mic-meta" role="status" aria-live="polite">
                        <span class="mic-status">${escapeHtml(vm.statusLabel)}</span>
                        <span class="mic-privacy">${escapeHtml(vm.privacyCaption)}</span>
                    </div>
                    ${pttButtonHtml}
                </div>
            `;

            const muteBtn = this.shadowRoot.querySelector('[data-action="mute-toggle"]');
            if (muteBtn) {
                muteBtn.addEventListener("click", () => {
                    const nextMuted = !vm.isMuted;
                    this.setAttribute("state", nextMuted ? "muted" : "push_to_talk");
                    this.dispatchEvent(
                        new CustomEvent("ecosystem-mic-mute-change", {
                            bubbles: true,
                            composed: true,
                            detail: { muted: nextMuted },
                        })
                    );
                });
            }

            const pttBtn = this.shadowRoot.querySelector('[data-action="ptt"]');
            if (pttBtn) {
                pttBtn.addEventListener("click", () => {
                    const starting = vm.state !== "listening";
                    this.setAttribute("state", starting ? "listening" : "processing");
                    this.dispatchEvent(
                        new CustomEvent(
                            starting ? "ecosystem-mic-ptt-start" : "ecosystem-mic-ptt-stop",
                            {
                                bubbles: true,
                                composed: true,
                                detail: { timestamp: Date.now() },
                            }
                        )
                    );
                });
            }
        }
    }

    return {
        EcosystemFreezeButton,
        EcosystemPolicyBar,
        EcosystemOverrideModal,
        EcosystemMicPill,
    };
}

function registerEcosystemControls(env = {}) {
    const registry =
        env.customElements ||
        (typeof customElements !== "undefined" ? customElements : null);
    const BaseEl =
        env.HTMLElement ||
        (typeof HTMLElement !== "undefined" ? HTMLElement : null);

    if (!registry || !BaseEl) {
        return null;
    }

    const classes = createComponentClasses(BaseEl);
    const definitions = [
        ["ecosystem-freeze-button", "EcosystemFreezeButton"],
        ["ecosystem-policy-bar", "EcosystemPolicyBar"],
        ["ecosystem-override-modal", "EcosystemOverrideModal"],
        ["ecosystem-mic-pill", "EcosystemMicPill"],
    ];

    for (const [tag, key] of definitions) {
        const existing = registry.get(tag);
        if (existing) {
            // Already registered (e.g. the browser auto-registered on load). Return
            // the REGISTERED constructor — the freshly-created one is unregistered
            // and constructing it would throw a TypeError.
            classes[key] = existing;
        } else {
            registry.define(tag, classes[key]);
        }
    }
    return classes;
}

module.exports = {
    escapeHtml,
    createComponentClasses,
    registerEcosystemControls,
};

