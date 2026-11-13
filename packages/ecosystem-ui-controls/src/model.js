"use strict";

/**
 * Pure state, precedence, formatting, and validation models for @appecosystem/ui-controls.
 * Zero DOM dependencies so state transitions are deterministically unit-tested in Node.js.
 */

const ALWAYS_ENFORCED_INVARIANTS = Object.freeze([
    {
        id: "command_authentication",
        label: "Signed command authentication (HMAC-SHA256 / Ed25519)",
    },
    {
        id: "target_authorization_and_consent",
        label: "Target authorization & Zero-Breach-Toolkit baseline/AUP consent",
    },
    {
        id: "input_validation",
        label: "Strict input validation & Draft 2020-12 schema checks",
    },
    {
        id: "audit",
        label: "Immutable hash-chained audit logging",
    },
    {
        id: "freeze",
        label: "Emergency Freeze preemption from any authorized surface",
    },
    {
        id: "cloud_budget_and_data_boundary",
        label: "Cloud spend caps & sensitive data egress blocks",
    },
]);

const BYPASSED_GATES_DEFAULT = Object.freeze([
    "Interactive approval queue prompts (within selected scope)",
    "AI/automation confidence floor gates",
    "Action rate-limit & cooldown timers",
    "Scheduled maintenance window holds",
]);

const ACTION_CLASS_OPTIONS = Object.freeze([
    { id: "investigate", label: "Investigate (active scans & diagnostics)" },
    { id: "contain", label: "Contain (quarantine, block IP, lock node)" },
    { id: "remediate", label: "Remediate (restart service, rotate credentials)" },
    { id: "data_release", label: "Data Release (non-sensitive external export)" },
    { id: "system_change", label: "System Change (configuration & model updates)" },
]);

const DURATION_PRESETS = Object.freeze([
    { id: "15m", label: "15 minutes", seconds: 15 * 60 },
    { id: "30m", label: "30 minutes (Recommended)", seconds: 30 * 60 },
    { id: "1h", label: "1 hour", seconds: 60 * 60 },
    { id: "4h", label: "4 hours", seconds: 4 * 60 * 60 },
    { id: "until_revoked", label: "Until manually revoked", seconds: null },
]);

const AUTHORITY_LABELS = Object.freeze({
    hub_synced: "Hub Synced",
    standalone_local: "Standalone Local",
    lease_expired: "Hub Unreachable · Local Safe Defaults",
});

const MODE_LABELS = Object.freeze({
    normal: "Normal",
    incident: "Incident",
    survival: "Survival",
    freeze: "Freeze",
    maintenance: "Maintenance",
});

function formatRemainingDuration(remainingMs) {
    if (!Number.isFinite(remainingMs) || remainingMs <= 0) {
        return "Expired";
    }
    const totalSeconds = Math.ceil(remainingMs / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    if (hours > 0) {
        return `${hours}h ${String(minutes).padStart(2, "0")}m`;
    }
    if (minutes > 0) {
        return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
    }
    return `${seconds}s`;
}

function summarizeDeviceSync(appliedList, pendingList, unreachableList, verb = "applied") {
    const applied = Array.isArray(appliedList) ? appliedList.filter(Boolean) : [];
    const pending = Array.isArray(pendingList) ? pendingList.filter(Boolean) : [];
    const unreachable = Array.isArray(unreachableList) ? unreachableList.filter(Boolean) : [];

    const parts = [];
    if (applied.length > 0) parts.push(`${applied.length} ${verb}`);
    if (pending.length > 0) parts.push(`${pending.length} pending`);
    if (unreachable.length > 0) parts.push(`${unreachable.length} unreachable`);

    return {
        applied,
        pending,
        unreachable,
        hasUnreachable: unreachable.length > 0,
        hasPending: pending.length > 0,
        summaryText: parts.length > 0 ? parts.join(" · ") : "Local node only",
    };
}

function summarizeScope(scope) {
    if (!scope || typeof scope !== "object") {
        return "No scope";
    }
    const apps = Array.isArray(scope.apps) && scope.apps.length ? scope.apps.join(", ") : "none";
    const devices = Array.isArray(scope.devices) && scope.devices.length ? scope.devices.join(", ") : "none";
    const actions =
        Array.isArray(scope.action_classes) && scope.action_classes.length
            ? scope.action_classes.join(", ")
            : "none";
    return `Apps: ${apps} · Devices: ${devices} · Actions: ${actions}`;
}

/**
 * Compute the effective UI view-model for <ecosystem-policy-bar>.
 *
 * Security & HIG invariants enforced here:
 * 1. Freeze ALWAYS supersedes Restrictions: Off (Scoped).
 * 2. Timed overrides whose expires_at <= nowMs immediately revert to Restrictions: On.
 * 3. viewMode === "ambient" strips all privileged controls (override, restore, resume)
 *    while preserving status visibility and Freeze request capability.
 * 4. Unreachable devices are explicitly surfaced and never merged into applied/acknowledged counts.
 *
 * @param {object|null} rawState  null/non-object yields the "unknown" view-model
 * @param {{viewMode?: "admin"|"ambient", nowMs?: number}} [opts]
 */
function computeEffectivePolicyBanner(rawState, opts = {}) {
    const viewMode = opts.viewMode === "ambient" ? "ambient" : "admin";

    // No usable snapshot yet (first paint, or an unparseable payload). Do NOT
    // claim "RESTRICTIONS: ON": the ecosystem may be frozen or running a scoped
    // override that this surface simply has not heard about. Say so, keep
    // Freeze available, and offer nothing that depends on knowing the state.
    if (!rawState || typeof rawState !== "object" || Array.isArray(rawState)) {
        return {
            effectiveState: "unknown",
            severity: "warning",
            icon: "lock-shield",
            badgeText: "STATUS: UNKNOWN",
            headline: "Waiting for policy state",
            detailText:
                "No policy state received yet — treat restrictions as enforced. Freeze remains available.",
            modeLabel: null,
            authorityKey: "standalone_local",
            authorityLabel: AUTHORITY_LABELS.standalone_local,
            countdownText: null,
            remainingMs: null,
            scopeText: null,
            deviceSync: summarizeDeviceSync([], [], []),
            overrideSuspended: false,
            overrideExpired: false,
            freezeUnconfirmed: false,
            freezeNotDurable: false,
            viewMode,
            actions: {
                canFreeze: true,
                canResume: false,
                canManageRestrictions: false,
                canRestoreRestrictions: false,
            },
        };
    }

    const state = rawState;
    const nowMs = opts.nowMs == null ? Date.now() : Number(opts.nowMs);
    const isAdmin = viewMode === "admin";

    const modeKey = MODE_LABELS[state.mode] ? state.mode : "normal";
    const authorityKey = AUTHORITY_LABELS[state.authority] ? state.authority : "standalone_local";
    const authorityLabel = AUTHORITY_LABELS[authorityKey];
    const isFrozen = Boolean(state.frozen) || modeKey === "freeze";

    // Evaluate whether an active_override exists and is still unexpired.
    const ov = state.active_override && typeof state.active_override === "object"
        ? state.active_override
        : null;
    let overrideActive = false;
    let overrideExpired = false;
    let remainingMs = null;
    let countdownText = null;

    if (ov && state.restrictions === "off_scoped") {
        if (ov.expires_at) {
            const expMs = Date.parse(ov.expires_at);
            if (Number.isFinite(expMs)) {
                if (nowMs >= expMs) {
                    overrideExpired = true;
                    overrideActive = false;
                } else {
                    overrideActive = true;
                    remainingMs = expMs - nowMs;
                    countdownText = `${formatRemainingDuration(remainingMs)} remaining`;
                }
            }
        } else {
            overrideActive = true;
            countdownText = "Until manually revoked";
        }
    }

    // Precedence 1: FROZEN always wins.
    if (isFrozen) {
        const fi = state.freeze_info && typeof state.freeze_info === "object"
            ? state.freeze_info
            : {};
        const sync = summarizeDeviceSync(
            fi.acknowledged_devices,
            fi.pending_devices,
            fi.unreachable_devices,
            "frozen"
        );
        const initiator = fi.initiated_by ? `by ${fi.initiated_by}` : "by operator";
        const reason = fi.reason ? ` — ${fi.reason}` : "";
        // A surface that froze itself but could not confirm delivery to the
        // mesh reports freeze_confirmed: false. Only an explicit false counts;
        // hub-originated state never carries the field. Do not claim the
        // ecosystem is halted, and keep Freeze available as a retry.
        const freezeUnconfirmed = state.freeze_confirmed === false;
        // "Suspended" is only true if the mesh actually froze. With an
        // unconfirmed local freeze the override may still be in force
        // everywhere else, so say that instead.
        const overrideSuspended = overrideActive && !freezeUnconfirmed;
        const suspendedNote = !overrideActive
            ? ""
            : freezeUnconfirmed
                ? " · Scoped override may still be active on other devices"
                : " · Scoped override suspended while frozen";
        // The surface holding this freeze could not write it to disk (for
        // example a read-only config mount): it holds for now but would be
        // lost on restart. Operators need to know that before relying on it.
        const freezeNotDurable = state.freeze_durable === false;
        const durabilityNote = freezeNotDurable
            ? " · Not saved to disk — this freeze will be lost if the display restarts"
            : "";

        return {
            effectiveState: "frozen",
            severity: "critical",
            icon: "shield-octagon",
            badgeText: freezeUnconfirmed ? "FROZEN (LOCAL ONLY)" : "FROZEN",
            headline: freezeUnconfirmed
                ? "Freeze held on this display — mesh delivery not confirmed"
                : "Emergency Freeze Active — Mutating automations & commands halted",
            detailText: `Initiated ${initiator}${reason}${suspendedNote}${durabilityNote}`,
            modeLabel: MODE_LABELS.freeze,
            authorityKey,
            authorityLabel,
            countdownText: null,
            remainingMs: null,
            scopeText: ov ? summarizeScope(ov.scope) : null,
            deviceSync: sync,
            overrideSuspended,
            overrideExpired,
            freezeUnconfirmed,
            freezeNotDurable,
            viewMode,
            actions: {
                canFreeze: freezeUnconfirmed,
                canResume: isAdmin,
                canManageRestrictions: false,
                canRestoreRestrictions: isAdmin && overrideActive,
            },
        };
    }

    // Precedence 2: Scoped Restrictions Off (active & unexpired).
    if (overrideActive && ov) {
        const sync = summarizeDeviceSync(
            ov.applied_devices,
            ov.pending_devices,
            ov.unreachable_devices,
            "applied"
        );
        const scopeText = summarizeScope(ov.scope);
        return {
            effectiveState: "restrictions_off_scoped",
            severity: "warning",
            icon: "lock-open-clock",
            badgeText: "RESTRICTIONS: OFF (SCOPED)",
            headline: `${countdownText} · ${scopeText}`,
            detailText: `Authorized by ${ov.issued_by} (${ov.reason}) · Core safety invariants remain enforced`,
            modeLabel: MODE_LABELS[modeKey],
            authorityKey,
            authorityLabel,
            countdownText,
            remainingMs,
            scopeText,
            deviceSync: sync,
            overrideSuspended: false,
            overrideExpired: false,
            freezeUnconfirmed: false,
            freezeNotDurable: false,
            viewMode,
            actions: {
                canFreeze: true,
                canResume: false,
                canManageRestrictions: isAdmin,
                canRestoreRestrictions: isAdmin,
            },
        };
    }

    // Precedence 3: Restrictions On (default fail-closed posture).
    const expiryNotice = overrideExpired
        ? "Previous scoped override expired — restrictions automatically restored."
        : authorityKey === "lease_expired"
            ? "Hub lease expired — enforcing local fail-closed restrictions."
            : "All policy gates, approvals, and safety invariants enforced.";

    return {
        effectiveState: "restrictions_on",
        severity: authorityKey === "lease_expired" ? "warning" : "normal",
        icon: "lock-shield",
        badgeText: "RESTRICTIONS: ON",
        headline: `Mode: ${MODE_LABELS[modeKey]} · ${authorityLabel}`,
        detailText: expiryNotice,
        modeLabel: MODE_LABELS[modeKey],
        authorityKey,
        authorityLabel,
        countdownText: null,
        remainingMs: null,
        scopeText: null,
        deviceSync: summarizeDeviceSync([], [], []),
        overrideSuspended: false,
        overrideExpired,
        freezeUnconfirmed: false,
        freezeNotDurable: false,
        viewMode,
        actions: {
            canFreeze: true,
            canResume: false,
            canManageRestrictions: isAdmin,
            canRestoreRestrictions: false,
        },
    };
}

/**
 * Validate an operator's scoped restriction override submission.
 * Never permits global/unscoped "everything off" or missing step-up authentication.
 */
function validateOverrideForm(input = {}, nowMs = Date.now()) {
    const errors = [];
    const apps = Array.isArray(input.apps)
        ? input.apps.map((s) => String(s).trim()).filter(Boolean)
        : [];
    const devices = Array.isArray(input.devices)
        ? input.devices.map((s) => String(s).trim()).filter(Boolean)
        : [];
    const actionClasses = Array.isArray(input.actionClasses)
        ? input.actionClasses.map((s) => String(s).trim()).filter(Boolean)
        : [];

    if (apps.length === 0) {
        errors.push("Select at least one target application.");
    }
    if (devices.length === 0) {
        errors.push("Select at least one target device.");
    }
    if (actionClasses.length === 0) {
        errors.push("Select at least one action class to include in the override scope.");
    }

    const allowedActionIds = new Set(ACTION_CLASS_OPTIONS.map((a) => a.id));
    for (const ac of actionClasses) {
        if (!allowedActionIds.has(ac)) {
            errors.push(`Unsupported action class: ${ac}`);
        }
    }

    const durationPreset = DURATION_PRESETS.find((d) => d.id === (input.duration || "30m"));
    if (!durationPreset) {
        errors.push("Select a valid override duration.");
    } else if (durationPreset.id === "until_revoked" && input.confirmUntilRevoked !== true) {
        errors.push("Explicit confirmation is required for an 'Until manually revoked' override.");
    }

    const reason = String(input.reason || "").trim();
    if (reason.length < 8) {
        errors.push("Provide an audit reason of at least 8 characters.");
    }

    const stepUpMethod = input.stepUpMethod === "passkey" ? "passkey" : "totp";
    const credential = String(input.stepUpCredential || "").trim();
    if (stepUpMethod === "totp") {
        if (!/^\d{6,8}$/.test(credential)) {
            errors.push("Enter a valid 6-to-8 digit TOTP verification code.");
        }
    } else if (!credential || credential.length < 8) {
        errors.push("Complete Passkey (WebAuthn) verification before applying override.");
    }

    if (errors.length > 0) {
        return { valid: false, errors, payload: null };
    }

    const issuedAtIso = new Date(nowMs).toISOString().replace(/\.\d{3}Z$/, "Z");
    const expiresAtIso =
        durationPreset.seconds != null
            ? new Date(nowMs + durationPreset.seconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z")
            : null;

    return {
        valid: true,
        errors: [],
        payload: {
            scope: {
                apps,
                devices,
                action_classes: actionClasses,
            },
            duration_id: durationPreset.id,
            duration_seconds: durationPreset.seconds,
            issued_at: issuedAtIso,
            expires_at: expiresAtIso,
            reason,
            step_up: {
                method: stepUpMethod,
                credential,
            },
            bypassed: BYPASSED_GATES_DEFAULT.slice(),
            always_enforced: ALWAYS_ENFORCED_INVARIANTS.map((item) => item.id),
        },
    };
}

function computeFreezeButtonState(opts = {}) {
    const frozen = Boolean(opts.frozen);
    const viewMode = opts.viewMode === "ambient" ? "ambient" : "admin";
    const confirmTap = Boolean(opts.confirmTap);
    const armed = Boolean(opts.armed);

    if (frozen) {
        if (viewMode === "admin") {
            return {
                mode: "resume",
                icon: "play-shield",
                label: "Frozen · Resume...",
                ariaLabel: "Ecosystem is frozen. Activate to open step-up resume verification.",
                disabled: false,
                severity: "critical",
            };
        }
        return {
            mode: "frozen_ambient",
            icon: "shield-octagon",
            label: "Ecosystem Frozen",
            ariaLabel: "Ecosystem is frozen. Resume requires an authenticated administrator dashboard.",
            disabled: true,
            severity: "critical",
        };
    }

    if (confirmTap && armed) {
        return {
            mode: "armed",
            icon: "shield-octagon",
            label: "Tap Again to Freeze",
            ariaLabel: "Confirm Emergency Freeze: activate within 3 seconds to halt mutating actions.",
            disabled: false,
            severity: "critical",
        };
    }

    if (opts.retry) {
        return {
            mode: "retry",
            icon: "octagon-pause",
            label: "Retry Freeze",
            ariaLabel: "Retry Emergency Freeze: this display is frozen but the ecosystem did not confirm. Activate to send the freeze again.",
            disabled: false,
            severity: "danger",
        };
    }

    return {
        mode: "ready",
        icon: "octagon-pause",
        label: "Freeze",
        ariaLabel: "Emergency Freeze: immediately halt all mutating ecosystem automations and commands.",
        disabled: false,
        severity: "danger",
    };
}

const MIC_STATES = new Set([
    "muted",
    "push_to_talk",
    "listening",
    "processing",
    "unavailable",
]);

function computeMicPillState(opts = {}) {
    const rawState = MIC_STATES.has(opts.state) ? opts.state : "muted";
    const unavailableReason = String(opts.unavailableReason || "").trim();
    const backendLabel = String(opts.backendLabel || "Local Whisper").trim();

    if (rawState === "unavailable") {
        return {
            state: "unavailable",
            isMuted: true,
            canToggleMute: false,
            canPushToTalk: false,
            icon: "mic-off",
            statusLabel: unavailableReason || "Voice Unavailable",
            privacyCaption: `${backendLabel} · No audio retained`,
        };
    }

    if (rawState === "muted") {
        return {
            state: "muted",
            isMuted: true,
            canToggleMute: true,
            canPushToTalk: false,
            icon: "mic-off",
            statusLabel: "Mic Muted",
            privacyCaption: `${backendLabel} · No audio retained`,
        };
    }

    if (rawState === "listening") {
        return {
            state: "listening",
            isMuted: false,
            canToggleMute: true,
            canPushToTalk: true,
            icon: "mic-live",
            statusLabel: "Listening locally...",
            privacyCaption: `${backendLabel} · No audio retained`,
        };
    }

    if (rawState === "processing") {
        return {
            state: "processing",
            isMuted: false,
            canToggleMute: true,
            canPushToTalk: false,
            icon: "waveform",
            statusLabel: "Transcribing on-device...",
            privacyCaption: `${backendLabel} · No audio retained`,
        };
    }

    return {
        state: "push_to_talk",
        isMuted: false,
        canToggleMute: true,
        canPushToTalk: true,
        icon: "mic-ready",
        statusLabel: "Hold to Speak",
        privacyCaption: `${backendLabel} · No audio retained`,
    };
}

module.exports = {
    ALWAYS_ENFORCED_INVARIANTS,
    BYPASSED_GATES_DEFAULT,
    ACTION_CLASS_OPTIONS,
    DURATION_PRESETS,
    AUTHORITY_LABELS,
    MODE_LABELS,
    formatRemainingDuration,
    summarizeDeviceSync,
    summarizeScope,
    computeEffectivePolicyBanner,
    validateOverrideForm,
    computeFreezeButtonState,
    computeMicPillState,
};

