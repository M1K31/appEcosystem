"use strict";

/**
 * Phase 1 ecosystem event/command/notification/capability contracts and JSON Schema validation.
 * Mirrors Python ecosystem_client.contracts byte-for-byte.
 */
const fs = require("fs");
const path = require("path");
const { signPayload, verifySignature } = require("./_auth");
const { generateUlid, resolveDeviceId } = require("./ulid");

const SCHEMAS_DIR = path.resolve(__dirname, "../schemas");
const SCHEMA_CACHE = new Map();

class SchemaValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = "SchemaValidationError";
    }
}

const EventType = Object.freeze({
    // Security events (OpenEye, AegisSIEM, cyber-agents)
    SECURITY_ALERT: "security.alert",
    SECURITY_MOTION_DETECTED: "security.motion_detected",
    SECURITY_PERSON_DETECTED: "security.person_detected",
    SECURITY_INTRUSION: "security.intrusion",
    SECURITY_THREAT_BLOCKED: "security.threat_blocked",
    SECURITY_IOC_MATCH: "security.ioc_match",

    // System events (any project)
    SYSTEM_STARTUP: "system.startup",
    SYSTEM_SHUTDOWN: "system.shutdown",
    SYSTEM_HEALTH_CHANGED: "system.health_changed",
    SYSTEM_ERROR: "system.error",
    SYSTEM_CONFIG_CHANGED: "system.config_changed",

    // Network events (AegisSIEM)
    NETWORK_DEVICE_CONNECTED: "network.device_connected",
    NETWORK_DEVICE_DISCONNECTED: "network.device_disconnected",
    NETWORK_ANOMALY: "network.anomaly",
    NETWORK_BANDWIDTH_ALERT: "network.bandwidth_alert",

    // Display events (MagicMirror)
    DISPLAY_UPDATE: "display.update",
    DISPLAY_ALERT: "display.alert",
    DISPLAY_WIDGET_CHANGED: "display.widget_changed",

    // AI events (AI_For_Survival, ecosystem-ai)
    AI_ANALYSIS_COMPLETE: "ai.analysis_complete",
    AI_RECOMMENDATION: "ai.recommendation",
    AI_PLAYBOOK_TRIGGERED: "ai.playbook_triggered",

    // Ecosystem service & freeze lifecycle (registry / hub)
    ECOSYSTEM_SERVICE_REGISTERED: "ecosystem.service_registered",
    ECOSYSTEM_SERVICE_DEREGISTERED: "ecosystem.service_deregistered",
    ECOSYSTEM_SERVICE_UNHEALTHY: "ecosystem.service_unhealthy",
    ECOSYSTEM_AI_PROFILE_CHANGED: "ecosystem.ai_profile_changed",
    ECOSYSTEM_FREEZE_REQUESTED: "ecosystem.freeze_requested",
    ECOSYSTEM_FREEZE_APPLIED: "ecosystem.freeze_applied",
    ECOSYSTEM_RESUME_REQUESTED: "ecosystem.resume_requested",

    // Scanning lifecycle (Zero-Breach-Toolkit / scan_agent)
    SCAN_REQUESTED: "scan.requested",
    SCAN_STARTED: "scan.started",
    SCAN_PROGRESS: "scan.progress",
    SCAN_COMPLETED: "scan.completed",
    SCAN_FINDING: "scan.finding",
    SCAN_AUTHORIZATION_CHANGED: "scan.authorization_changed",

    // Policy, approvals & containment (ecosystem-policy / hub)
    POLICY_DECISION: "policy.decision",
    POLICY_MODE_CHANGED: "policy.mode_changed",
    POLICY_RESTRICTIONS_CHANGED: "policy.restrictions_changed",
    APPROVAL_REQUESTED: "approval.requested",
    APPROVAL_DECIDED: "approval.decided",
    CONTAINMENT_APPLIED: "containment.applied",
    CONTAINMENT_REVERTED: "containment.reverted",

    // Capabilities & automations
    CAPABILITY_REGISTERED: "capability.registered",
    CAPABILITY_WITHDRAWN: "capability.withdrawn",
    AUTOMATION_REQUESTED: "automation.requested",
    AUTOMATION_COMPLETED: "automation.completed",
    AUTOMATION_FAILED: "automation.failed",

    // Cross-device notifications (notify.*)
    NOTIFY_SECURITY: "notify.security",
    NOTIFY_SYSTEM: "notify.system",
    NOTIFY_SCAN: "notify.scan",
    NOTIFY_POLICY: "notify.policy",
    NOTIFY_APPROVAL: "notify.approval",
    NOTIFY_AUTOMATION: "notify.automation",

    // Compute broker & Model Forge
    COMPUTE_JOB_STARTED: "compute.job.started",
    COMPUTE_JOB_COMPLETED: "compute.job.completed",
    COMPUTE_JOB_FAILED: "compute.job.failed",
    MODEL_PUBLISHED: "model.published",

    // Device enrollment
    DEVICE_ENROLLED: "device.enrolled",
    DEVICE_UNENROLLED: "device.unenrolled",
});

function listSchemas() {
    if (!fs.existsSync(SCHEMAS_DIR)) return [];
    return fs
        .readdirSync(SCHEMAS_DIR)
        .filter((f) => f.endsWith(".schema.json"))
        .map((f) => f.slice(0, -".schema.json".length))
        .sort();
}

function loadSchema(name) {
    const key = name.endsWith(".schema.json")
        ? name.slice(0, -".schema.json".length)
        : name;
    if (SCHEMA_CACHE.has(key)) return SCHEMA_CACHE.get(key);
    const filePath = path.join(SCHEMAS_DIR, `${key}.schema.json`);
    if (!fs.existsSync(filePath)) {
        throw new Error(`Unknown ecosystem contract schema: ${JSON.stringify(name)}`);
    }
    const schema = JSON.parse(fs.readFileSync(filePath, "utf8"));
    SCHEMA_CACHE.set(key, schema);
    return schema;
}

function _matchesJsonType(value, expected) {
    if (expected === "null") return value === null;
    if (expected === "boolean") return typeof value === "boolean";
    if (expected === "integer") return typeof value === "number" && Number.isInteger(value);
    if (expected === "number") return typeof value === "number" && Number.isFinite(value);
    if (expected === "string") return typeof value === "string";
    if (expected === "object") return typeof value === "object" && value !== null && !Array.isArray(value);
    if (expected === "array") return Array.isArray(value);
    return true;
}

function _validateNode(value, schema, nodePath, errors) {
    if (schema.type !== undefined) {
        const allowed = Array.isArray(schema.type) ? schema.type : [schema.type];
        if (!allowed.some((t) => _matchesJsonType(value, t))) {
            errors.push(`${nodePath}: expected type [${allowed.join(", ")}], got ${value === null ? "null" : typeof value}`);
            return;
        }
    }

    if (value === null || value === undefined) return;

    if ("const" in schema && value !== schema.const) {
        errors.push(`${nodePath}: expected const ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}`);
    }

    if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
        errors.push(`${nodePath}: value ${JSON.stringify(value)} not in ${JSON.stringify(schema.enum)}`);
    }

    if (typeof value === "string") {
        if (schema.minLength !== undefined && value.length < Number(schema.minLength)) {
            errors.push(`${nodePath}: string shorter than minLength ${schema.minLength}`);
        }
        if (schema.pattern !== undefined && !new RegExp(schema.pattern).test(value)) {
            errors.push(`${nodePath}: ${JSON.stringify(value)} does not match pattern ${JSON.stringify(schema.pattern)}`);
        }
    }

    if (typeof value === "number") {
        if (schema.minimum !== undefined && value < Number(schema.minimum)) {
            errors.push(`${nodePath}: ${value} < minimum ${schema.minimum}`);
        }
    }

    if (Array.isArray(value)) {
        if (schema.minItems !== undefined && value.length < Number(schema.minItems)) {
            errors.push(`${nodePath}: array has fewer than ${schema.minItems} items`);
        }
        if (schema.items && typeof schema.items === "object") {
            value.forEach((item, idx) => {
                _validateNode(item, schema.items, `${nodePath}[${idx}]`, errors);
            });
        }
    }

    if (typeof value === "object" && !Array.isArray(value)) {
        for (const reqKey of schema.required || []) {
            if (!Object.prototype.hasOwnProperty.call(value, reqKey) || value[reqKey] === undefined) {
                errors.push(`${nodePath}: missing required property ${JSON.stringify(reqKey)}`);
            }
        }
        const props = schema.properties || {};
        if (schema.additionalProperties === false && Object.keys(props).length > 0) {
            for (const key of Object.keys(value)) {
                if (!Object.prototype.hasOwnProperty.call(props, key)) {
                    errors.push(`${nodePath}: unexpected property ${JSON.stringify(key)}`);
                }
            }
        }
        for (const [key, subschema] of Object.entries(props)) {
            if (Object.prototype.hasOwnProperty.call(value, key) && value[key] !== undefined && subschema && typeof subschema === "object") {
                _validateNode(value[key], subschema, `${nodePath}.${key}`, errors);
            }
        }
    }
}

function validateAgainstSchema(instance, schema) {
    const schemaObj = typeof schema === "string" ? loadSchema(schema) : schema;
    const errors = [];
    _validateNode(instance, schemaObj, "$", errors);
    return errors;
}

function assertValidSchema(instance, schema) {
    const errors = validateAgainstSchema(instance, schema);
    if (errors.length > 0) {
        throw new SchemaValidationError(errors.join("; "));
    }
}

function canonicalSignableEvent(envelope) {
    const version = envelope && envelope.schema_version;
    if (typeof version === "number" && Number.isInteger(version) && version >= 2) {
        const src = envelope.source;
        let srcObj;
        if (typeof src === "string") {
            srcObj = { app: src, device_id: resolveDeviceId() };
        } else if (src && typeof src === "object") {
            srcObj = {
                app: String(src.app || ""),
                device_id: String(src.device_id || ""),
            };
        } else {
            srcObj = { app: "", device_id: "" };
        }
        const signable = {
            schema_version: version,
            id: envelope.id || "",
            type: envelope.type || "",
            source: srcObj,
            timestamp: envelope.timestamp == null ? 0 : envelope.timestamp,
            data: envelope.data || {},
        };
        if (envelope.correlation_id !== undefined && envelope.correlation_id !== null) {
            signable.correlation_id = envelope.correlation_id;
        }
        return signable;
    }

    // Legacy v1 envelope (5-field layout)
    const rawSrc = envelope ? envelope.source : "";
    const v1Source = rawSrc && typeof rawSrc === "object" ? String(rawSrc.app || "") : String(rawSrc || "");
    return {
        id: (envelope && envelope.id) || "",
        type: (envelope && envelope.type) || "",
        source: v1Source,
        timestamp: envelope && envelope.timestamp != null ? envelope.timestamp : 0,
        data: (envelope && envelope.data) || {},
    };
}

function buildEventEnvelopeV2(eventType, sourceApp, data = {}, secret = "", opts = {}) {
    const envelope = {
        schema_version: 2,
        id: opts.eventId || generateUlid(),
        type: eventType,
        source: {
            app: sourceApp,
            device_id: opts.deviceId || resolveDeviceId(),
        },
        timestamp: opts.timestamp == null ? Date.now() / 1000 : Number(opts.timestamp),
        data: Object.assign({}, data || {}),
    };
    if (opts.correlationId !== undefined && opts.correlationId !== null) {
        envelope.correlation_id = opts.correlationId;
    }
    envelope.signature = signPayload(canonicalSignableEvent(envelope), secret);
    return envelope;
}

function verifyEventEnvelope(envelope, secret) {
    if (!envelope || typeof envelope !== "object") return false;
    const signature = envelope.signature;
    if (!signature || typeof signature !== "string") return false;
    return verifySignature(canonicalSignableEvent(envelope), signature, secret);
}

function canonicalSignableCommand(envelope) {
    const out = {};
    for (const [k, v] of Object.entries(envelope || {})) {
        if (k === "signature") continue;
        out[k] = v;
    }
    return out;
}

function buildCommandEnvelope(command, actionClass, actor, target, secret, opts = {}) {
    const authRef = opts.authorizationRef !== undefined ? opts.authorizationRef : null;
    if (authRef && (String(authRef).startsWith("notify:") || String(authRef).startsWith("notify."))) {
        throw new Error("A notification identifier is never a valid command authorization_ref");
    }

    const cid = opts.commandId || generateUlid();
    const nowTs = opts.issuedAt == null ? Date.now() / 1000 : Number(opts.issuedAt);
    const ttlSeconds = opts.ttlSeconds == null ? 60.0 : Number(opts.ttlSeconds);
    const envelope = {
        schema_version: 1,
        id: cid,
        command,
        action_class: actionClass,
        actor: Object.assign({}, actor),
        target: Object.assign({}, target),
        parameters: Object.assign({}, opts.parameters || {}),
        issued_at: nowTs,
        expires_at: nowTs + ttlSeconds,
        correlation_id: opts.correlationId || cid,
        idempotency_key: opts.idempotencyKey || cid,
        authorization_ref: authRef,
        rationale: opts.rationale !== undefined ? opts.rationale : null,
        ack_required: opts.ackRequired === undefined ? true : Boolean(opts.ackRequired),
    };
    envelope.signature = signPayload(canonicalSignableCommand(envelope), secret);
    assertValidSchema(envelope, "command-envelope.v1");
    return envelope;
}

function verifyCommandEnvelope(envelope, secret, opts = {}) {
    const errors = validateAgainstSchema(envelope, "command-envelope.v1");
    if (errors.length > 0) {
        return { valid: false, reason: `schema invalid: ${errors[0]}` };
    }
    const authRef = envelope.authorization_ref;
    if (authRef && (String(authRef).startsWith("notify:") || String(authRef).startsWith("notify."))) {
        return { valid: false, reason: "notification reference cannot authorize a command" };
    }
    const current = opts.now == null ? Date.now() / 1000 : Number(opts.now);
    const issuedAt = Number(envelope.issued_at);
    const expiresAt = Number(envelope.expires_at);
    if (expiresAt <= issuedAt) {
        return { valid: false, reason: "expires_at must be greater than issued_at" };
    }
    if (current > expiresAt) {
        return { valid: false, reason: "command expired" };
    }
    if (!verifySignature(canonicalSignableCommand(envelope), envelope.signature || "", secret)) {
        return { valid: false, reason: "invalid command signature" };
    }
    return { valid: true, reason: "ok" };
}

function buildNotificationEnvelope(notifyType, sourceApp, severity, title, body, opts = {}) {
    if (!opts.dedupeKey) {
        throw new Error("dedupeKey is required for NotificationEnvelope");
    }
    const envelope = {
        schema_version: 1,
        type: notifyType,
        id: opts.notificationId || generateUlid(),
        dedupe_key: opts.dedupeKey,
        source: {
            app: sourceApp,
            device_id: opts.deviceId || resolveDeviceId(),
        },
        severity,
        title,
        body: body || "",
        actions: Array.isArray(opts.actions) ? opts.actions.slice() : [],
        privacy: opts.privacy || "redacted",
        ttl: opts.ttl || "24h",
        deep_link: opts.deepLink !== undefined ? opts.deepLink : null,
        created_at:
            opts.createdAt ||
            new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    };
    if (opts.secret) {
        const signable = Object.assign({}, envelope);
        envelope.signature = signPayload(signable, opts.secret);
    }
    assertValidSchema(envelope, "notification-envelope.v1");
    return envelope;
}

module.exports = {
    SchemaValidationError,
    EventType,
    listSchemas,
    loadSchema,
    validateAgainstSchema,
    assertValidSchema,
    canonicalSignableEvent,
    buildEventEnvelopeV2,
    verifyEventEnvelope,
    canonicalSignableCommand,
    buildCommandEnvelope,
    verifyCommandEnvelope,
    buildNotificationEnvelope,
};

