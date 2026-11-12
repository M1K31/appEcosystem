"use strict";

/**
 * Node.js HubClient for MagicMirror-Custom and JS services:
 * joins an existing appEcosystem Hub (or operates standalone when offline),
 * registers/resolves capability manifests, and publishes deduplicated
 * `notify.*` envelopes with a local file-backed offline outbox.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const { signRequest } = require("./_auth");
const { assertValidSchema, buildNotificationEnvelope } = require("./contracts");
const { generateUlid, resolveDeviceId } = require("./ulid");

function defaultJsOutboxPath(appName) {
    const safe = String(appName || "js-app").replace(/[^A-Za-z0-9_-]/g, "_");
    const base =
        process.env.ECOSYSTEM_OUTBOX_DIR ||
        path.join(os.homedir(), ".local", "share", "ecosystem");
    return path.join(base, `outbox-${safe}.json`);
}

class HubClient {
    constructor(appName, opts = {}) {
        this.appName = appName;
        this.deviceId = opts.deviceId || resolveDeviceId();
        this.registryUrl = (opts.registryUrl || process.env.ECOSYSTEM_REGISTRY_URL || "http://localhost:8500").replace(/\/+$/, "");
        this.secret = opts.secret !== undefined ? opts.secret : (process.env.ECOSYSTEM_HMAC_SECRET || "");
        this.role = String(opts.role || process.env.ECOSYSTEM_HUB_ROLE || "join").toLowerCase();
        this.timeout = opts.timeout || 5000;
        this.outboxPath = opts.outboxPath || defaultJsOutboxPath(appName);
        this.maxOutboxItems = opts.maxOutboxItems || 250;

        this._capabilities = new Map();
        for (const cap of opts.capabilities || []) {
            this._storeLocalCapability(cap);
        }
        this._joined = false;
    }

    get isJoined() {
        return this._joined;
    }

    _headers(method, url, body = null) {
        const base = body !== null ? { "Content-Type": "application/json" } : {};
        if (!this.secret) return base;
        return Object.assign(base, signRequest(method, url, this.secret, body));
    }

    _normalizeManifest(partial) {
        const m = Object.assign({ schema_version: 1 }, partial);
        if (!m.provider) {
            m.provider = { app: this.appName, device_id: this.deviceId };
        }
        assertValidSchema(m, "capability-manifest.v1");
        return m;
    }

    _storeLocalCapability(partial) {
        const m = this._normalizeManifest(partial);
        this._capabilities.set(m.capability, m);
        return m;
    }

    async checkHealth() {
        if (this.role === "off") return false;
        try {
            const resp = await fetch(`${this.registryUrl}/health`, {
                method: "GET",
                signal: AbortSignal.timeout(this.timeout),
            });
            return Boolean(resp && resp.ok);
        } catch {
            return false;
        }
    }

    async start() {
        if (this.role === "off") {
            this._joined = false;
            return "standalone";
        }
        const ok = await this.checkHealth();
        if (!ok) {
            this._joined = false;
            return "standalone";
        }
        this._joined = true;
        await this.syncCapabilities();
        await this.flushOutbox();
        return "joined";
    }

    async stop() {
        if (this._joined) {
            const url = `${this.registryUrl}/capabilities/${encodeURIComponent(this.appName)}`;
            try {
                await fetch(url, {
                    method: "DELETE",
                    headers: this._headers("DELETE", url, null),
                    signal: AbortSignal.timeout(2500),
                });
            } catch {
                // Best-effort withdrawal
            }
        }
        this._joined = false;
    }

    async getPolicyState() {
        if (!this._joined) return null;
        try {
            const url = `${this.registryUrl}/policy/state`;
            const resp = await fetch(url, {
                method: "GET",
                headers: this._headers("GET", url, null),
                signal: AbortSignal.timeout(this.timeout),
            });
            if (resp && resp.ok) {
                return await resp.json();
            }
        } catch {
            return null;
        }
        return null;
    }

    async requestFreeze(reason = "Emergency freeze", channel = "js_client") {
        const payload = {
            initiated_by: `${this.appName}/${this.deviceId}`,
            channel: channel,
            reason: reason,
        };
        if (!this._joined) return null;
        try {
            const url = `${this.registryUrl}/policy/freeze`;
            const resp = await fetch(url, {
                method: "POST",
                headers: this._headers("POST", url, payload),
                body: JSON.stringify(payload),
                signal: AbortSignal.timeout(this.timeout),
            });
            if (resp && resp.ok) {
                return await resp.json();
            }
        } catch {
            return null;
        }
        return null;
    }

    /**
     * Ask the hub to run a capability and return its status document.
     *
     * The hub decides (policy, approval) and forwards to the provider; `status`
     * is one of completed, accepted, pending_approval, denied, failed or
     * provider_unavailable. Nothing is ever queued: if the hub cannot be
     * reached the answer is provider_unavailable. To retry safely after an
     * unknown outcome, pass the same `idempotencyKey`.
     *
     * opts: rationale, idempotencyKey, actorType, actorId, correlationId,
     *       context, stepUpToken, timeoutMs
     */
    async invoke(capability, target, parameters = {}, opts = {}) {
        if (!this.secret) {
            return { status: "provider_unavailable", error: "not_configured", command_id: null };
        }
        const key = opts.idempotencyKey || generateUlid();
        const body = {
            capability,
            target: Object.assign({}, target || {}),
            parameters: Object.assign({}, parameters || {}),
            actor: {
                app: this.appName,
                id: opts.actorId || this.appName,
                type: opts.actorType || "service",
                device_id: this.deviceId,
            },
            idempotency_key: key,
        };
        if (opts.rationale != null) body.rationale = opts.rationale;
        if (opts.correlationId != null) body.correlation_id = opts.correlationId;
        if (opts.context != null) body.context = opts.context;
        if (opts.stepUpToken != null) body.step_up_token = opts.stepUpToken;

        const url = `${this.registryUrl}/commands/dispatch`;
        let resp;
        try {
            resp = await fetch(url, {
                method: "POST",
                headers: this._headers("POST", url, body),
                body: JSON.stringify(body),
                signal: AbortSignal.timeout(opts.timeoutMs || 60000),
            });
        } catch (err) {
            if (HubClient._neverConnected(err)) {
                return { status: "provider_unavailable", error: "hub_unreachable", command_id: null };
            }
            // Sent, but no answer: it may or may not have run.
            return {
                status: "failed",
                error: `no answer from the hub (${(err && err.name) || "Error"})`,
                outcome_unknown: true,
                command_id: null,
                idempotency_key: key,
            };
        }

        let payload = null;
        try {
            payload = await resp.json();
        } catch {
            payload = null;
        }
        const isObject = payload !== null && typeof payload === "object" && !Array.isArray(payload);
        if (resp.status === 200 && isObject) {
            return payload;
        }
        const out = {
            status: "failed",
            error: isObject && payload.detail ? String(payload.detail) : `hub answered HTTP ${resp.status}`,
            http_status: resp.status,
            command_id: null,
            idempotency_key: key,
        };
        if (resp.status >= 500 || resp.status === 200) {
            out.outcome_unknown = true;
        }
        return out;
    }

    /** True when the request never reached the hub (as opposed to: sent, no answer). */
    static _neverConnected(err) {
        const codes = ["ECONNREFUSED", "ENOTFOUND", "EHOSTUNREACH", "ENETUNREACH", "EAI_AGAIN", "UND_ERR_CONNECT_TIMEOUT"];
        const code = err && ((err.cause && err.cause.code) || err.code);
        if (code && codes.includes(code)) return true;
        const message = String((err && err.message) || "");
        return codes.some((c) => message.includes(c));
    }

    /** The hub's record of a command (status, result, audit events), or null. */
    async getCommand(commandId) {
        try {
            const url = `${this.registryUrl}/commands/${encodeURIComponent(commandId)}`;
            const resp = await fetch(url, {
                method: "GET",
                headers: this._headers("GET", url, null),
                signal: AbortSignal.timeout(this.timeout),
            });
            if (resp && resp.ok) {
                return await resp.json();
            }
        } catch {
            return null;
        }
        return null;
    }

    async registerCapability(partial) {
        const manifest = this._storeLocalCapability(partial);
        if (this._joined) {
            await this.syncCapabilities();
        }
        return manifest;
    }

    async syncCapabilities() {
        const list = [...this._capabilities.values()];
        if (list.length === 0) return true;
        const url = `${this.registryUrl}/capabilities/register`;
        const body = { capabilities: list };
        try {
            const resp = await fetch(url, {
                method: "POST",
                headers: this._headers("POST", url, body),
                body: JSON.stringify(body),
                signal: AbortSignal.timeout(this.timeout),
            });
            return Boolean(resp && resp.ok);
        } catch {
            return false;
        }
    }

    async resolveCapability(capabilityName) {
        if (this._joined) {
            const url = `${this.registryUrl}/capabilities?capability=${encodeURIComponent(capabilityName)}&resolve=true`;
            try {
                const resp = await fetch(url, {
                    method: "GET",
                    headers: this._headers("GET", url, null),
                    signal: AbortSignal.timeout(this.timeout),
                });
                if (resp && resp.ok) {
                    return await resp.json();
                }
            } catch {
                // Fall back to local capabilities
            }
        }
        if (this._capabilities.has(capabilityName)) {
            const m = this._capabilities.get(capabilityName);
            return {
                capability: capabilityName,
                available: true,
                providers: [{ capability: capabilityName, app: this.appName, device_id: this.deviceId, manifest: m }],
                unavailable_reason: null,
            };
        }
        return {
            capability: capabilityName,
            available: false,
            providers: [],
            unavailable_reason: `Hub unreachable and capability '${capabilityName}' is not hosted locally`,
        };
    }

    _readOutbox() {
        try {
            if (!fs.existsSync(this.outboxPath)) return [];
            const parsed = JSON.parse(fs.readFileSync(this.outboxPath, "utf8"));
            return Array.isArray(parsed) ? parsed : [];
        } catch {
            return [];
        }
    }

    _writeOutbox(items) {
        fs.mkdirSync(path.dirname(this.outboxPath), { recursive: true });
        const bounded = items.slice(-this.maxOutboxItems);
        fs.writeFileSync(this.outboxPath, JSON.stringify(bounded, null, 2), { mode: 0o600 });
    }

    _enqueueOffline(envelope) {
        const items = this._readOutbox();
        if (items.some((e) => e.dedupe_key === envelope.dedupe_key)) {
            return false;
        }
        items.push(envelope);
        this._writeOutbox(items);
        return true;
    }

    async _sendNotification(envelope) {
        const url = `${this.registryUrl}/notifications/publish`;
        const resp = await fetch(url, {
            method: "POST",
            headers: this._headers("POST", url, envelope),
            body: JSON.stringify(envelope),
            signal: AbortSignal.timeout(this.timeout),
        });
        return Boolean(resp && resp.ok);
    }

    async notify(notifyType, severity, title, body, opts = {}) {
        const envelope = buildNotificationEnvelope(
            notifyType,
            this.appName,
            severity,
            title,
            body,
            Object.assign({ deviceId: this.deviceId, secret: this.secret || undefined }, opts)
        );
        if (this._joined) {
            try {
                if (await this._sendNotification(envelope)) {
                    return { status: "delivered", id: envelope.id };
                }
            } catch {
                // Fall through to offline outbox
            }
        }
        const added = this._enqueueOffline(envelope);
        return {
            status: added ? "queued_offline" : "deduplicated_offline",
            id: envelope.id,
        };
    }

    async flushOutbox() {
        const items = this._readOutbox();
        if (items.length === 0) return { delivered: 0, remaining: 0 };
        const remaining = [];
        let delivered = 0;
        let failed = false;
        for (const env of items) {
            if (failed) {
                remaining.push(env);
                continue;
            }
            try {
                if (await this._sendNotification(env)) {
                    delivered += 1;
                } else {
                    failed = true;
                    remaining.push(env);
                }
            } catch {
                failed = true;
                remaining.push(env);
            }
        }
        this._writeOutbox(remaining);
        return { delivered, remaining: remaining.length };
    }

    async fetchRecentNotifications(opts = {}) {
        const limit = opts.limit || 25;
        const minSeverity = opts.minSeverity ? `&min_severity=${encodeURIComponent(opts.minSeverity)}` : "";
        const url = `${this.registryUrl}/notifications/recent?limit=${encodeURIComponent(limit)}${minSeverity}`;
        try {
            const resp = await fetch(url, {
                method: "GET",
                headers: this._headers("GET", url, null),
                signal: AbortSignal.timeout(this.timeout),
            });
            if (!resp || !resp.ok) return [];
            const data = await resp.json();
            return Array.isArray(data.notifications) ? data.notifications : [];
        } catch {
            return [];
        }
    }
}

module.exports = { HubClient, defaultJsOutboxPath };

