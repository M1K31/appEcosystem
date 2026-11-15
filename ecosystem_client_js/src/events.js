"use strict";

const http = require("http");
const https = require("https");
const { buildEventEnvelopeV2, verifyEventEnvelope } = require("./contracts");

class EventPublisher {
    constructor(config, mode, serviceName) {
        this.config = config;
        this.mode = mode;
        this.serviceName = serviceName;
        this._peerWebhooks = {};
    }

    setPeerWebhooks(webhooks) {
        this._peerWebhooks = webhooks || {};
    }

    async publish(eventType, data = {}, opts = {}) {
        if (this.mode === "standalone") {
            return { delivered: 0, failed: 0, mode: "standalone" };
        }
        const envelope = this._buildEnvelope(eventType, data, opts);
        if (this.mode === "registry") {
            return this._publishViaRegistry(envelope);
        }
        const matching = this._getMatchingPeers(eventType);
        let delivered = 0;
        for (const info of Object.values(matching)) {
            try {
                await this._deliverToPeer(envelope, info.webhook_url);
                delivered++;
            } catch {
                /* failed delivery */
            }
        }
        return {
            delivered,
            failed: Object.keys(matching).length - delivered,
            subscribers: Object.keys(matching),
        };
    }

    _buildEnvelope(eventType, data = {}, opts = {}) {
        return buildEventEnvelopeV2(
            eventType,
            this.serviceName,
            data,
            this.config.hmacSecret || "",
            opts
        );
    }

    static _sourceHeader(envelope) {
        const src = envelope && envelope.source;
        if (src && typeof src === "object") {
            return String(src.app || "");
        }
        return String(src || "");
    }

    async _publishViaRegistry(envelope) {
        const url = `${(this.config.registryUrl || "http://localhost:8500").replace(/\/+$/, "")}/events/publish`;
        try {
            return await this._postJson(url, envelope);
        } catch (err) {
            return { delivered: 0, failed: 1, error: String(err && err.message ? err.message : err) };
        }
    }

    _getMatchingPeers(eventType) {
        const matching = {};
        for (const [name, info] of Object.entries(this._peerWebhooks)) {
            for (const pattern of info.subscriptions || []) {
                if (
                    pattern === "*" ||
                    (pattern.endsWith(".*") && eventType.startsWith(pattern.slice(0, -2) + ".")) ||
                    pattern === eventType
                ) {
                    matching[name] = info;
                    break;
                }
            }
        }
        return matching;
    }

    async _deliverToPeer(envelope, webhookUrl) {
        await this._postJson(webhookUrl, envelope);
    }

    _postJson(targetUrl, envelope) {
        const body = JSON.stringify(envelope);
        return new Promise((resolve, reject) => {
            const parsed = new URL(targetUrl);
            const lib = parsed.protocol === "https:" ? https : http;
            const req = lib.request(
                {
                    hostname: parsed.hostname,
                    port: parsed.port,
                    path: parsed.pathname + parsed.search,
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Content-Length": Buffer.byteLength(body),
                        "X-Ecosystem-Signature": envelope.signature || "",
                        "X-Ecosystem-Event": envelope.type,
                        "X-Ecosystem-Source": EventPublisher._sourceHeader(envelope),
                    },
                    timeout: this.config.requestTimeout,
                },
                (res) => {
                    let raw = "";
                    res.on("data", (chunk) => {
                        raw += chunk;
                    });
                    res.on("end", () => {
                        if (res.statusCode >= 400) {
                            return reject(new Error(`HTTP ${res.statusCode}`));
                        }
                        try {
                            resolve(raw ? JSON.parse(raw) : {});
                        } catch {
                            resolve(raw);
                        }
                    });
                }
            );
            req.on("error", reject);
            req.on("timeout", () => {
                req.destroy();
                reject(new Error("timeout"));
            });
            req.write(body);
            req.end();
        });
    }
}

class EventSubscriber {
    constructor(hmacSecret) {
        this._hmacSecret = hmacSecret;
        this._handlers = {};
    }

    on(eventPattern, handler) {
        if (!this._handlers[eventPattern]) this._handlers[eventPattern] = [];
        this._handlers[eventPattern].push(handler);
    }

    async dispatch(envelope) {
        if (!verifyEventEnvelope(envelope, this._hmacSecret)) return false;

        for (const [pattern, handlers] of Object.entries(this._handlers)) {
            if (this._matches(envelope.type, pattern)) {
                for (const handler of handlers) {
                    try {
                        await handler(envelope);
                    } catch (e) {
                        console.error(`Handler error: ${e}`);
                    }
                }
            }
        }
        return true;
    }

    _matches(eventType, pattern) {
        if (pattern === "*") return true;
        if (pattern.endsWith(".*")) return eventType.startsWith(pattern.slice(0, -2) + ".");
        return eventType === pattern;
    }

    get subscriptions() {
        return Object.keys(this._handlers);
    }
}

module.exports = { EventPublisher, EventSubscriber };
