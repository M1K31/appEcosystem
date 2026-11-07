"use strict";

/**
 * Zero-dependency Crockford Base32 monotonic ULID generator and device ID helper.
 * Mirrors Python ecosystem_client.ulid byte-for-byte.
 */
const crypto = require("crypto");
const os = require("os");

const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CROCKFORD_MAP = Object.freeze(
    Object.fromEntries([...CROCKFORD_ALPHABET].map((ch, idx) => [ch, idx]))
);
const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const MAX_TIME_MS = (1n << 48n) - 1n;
const MAX_ENTROPY = (1n << 80n) - 1n;

let _lastMs = -1n;
let _lastEntropy = 0n;

function _encodeBase32(valueBigInt, length) {
    const chars = new Array(length);
    let v = valueBigInt;
    for (let idx = length - 1; idx >= 0; idx -= 1) {
        chars[idx] = CROCKFORD_ALPHABET[Number(v & 0x1fn)];
        v >>= 5n;
    }
    return chars.join("");
}

function _randomEntropy80() {
    const buf = crypto.randomBytes(10);
    let val = 0n;
    for (let i = 0; i < 10; i += 1) {
        val = (val << 8n) | BigInt(buf[i]);
    }
    return val;
}

/**
 * Generate a 26-character lexicographically sortable Crockford Base32 ULID.
 * Monotonically increments the 80-bit random payload within the same millisecond.
 * @param {number|bigint|null} [timestampMs]
 * @returns {string}
 */
function generateUlid(timestampMs = null) {
    let nowMs = timestampMs == null ? BigInt(Date.now()) : BigInt(Math.trunc(Number(timestampMs)));
    if (nowMs < 0n || nowMs > MAX_TIME_MS) {
        throw new RangeError(`ULID timestampMs out of 48-bit range: ${nowMs}`);
    }

    let entropy;
    if (timestampMs == null && nowMs === _lastMs) {
        entropy = _lastEntropy + 1n;
        if (entropy > MAX_ENTROPY) {
            nowMs += 1n;
            entropy = _randomEntropy80();
        }
    } else {
        entropy = _randomEntropy80();
    }
    _lastMs = nowMs;
    _lastEntropy = entropy;

    return _encodeBase32(nowMs, 10) + _encodeBase32(entropy, 16);
}

/**
 * Return true if value is a canonical 26-char uppercase Crockford Base32 ULID.
 * @param {*} value
 * @returns {boolean}
 */
function isUlid(value) {
    if (typeof value !== "string" || !ULID_RE.test(value)) {
        return false;
    }
    return CROCKFORD_MAP[value[0]] <= 7;
}

/**
 * Extract the 48-bit Unix millisecond timestamp from a valid ULID.
 * @param {string} ulidStr
 * @returns {number}
 */
function ulidTimestampMs(ulidStr) {
    if (!isUlid(ulidStr)) {
        throw new Error(`Invalid ULID: ${JSON.stringify(ulidStr)}`);
    }
    let ts = 0n;
    for (let i = 0; i < 10; i += 1) {
        ts = (ts << 5n) | BigInt(CROCKFORD_MAP[ulidStr[i]]);
    }
    return Number(ts);
}

/**
 * Resolve the local device identifier for event/command source metadata.
 * @returns {string}
 */
function resolveDeviceId() {
    const envId = (process.env.ECOSYSTEM_DEVICE_ID || "").trim();
    if (envId) return envId;
    try {
        const host = (os.hostname() || "").trim();
        if (host) return host;
    } catch {
        // Ignore hostname lookup errors
    }
    return "local-device";
}

module.exports = {
    CROCKFORD_ALPHABET,
    generateUlid,
    isUlid,
    ulidTimestampMs,
    resolveDeviceId,
};

