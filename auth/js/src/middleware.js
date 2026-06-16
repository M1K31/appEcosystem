/**
 * Express middleware for ecosystem authentication.
 * Mirrors the Python FastAPI middleware.
 */

const {
  verifyEcosystemToken,
  verifyRequest,
  NonceStore,
  SIGNATURE_HEADER,
  TIMESTAMP_HEADER,
  NONCE_HEADER,
} = require("./tokens");

// Insecure development default. Mirrors Python's DEFAULT_DEV_SECRET.
const DEFAULT_DEV_SECRET = "dev-ecosystem-secret-change-in-production";

// Process-wide nonce cache for replay detection on the signature path.
const _nonceStore = new NonceStore();

/**
 * Get the shared HMAC secret from environment.
 *
 * Fails closed: if the resolved secret is the known development default and
 * ECOSYSTEM_ENV is anything other than "dev", an error is thrown rather than
 * silently trusting a public key.
 * @returns {string}
 */
function getEcosystemSecret() {
  const secret = process.env.ECOSYSTEM_HMAC_SECRET || DEFAULT_DEV_SECRET;
  if (secret === DEFAULT_DEV_SECRET && (process.env.ECOSYSTEM_ENV || "dev") !== "dev") {
    throw new Error(
      "Refusing to start: ECOSYSTEM_HMAC_SECRET is unset or set to the insecure default."
    );
  }
  return secret;
}

/**
 * Express middleware that validates ecosystem HMAC-signed requests.
 *
 * Checks X-Ecosystem-Signature header against JSON body,
 * or validates a Bearer token from the Authorization header.
 *
 * On success, sets req.ecosystemAuth with auth details.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function requireEcosystemAuth(req, res, next) {
  const secret = getEcosystemSecret();

  // Check HMAC signature header (replay-resistant request scheme).
  const signature = req.headers[SIGNATURE_HEADER.toLowerCase()];
  if (signature) {
    const timestamp = req.headers[TIMESTAMP_HEADER.toLowerCase()];
    const nonce = req.headers[NONCE_HEADER.toLowerCase()];
    const fullUrl = req.protocol + "://" + req.get("host") + req.originalUrl;

    const isBodyless = req.method === "GET" || req.method === "DELETE";
    const body = isBodyless ? {} : (req.body && typeof req.body === "object" ? req.body : {});

    if (
      !verifyRequest(req.method, fullUrl, secret, signature, timestamp, nonce, body, 300, _nonceStore)
    ) {
      return res
        .status(401)
        .json({ detail: "Invalid, stale, or replayed ecosystem signature" });
    }
    req.ecosystemAuth = { auth_method: "hmac", payload: body };
    return next();
  }

  // Check Bearer token (for service-to-service calls)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const tokenStr = authHeader.slice(7);
    let tokenData;
    try {
      tokenData = JSON.parse(tokenStr);
    } catch {
      return res.status(401).json({ detail: "Invalid token format" });
    }
    if (!verifyEcosystemToken(tokenData, secret)) {
      return res.status(401).json({ detail: "Invalid or expired ecosystem token" });
    }
    req.ecosystemAuth = { auth_method: "token", service: tokenData.service };
    return next();
  }

  return res.status(401).json({ detail: "Missing ecosystem authentication" });
}

module.exports = { requireEcosystemAuth, getEcosystemSecret };
