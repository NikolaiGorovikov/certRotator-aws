const fs = require("fs");
const path = require("path");

function validateConfig(config) {
    //
    // 1) Basic sanity check: Must be an object.
    //
    if (typeof config !== "object" || config === null) {
        throw new Error("Configuration must be a non-null object.");
    }

    //
    // 2) Check mandatory top-level fields:
    //    - vault
    //    - cert
    //    - tls
    //    - onreplace
    //    - onstart
    //    - intervals
    //
    const requiredTopLevelFields = ["vault", "cert", "tls", "onreplace", "onstart", "intervals"];
    requiredTopLevelFields.forEach((field) => {
        if (!Object.prototype.hasOwnProperty.call(config, field)) {
            throw new Error(`Missing mandatory top-level field '${field}'.`);
        }
    });

    //
    // 3) vault object checks
    //    Mandatory: pki_role, vault_role, pki_path, address
    //    Optional: version (if provided, must be "v1")
    //
    const { vault } = config;

    if (typeof vault !== "object" || vault === null) {
        throw new Error("'vault' must be an object.");
    }

    // version (optional but if present, must be "v1")
    if (Object.prototype.hasOwnProperty.call(vault, "version") && vault.version !== "v1") {
        throw new Error("If 'vault.version' is provided, it must be 'v1'.");
    }

    // pki_role (mandatory)
    if (!vault.pki_role || typeof vault.pki_role !== "string") {
        throw new Error("'vault.pki_role' is mandatory and must be a non-empty string.");
    }

    // vault_role (mandatory)
    if (!vault.vault_role || typeof vault.vault_role !== "string") {
        throw new Error("'vault.vault_role' is mandatory and must be a non-empty string.");
    }

    // pki_path (mandatory)
    if (!vault.pki_path || typeof vault.pki_path !== "string") {
        throw new Error("'vault.pki_path' is mandatory and must be a non-empty string.");
    }

    // address (mandatory) - format: domain(:port)?
    if (!vault.address || typeof vault.address !== "string") {
        throw new Error("'vault.address' is mandatory and must be a string (e.g. domain:port).");
    }
    // Optional port check
    // We'll do a light check: domain name or IP, optionally followed by :port
    const addressRegex = /^([a-zA-Z0-9.-]+)(?::(\d{1,5}))?$/;
    const match = vault.address.match(addressRegex);
    if (!match) {
        throw new Error(`'vault.address' must look like 'domain' or 'domain:port', got '${vault.address}'.`);
    }
    if (match[2]) {
        const portNum = Number(match[2]);
        if (portNum < 1 || portNum > 65535) {
            throw new Error(`'vault.address' port must be in range 1-65535, got ${portNum}.`);
        }
    }

    //
    // 4) cert object checks
    //    This can be empty, but it must be an object.
    //
    const { cert } = config;
    if (typeof cert !== "object" || cert === null) {
        throw new Error("'cert' must be an object (it can be empty, but not null).");
    }
    // If you want to enforce at least one property in cert, you could do it here.

    //
    // 5) tls object checks
    //    Must have: ca, cert, key
    //    cert and key must be the same file path (bundle).
    //    Check write permissions on cert/key (but not on CA).
    //
    const { tls } = config;
    if (typeof tls !== "object" || tls === null) {
        throw new Error("'tls' must be an object.");
    }
    ["ca", "cert", "key"].forEach((field) => {
        if (!tls[field] || typeof tls[field] !== "string") {
            throw new Error(`'tls.${field}' is mandatory and must be a non-empty string (path).`);
        }
    });

    // cert and key must point to the same file
    if (tls.cert !== tls.key) {
        throw new Error("'tls.cert' and 'tls.key' must point to the same file (a bundle).");
    }

    // Check write permissions to cert/key (but not CA)
    try {
        // fs.accessSync throws if no access
        fs.accessSync(path.resolve(tls.cert), fs.constants.W_OK);
    } catch (err) {
        throw new Error(`No write permission to 'tls.cert' (or 'tls.key') at: ${tls.cert}`);
    }

    //
    // 6) onreplace and onstart: arrays of objects
    //    Each object must have 'command' (string).
    //    'description' is optional.
    //    'onfail' is optional and can be "true" or an object.
    //        If an object, it can contain 'retry_every' (number in range 1000-1800000)
    //        and 'retry_num' (1-1000).
    //
    function validateHookArray(hookName) {
        const arr = config[hookName];
        if (!Array.isArray(arr)) {
            throw new Error(`'${hookName}' must be an array.`);
        }

        arr.forEach((item, index) => {
            if (typeof item !== "object" || item === null) {
                throw new Error(`Each element of '${hookName}' must be an object. Found invalid at index ${index}.`);
            }
            // command (mandatory)
            if (!item.command || typeof item.command !== "string") {
                throw new Error(`'${hookName}[${index}].command' is mandatory and must be a string.`);
            }
            // description (optional) - no checks besides type if present
            if (Object.prototype.hasOwnProperty.call(item, "description") && typeof item.description !== "string") {
                throw new Error(`'${hookName}[${index}].description' must be a string if provided.`);
            }
            // onfail (optional)
            if (Object.prototype.hasOwnProperty.call(item, "onfail")) {
                const val = item.onfail;
                if (val !== true && (typeof val !== "object" || val === null)) {
                    throw new Error(
                        `'${
                            hookName
                        }[${index}].onfail' must be either true or an object. Received type: ${typeof val}`
                    );
                }
                if (typeof val === "object") {
                    // If there's an object, check optional fields
                    if (Object.prototype.hasOwnProperty.call(val, "retry_every")) {
                        if (typeof val.retry_every !== "number") {
                            throw new Error(
                                `'${hookName}[${index}].onfail.retry_every' must be a number (milliseconds), e.g. 60000.`
                            );
                        }
                        if (val.retry_every < 1000 || val.retry_every > 1800000) {
                            throw new Error(
                                `'${hookName}[${index}].onfail.retry_every' must be in range [1000, 1800000]. Got ${val.retry_every}.`
                            );
                        }
                    }
                    if (Object.prototype.hasOwnProperty.call(val, "retry_num")) {
                        if (
                            typeof val.retry_num !== "number" ||
                            val.retry_num < 1 ||
                            val.retry_num > 1000
                        ) {
                            throw new Error(
                                `'${hookName}[${index}].onfail.retry_num' must be a number between 1 and 1000.`
                            );
                        }
                    }
                }
            }
        });
    }

    validateHookArray("onreplace");
    validateHookArray("onstart");

    //
    // 7) intervals object checks
    //    Must have: ok (0.01-0.45), error (0.01-0.3), default (>=0, no explicit upper bound given), buffer (0.05-0.8)
    //
    const { intervals } = config;
    if (typeof intervals !== "object" || intervals === null) {
        throw new Error("'intervals' must be an object.");
    }

    // Helper for numeric range check
    function checkRange(field, val, min, max, inclusive = true) {
        if (typeof val !== "number") {
            throw new Error(`'intervals.${field}' must be a number.`);
        }
        if (inclusive) {
            if (val < min || val > max) {
                throw new Error(
                    `'intervals.${field}' must be in range [${min}, ${max}]. Got ${val}.`
                );
            }
        } else {
            if (val <= min || val >= max) {
                throw new Error(
                    `'intervals.${field}' must be in range (${min}, ${max}). Got ${val}.`
                );
            }
        }
    }

    // ok: 0.01-0.45
    if (!Object.prototype.hasOwnProperty.call(intervals, "ok")) {
        throw new Error("Missing 'intervals.ok'.");
    }
    checkRange("ok", intervals.ok, 0.01, 0.45);

    // error: 0.01-0.3
    if (!Object.prototype.hasOwnProperty.call(intervals, "error")) {
        throw new Error("Missing 'intervals.error'.");
    }
    checkRange("error", intervals.error, 0.01, 0.3);

    // default: from 0 up (no upper bound given explicitly)
    if (!Object.prototype.hasOwnProperty.call(intervals, "default")) {
        throw new Error("Missing 'intervals.default'.");
    }
    if (typeof intervals.default !== "number" || intervals.default < 0) {
        throw new Error("'intervals.default' must be a number >= 0.");
    }

    // buffer: 0.05-0.8
    if (!Object.prototype.hasOwnProperty.call(intervals, "buffer")) {
        throw new Error("Missing 'intervals.buffer'.");
    }
    checkRange("buffer", intervals.buffer, 0.05, 0.8);

    //
    // If we reach here, we consider the config valid:
    //
    return true;
}

module.exports = validateConfig;