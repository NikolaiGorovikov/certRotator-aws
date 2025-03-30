const aws = require("aws-ahh-sdk");
const { spawn } = require('child_process');
const logger = require("./logger");
const fs = require("fs");

/**
 * Runs a shell command asynchronously.
 * @param {string} fullCommand - The full shell command to run.
 * @returns {Promise<void>} Resolves when the command finishes successfully.
 * @throws If the process exits with a non-zero code.
 */
async function runCommand(fullCommand) {
    return new Promise((resolve, reject) => {
        const child = spawn(fullCommand, { shell: true, stdio: 'inherit' });

        child.on('error', (err) => {
            reject(new Error(`Failed to start command: ${err.message}`));
        });

        child.on('close', (code) => {
            if (code === 0) {
                resolve();
            } else {
                reject(new Error(`Command exited with code ${code}`));
            }
        });
    });
}

/**
 * Fetches a certificate from the vault.
 * @param {object} config - The configuration object.
 * @returns {Promise<object>} The certificate data.
 */
async function fetchCertificate(config) {
    logger.info("Fetching certificate from vault...");
    const certData = await aws.vaultCert({
        requestBody: config.cert,
        ...config.vault
    });
    logger.info("Certificate fetch successful!");
    return certData;
}

/**
 * Writes the certificate and private key to a file.
 * @param {object} certData - The certificate data object.
 * @param {object} config - The configuration object (for file paths).
 */
function writeCertificateToFile(certData, config) {
    logger.info(`Writing certificate to file: ${config.tls.cert}`);
    fs.writeFileSync(config.tls.cert, certData.certificate + "\n" + certData.private_key);
    logger.info("File write successful!");
}

/**
 * Runs a list of commands sequentially.
 * If any command fails, it throws an error.
 * @param {string[]} commands - Array of shell commands to run.
 * @param {string} errorMessage - Custom error message used in logs.
 */
async function runCommandsSafely(commands, errorMessage) {
    if (!commands || commands.length === 0) {
        logger.info("No commands to run.");
        return;
    }
    logger.info(`Running ${commands.length} command(s)...`);
    for (let command of commands) {
        try {
            await runCommand(command);
            logger.info(`Command "${command}" ran successfully.`);
        } catch (error) {
            logger.error(`${errorMessage}\n  -> Failed command: "${command}"\n  -> ${error.message}`);
            throw error;
        }
    }
    logger.info("All commands executed successfully.");
}

/**
 * Schedules the next run of the main function.
 * @param {number} delay - Delay in ms for when to call main again.
 * @param {object} current - The current state object.
 * @param {object} config - The config object.
 */
function scheduleNextStatusTransition(delay, current, config) {
    logger.info(`Scheduling next check in ${Math.round(delay / 1000)} seconds.`);
    setTimeout(() => main(current, config), delay);
}

/**
 * Main function managing certificate state machine.
 * @param {object} current - Holds the current status, active_cert, etc.
 * @param {object} config - Configuration object with intervals, file paths, etc.
 */
async function main(current, config) {
    logger.info(`Entering main function with status: "${current.status}"`);

    switch (current.status) {
        case 'start':
            await handleStart(current, config);
            break;

        case 'ok':
            await handleOk(current, config);
            break;

        case 'error':
            await handleError(current, config);
            break;

        default:
            logger.error(`Unknown status: "${current.status}". Aborting.`);
            throw new Error(`Unknown status: ${current.status}`);
    }
}

/**
 * Handle logic when status is "start".
 * @param {object} current
 * @param {object} config
 */
async function handleStart(current, config) {
    logger.info("Status is 'start'. Attempting to obtain the first certificate...");

    const retryTime = config.intervals.default;
    let certData;

    try {
        certData = await fetchCertificate(config);
    } catch (e) {
        logger.error("The initial certificate was not obtained. Likely configuration error.");
        logger.info(`Retrying in ${Math.round(retryTime / 1000)} seconds.`);
        return scheduleNextStatusTransition(retryTime, current, config);
    }

    current.active_cert = certData;
    current.second_cert = null;

    // Write the first certificate to file.
    try {
        writeCertificateToFile(certData, config);
    } catch (e) {
        logger.error("Couldn't write the initial certificate to file. Check permissions.");
        logger.info(`Will retry in ${Math.round(retryTime / 1000)} seconds.`);
        return scheduleNextStatusTransition(retryTime, current, config);
    }

    // Run onstart commands
    try {
        logger.info("Running 'onstart' commands...");
        await runCommandsSafely(config.onstart, "Fatal error running 'onstart' commands.");
    } catch (e) {
        // Fatal error, cannot proceed
        throw e;
    }

    // Calculate TTL for scheduling
    const ttl = certData.expiration * 1000 - Date.now();
    if (!ttl || ttl <= 0) {
        logger.error("Unknown or invalid certificate expiration time.");
        throw new Error("Can't proceed, unknown/invalid expiration time.");
    }

    certData.ttl = ttl;
    const time = config.intervals.ok * ttl;
    logger.info(`Certificate obtained. Next renewal in ${Math.round(time / 1000)} seconds.`);

    current.status = "ok";
    scheduleNextStatusTransition(time, current, config);
}

/**
 * Handle logic when status is "ok".
 * @param {object} current
 * @param {object} config
 */
async function handleOk(current, config) {
    logger.info("Status is 'ok'. Attempting to obtain a new certificate in background...");

    const retryTime = current.active_cert.ttl * config.intervals.error;
    let certData;

    try {
        certData = await fetchCertificate(config);
    } catch (e) {
        logger.error("Failed to obtain new certificate. Likely configuration error.");
        logger.info(`Retrying in ${Math.round(retryTime / 1000)} seconds.`);
        current.status = "error";
        return scheduleNextStatusTransition(retryTime, current, config);
    }

    current.second_cert = certData;

    // Check if the certificate is about to expire
    const timeUntilExpiration = current.active_cert.expiration * 1000 - Date.now();
    const bufferTime = current.active_cert.ttl * config.intervals.buffer;

    if (timeUntilExpiration < bufferTime) {
        logger.info("The active certificate is close to expiration. Replacing with new certificate now.");

        try {
            writeCertificateToFile(current.second_cert, config);
            current.active_cert = current.second_cert;
            current.second_cert = null;
        } catch (e) {
            logger.error("Couldn't write new certificate to file. Check permissions.");
            logger.info(`Retrying in ${Math.round(retryTime / 1000)} seconds.`);
            current.status = "error";
            return scheduleNextStatusTransition(retryTime, current, config);
        }

        // Run onreplace commands
        try {
            await runCommandsSafely(config.onreplace, "Fatal error running 'onreplace' commands.");
        } catch (e) {
            throw e;
        }
    }

    // Calculate TTL for scheduling
    const ttl = certData.expiration * 1000 - Date.now();
    if (!ttl || ttl <= 0) {
        logger.error("Unknown or invalid certificate expiration time.");
        throw new Error("Can't proceed, unknown/invalid expiration time.");
    }

    certData.ttl = ttl;
    const time = config.intervals.ok * ttl;
    logger.info(`New certificate obtained. Next renewal in ${Math.round(time / 1000)} seconds.`);

    current.status = "ok";
    scheduleNextStatusTransition(time, current, config);
}

/**
 * Handle logic when status is "error".
 * @param {object} current
 * @param {object} config
 */
async function handleError(current, config) {
    logger.info("Status is 'error'. Attempting to recover and obtain a new certificate...");

    // <-- Likely bug is here: check if the certificate is actually expired
    // If expiration is in seconds, compare (expiration * 1000) to Date.now()
    if (current.active_cert.expiration * 1000 < Date.now()) {
        logger.error("The active certificate has expired. Cannot proceed.");
        throw new Error('Last certificate has expired, aborting.');
    }

    const retryTime = current.active_cert.ttl * config.intervals.error;
    let certData;

    try {
        certData = await fetchCertificate(config);
    } catch (e) {
        logger.error("Failed to obtain certificate while in error state.");

        // If we're close to expiration, attempt to swap with second_cert (if present)
        const timeUntilExpiration = current.active_cert.expiration * 1000 - Date.now();
        const bufferTime = current.active_cert.ttl * config.intervals.buffer;
        if (timeUntilExpiration < bufferTime && current.second_cert) {
            logger.info("Swapping to the backup certificate since the active one is about to expire.");

            try {
                writeCertificateToFile(current.second_cert, config);
                current.active_cert = current.second_cert;
                current.second_cert = null;
            } catch (writeErr) {
                logger.error("Could not write backup certificate to file.");
                logger.info(`Retrying in ${Math.round(retryTime / 1000)} seconds.`);
                return scheduleNextStatusTransition(retryTime, current, config);
            }

            // Run onreplace commands
            try {
                await runCommandsSafely(config.onreplace, "Fatal error running 'onreplace' commands.");
            } catch (cmdErr) {
                throw cmdErr;
            }
        }

        logger.info(`Retrying in ${Math.round(retryTime / 1000)} seconds.`);
        return scheduleNextStatusTransition(retryTime, current, config);
    }

    // If we succeed in obtaining the certificate
    current.second_cert = certData;

    // Check if the active certificate is close to expiration
    const timeUntilExpiration = current.active_cert.expiration * 1000 - Date.now();
    const bufferTime = current.active_cert.ttl * config.intervals.buffer;

    if (timeUntilExpiration < bufferTime) {
        logger.info("Active certificate is about to expire. Replacing with newly obtained certificate.");
        try {
            writeCertificateToFile(current.second_cert, config);
            current.active_cert = current.second_cert;
            current.second_cert = null;
        } catch (e) {
            logger.error("Failed to write new certificate to file. Check permissions.");
            logger.info(`Retrying in ${Math.round(retryTime / 1000)} seconds.`);
            return scheduleNextStatusTransition(retryTime, current, config);
        }

        // Run onreplace commands
        try {
            await runCommandsSafely(config.onreplace, "Fatal error running 'onreplace' commands.");
        } catch (e) {
            throw e;
        }
    }

    // Calculate TTL for the newly obtained certificate
    const ttl = certData.expiration * 1000 - Date.now();
    if (!ttl || ttl <= 0) {
        logger.error("Unknown or invalid certificate expiration time.");
        throw new Error("Can't proceed, unknown/invalid expiration time.");
    }

    certData.ttl = ttl;
    const time = config.intervals.ok * ttl;

    logger.info("Successfully recovered from error state! [ERROR:RESOLVED]");
    logger.info(`Next renewal in ${Math.round(time / 1000)} seconds.`);

    current.status = "ok";
    scheduleNextStatusTransition(time, current, config);
}

module.exports = main;
