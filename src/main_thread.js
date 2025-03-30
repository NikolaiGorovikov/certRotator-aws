const aws = require("aws-ahh-sdk");
const { spawn } = require("child_process");
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
        const child = spawn(fullCommand, { shell: true, stdio: "inherit" });

        child.on("error", (err) => {
            reject(new Error(`Failed to start command: ${err.message}`));
        });

        child.on("close", (code) => {
            if (code === 0) {
                resolve();
            } else {
                reject(new Error(`Command exited with code ${code}`));
            }
        });
    });
}

/**
 * Runs multiple commands in parallel. Each command has its own retry logic.
 * The function returns once ALL commands have succeeded OR at least one command fails all retries.
 *
 * @param {Array<{command: string, description?: string, onfail: {retry_every: number, retry_num: number}}>} hookArray
 * @param {string} hookName - Either "onstart" or "onreplace" (for logging).
 */
function runHookCommands(hookArray, hookName) {
    if (!Array.isArray(hookArray) || hookArray.length === 0) {
        logger.info(`No '${hookName}' commands to run.`);
        return Promise.resolve();
    }

    // Each command runs in parallel, each can succeed or keep retrying until success or attempts exhausted.
    // We gather the results with Promise.all().
    const promises = hookArray.map((hook, index) => {
        return new Promise((resolve, reject) => {
            let attempts = 0;
            const maxAttempts = hook.onfail.retry_num;
            const interval = hook.onfail.retry_every;
            let completed = false;

            async function attempt() {
                if (completed) return; // just in case

                attempts++;
                if (hook.description) {
                    logger.info(`(${hookName}[${index}]) ${hook.description}`);
                }
                logger.info(`Attempting command [${hook.command}] (attempt #${attempts})...`);

                try {
                    await runCommand(hook.command);
                    logger.info(`Command succeeded [${hook.command}]`);
                    completed = true;
                    resolve(); // done for this command
                } catch (err) {
                    logger.error(`Command failed [${hook.command}]: ${err.message}`);
                    if (attempts >= maxAttempts) {
                        // Exhausted all attempts => hard failure
                        return reject(new Error(
                            `Command [${hook.command}] failed after ${attempts} attempts.`
                        ));
                    }
                    // Otherwise, schedule next attempt
                    setTimeout(() => attempt(), interval);
                }
            }

            // First attempt
            attempt();
        });
    });

    // The runHookCommands only resolves when ALL commands are done or one is exhausted
    return Promise.all(promises).then(() => {
        logger.info(`All '${hookName}' commands completed successfully.`);
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
 * Writes the certificate and private key to a file (the same file for both, per config).
 * @param {object} certData - The certificate data object.
 * @param {object} config - The configuration object (for file paths).
 */
function writeCertificateToFile(certData, config) {
    logger.info(`Writing certificate to file: ${config.tls.cert}`);
    fs.writeFileSync(config.tls.cert, certData.certificate + "\n" + certData.private_key);
    logger.info("File write successful!");
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
        case "start":
            await handleStart(current, config);
            break;

        case "ok":
            await handleOk(current, config);
            break;

        case "error":
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

    // Run onstart commands with the new concurrency+retry logic
    try {
        logger.info("Running 'onstart' commands (with retry logic)...");
        await runHookCommands(config.onstart, "onstart");
    } catch (e) {
        // If we fail all attempts for any command, we consider it a fatal error
        logger.error(`Fatal error in 'onstart' commands: ${e.message}`);
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

        // Run onreplace commands with concurrency+retry logic
        try {
            logger.info("Running 'onreplace' commands (with retry logic)...");
            await runHookCommands(config.onreplace, "onreplace");
        } catch (e) {
            logger.error(`Fatal error in 'onreplace' commands: ${e.message}`);
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

    // If the active certificate is already expired, we have no fallback
    if (current.active_cert.expiration * 1000 < Date.now()) {
        logger.error("The active certificate has expired. Cannot proceed.");
        throw new Error("Last certificate has expired, aborting.");
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
                logger.info("Running 'onreplace' commands (with retry logic)...");
                await runHookCommands(config.onreplace, "onreplace");
            } catch (cmdErr) {
                throw cmdErr;
            }
        }

        logger.info(`Retrying in ${Math.round(retryTime / 1000)} seconds.`);
        return scheduleNextStatusTransition(retryTime, current, config);
    }

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
            current.status = "error";
            return scheduleNextStatusTransition(retryTime, current, config);
        }

        // Run onreplace commands with concurrency+retry logic
        try {
            logger.info("Running 'onreplace' commands (with retry logic)...");
            await runHookCommands(config.onreplace, "onreplace");
        } catch (e) {
            logger.error(`Fatal error in 'onreplace' commands: ${e.message}`);
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
