const aws = require("aws-ahh-sdk");
const { spawn } = require('child_process');
const logger = require("./logger");

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


async function getCert(config) {
    return await aws.vaultCert({
        requestBody: config.cert,
        ...config.vault
    });
}

async function main(current, config) {
    if (current.status === 'start') {
        const retryTime = config.intervals.default;
        try {
            var certData = await getCert(config);
        }
        catch (e) {
            logger.error("The initial certificate was not obtained. It is very likely that the configuration has errors.");
            logger.info("The certificate was not obtained, will retry in "+retryTime/1000+" seconds.");
            setTimeout(()=>main(current, config), retryTime);
            return;
        }
        current.active_cert = certData;
        current.second_cert = null;

        // Now change the certificates in the files
        // Yeah we assume bundles
        try {
            fs.writeFileSync(config.tls.cert, certData.certificate+"/n"+certData.private_key);
        }
        catch (e) {
            logger.error("Couldn't write to the file, check the permissions.");
            logger.info("The certificate was obtained, but can't be written to the file. Will retry in "+retryTime/1000+" seconds.");
            setTimeout(()=>main(current, config), retryTime);
            return;
        }
        const commands = config.onstart;
        try {
            if (commands) {
                for (let command of commands) await runCommand(command);
            }
        }
        catch (e) {
            logger.error("One of commands resulted in error. This is a Fatal error, as there is no way to figure out what to do next.")
            throw e;
        }

        const ttl = certData.expiration*1000-Date.now();
        if (!ttl) {
            logger.error("Unknown expiration time of the certificate.");
            throw new Error("Can't proceed, unknown expiration time.");
        }

        certData.ttl = ttl;
        const time = config.intervals.ok*ttl;
        logger.info("Will get a new certificate in "+time/1000+" seconds.");
        current.status = "ok";
        setTimeout(()=>main(current, config), time);
    }

    if (current.status === 'ok') {
        const retryTime = current.active_cert.ttl*config.intervals.error;
        try {
            var certData = await getCert(config);
        }
        catch (e) {
            logger.error("The certificate was not obtained. It is very likely that the configuration has errors.");
            logger.info("The certificate was not obtained, will retry in "+retryTime/1000+" seconds.");
            current.status = "error";
            setTimeout(()=>main(current, config), retryTime);
            return;
        }

        current.second_cert = certData;

        // Now change the certificates in the files
        // Yeah we assume bundles
        if (current.active_cert.expiration*1000-Date.now() < current.active_cert.ttl*config.intervals.buffer) {


            try {
                fs.writeFileSync(config.tls.cert, current.second_cert.certificate+"/n"+current.second_cert.private_key);
                current.active_cert = current.second_cert;
                current.second_cert = null;
            }
            catch (e) {
                logger.error("Couldn't write to the file, check the permissions.");
                logger.info("The certificate was obtained, but can't be written to the file. Will retry in "+retryTime/1000+" seconds.");
                current.status = "error";
                setTimeout(()=>main(current, config), retryTime);
                return;
            }
            const commands = config.onreplace;
            try {
                if (commands) {
                    for (let command of commands) await runCommand(command);
                }
            }
            catch (e) {
                logger.error("One of commands resulted in error. This is a Fatal error, as there is no way to figure out what to do next.")
                throw e;
            }
        }

        const ttl = certData.expiration*1000-Date.now();
        if (!ttl) {
            logger.error("Unknown expiration time of the certificate.");
            throw new Error("Can't proceed, unknown expiration time.");
        }

        certData.ttl = ttl;
        const time = config.intervals.ok*ttl;
        logger.info("Will get a new certificate in "+time/1000+" seconds.");
        current.status = "ok";
        setTimeout(()=>main(current, config), time);

    }

    if (current.status === 'error') {
        const retryTime = current.active_cert.ttl*config.intervals.error;
        try {
            var certData = await getCert(config);
        }
        catch (e) {
            logger.error("The certificate was not obtained. It is very likely that the configuration has errors.");
            if (current.active_cert.expiration*1000-Date.now() < current.active_cert.ttl*config.intervals.buffer && current.second_cert) {

                logger.info('Now, as the existing certificate is close to expiration, will change it to the backup one ')
                try {
                    fs.writeFileSync(config.tls.cert, current.second_cert.certificate+"/n"+current.second_cert.private_key);
                    current.active_cert = current.second_cert;
                    current.second_cert = null;
                }
                catch (e) {
                    logger.error("Couldn't write to the file, check the permissions.");
                    logger.info("The certificate was obtained, but can't be written to the file. Will retry in "+retryTime/1000+" seconds.");
                    current.status = "error";
                    setTimeout(()=>main(current, config), retryTime);
                    return;
                }
                const commands = config.onreplace;
                try {
                    if (commands) {
                        for (let command of commands) await runCommand(command);
                    }
                }
                catch (e) {
                    logger.error("One of commands resulted in error. This is a Fatal error, as there is no way to figure out what to do next.")
                    throw e;
                }

            }
            logger.info("The certificate was not obtained, will retry in "+retryTime/1000+" seconds.");
            current.status = "error";
            setTimeout(()=>main(current, config), retryTime);
            return;
        }

        current.second_cert = certData;

        // Now change the certificates in the files
        // Yeah we assume bundles
        if (current.active_cert.expiration*1000-Date.now() < current.active_cert.ttl*config.intervals.buffer) {

            try {
                fs.writeFileSync(config.tls.cert, current.second_cert.certificate+"/n"+current.second_cert.private_key);
                current.active_cert = current.second_cert;
                current.second_cert = null;
            }
            catch (e) {
                logger.error("Couldn't write to the file, check the permissions.");
                logger.info("The certificate was obtained, but can't be written to the file. Will retry in "+retryTime/1000+" seconds.");
                current.status = "error";
                setTimeout(()=>main(current, config), retryTime);
                return;
            }
            const commands = config.onreplace;
            try {
                if (commands) {
                    for (let command of commands) await runCommand(command);
                }
            }
            catch (e) {
                logger.error("One of commands resulted in error. This is a Fatal error, as there is no way to figure out what to do next.")
                throw e;
            }
        }

        const ttl = certData.expiration*1000-Date.now();
        if (!ttl) {
            logger.error("Unknown expiration time of the certificate.");
            throw new Error("Can't proceed, unknown expiration time.");
        }
        certData.ttl = ttl;

        const time = config.intervals.ok*ttl;
        logger.info("Will get a new certificate in "+time/1000+" seconds.");
        current.status = "ok";
        setTimeout(()=>main(current, config), time);

    }

}
