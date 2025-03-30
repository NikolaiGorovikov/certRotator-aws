const aws = require("aws-ahh-sdk");
const logger = require("./logger.js");
const main_thread = require("./main_thread.js");
const parse_config = require("./parse_config.js");

const get_config = require("./get_config.js");

function main() {
    try {
        const config = get_config();
        try {
            parse_config(config);
        }
        catch (e) {
            logger.error("Your config is bullshit.");
            logger.error(e.message);
            process.exit(1);
        }

        const tls = config.tls;
        aws.setTLS(tls);

        main_thread({status:"start"}, config);
    }
    catch (e) {
        logger.error("Some fatal error occured. Aborting.");
        process.exit(1);
    }
}

main();

process.on('SIGINT', () => {
    logger.info('SIGINT was received, shutting down...');

    setTimeout(()=>{
        process.exit(0);

    }, 100);

});

process.on('SIGTERM', () => {
    logger.info('SIGTERM was received, shutting down...');

    setTimeout(()=>{
        process.exit(0);

    }, 100);

});