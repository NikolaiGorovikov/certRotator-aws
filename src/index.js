const aws = require("aws-ahh-sdk");
const logger = require("./logger.js");

const get_config = require("./get_config.js");

function main() {
    const config = get_config();

    const tls = config.tls;
    aws.setTLS(tls);


}