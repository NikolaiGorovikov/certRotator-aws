const fs = require("fs");
const logger = require("./logger.js");

function main() {
    const path = process.argv[2];
    if (!path) {
        logger.error("Looks like you didn't provide the configuration file, aborting.");
        throw new Error("No config file in the argument");
    }
    try {
        var contents = fs.readFileSync(path, 'utf8');
    }
    catch (e) {
        logger.error("Can't read the file at a given location.");
        throw e;
    }
    try {
        var json = JSON.parse(contents);
    }
    catch (e) {
        logger.error("Your file is not a valid JSON");
        throw e;
    }

    return json;

}

module.exports = main;