const { createLogger, format, transports } = require('winston');

const logger = createLogger({
    level: process.env.LOG_LEVEL || 'info', // Default log level
    format: format.combine(
        format.colorize({ all: true }),
        format.timestamp(),
        format.printf(({ timestamp, level, message }) => {
            return `[${level}] ${timestamp}: ${message}`;
        })
    ),
    transports: [new transports.Console()],
});

module.exports = logger;