const { createLogger, format, transports } = require('winston');

// Helper to get local timezone offset in (+HH:MM) format
function getUTCOffsetString() {
    const offsetMinutes = new Date().getTimezoneOffset(); // in minutes
    const absMinutes = Math.abs(offsetMinutes);
    const hours = String(Math.floor(absMinutes / 60)).padStart(2, '0');
    const minutes = String(absMinutes % 60).padStart(2, '0');
    const sign = offsetMinutes <= 0 ? '+' : '-';
    return `UTC${sign}${hours}:${minutes}`;
}

const logger = createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: format.combine(
        format.colorize({ all: true }),
        format.timestamp({ format: () => new Date().toISOString() }), // UTC ISO format
        format.printf(({ timestamp, level, message }) => {
            const offset = getUTCOffsetString();
            return `[${level}] ${timestamp} (${offset}): ${message}`;
        })
    ),
    transports: [new transports.Console()],
});

module.exports = logger;