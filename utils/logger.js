const fs = require('fs');
const path = require('path');

const logFile = path.join(__dirname, '../logs/app.log');

// Ensure logs directory exists
const logsDir = path.dirname(logFile);
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

const logger = {
  info: (message) => {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] INFO: ${message}\n`;
    console.log(logMessage.trim());
    fs.appendFileSync(logFile, logMessage);
  },

  error: (message) => {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] ERROR: ${message}\n`;
    console.error(logMessage.trim());
    fs.appendFileSync(logFile, logMessage);
  },

  warn: (message) => {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] WARN: ${message}\n`;
    console.warn(logMessage.trim());
    fs.appendFileSync(logFile, logMessage);
  },
};

module.exports = logger;
