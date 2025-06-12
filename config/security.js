module.exports = {
  JWT_SECRET: process.env.JWT_SECRET || 'your-super-secret-jwt-key',
  JWT_EXPIRES_IN: '1h',
  BCRYPT_ROUNDS: 12,
  RATE_LIMIT: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP',
  },
  ZTA_CONFIG: {
    MAX_RISK_SCORE: 100,
    RISK_THRESHOLD: 70,
    SESSION_TIMEOUT: 30 * 60 * 1000, // 30 minutes
  },
};
