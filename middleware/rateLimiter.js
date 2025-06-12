const rateLimit = require('express-rate-limit');
const { RATE_LIMIT } = require('../config/security');

const createRateLimiter = (windowMs, max, message) => {
  return rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
  });
};

const generalLimiter = createRateLimiter(RATE_LIMIT.windowMs, RATE_LIMIT.max, RATE_LIMIT.message);

const strictLimiter = createRateLimiter(
  5 * 60 * 1000, // 5 minutes
  10, // 10 requests
  'Too many requests, please try again later'
);

const authLimiter = createRateLimiter(
  15 * 60 * 1000, // 15 minutes
  5, // 5 login attempts
  'Too many login attempts, please try again later'
);

module.exports = { generalLimiter, strictLimiter, authLimiter };
