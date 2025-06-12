const { db } = require('../config/database');
const { ZTA_CONFIG } = require('../config/security');

const zeroTrustMiddleware = (req, res, next) => {
  if (!req.user) {
    return next();
  }

  const userId = req.user.id;
  const ipAddress = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent') || '';

  // Get or create session
  const sessionQuery = `
    SELECT * FROM user_sessions
    WHERE user_id = ? AND ip_address = ? AND user_agent = ?
    ORDER BY last_activity DESC LIMIT 1
  `;

  db.get(sessionQuery, [userId, ipAddress, userAgent], (err, session) => {
    if (err) {
      return res.status(500).json({ error: 'Session validation failed' });
    }

    let riskScore = 0;
    const now = new Date();

    if (session) {
      // Calculate risk based on behavior
      const timeSinceLastActivity = now - new Date(session.last_activity);
      const requestFrequency = session.request_count;

      // Risk factors
      if (timeSinceLastActivity < 1000) riskScore += 20; // Too frequent
      if (requestFrequency > 50) riskScore += 30; // Too many requests
      if (req.path.includes('admin')) riskScore += 25; // Admin access

      // Update session
      const updateQuery = `
        UPDATE user_sessions
        SET request_count = request_count + 1,
            last_activity = CURRENT_TIMESTAMP,
            risk_score = ?
        WHERE id = ?
      `;

      db.run(updateQuery, [riskScore, session.id]);

      // Block if risk too high
      if (riskScore > ZTA_CONFIG.RISK_THRESHOLD) {
        return res.status(429).json({
          error: 'Suspicious activity detected. Access temporarily blocked.',
          riskScore,
        });
      }
    } else {
      // Create new session
      const insertQuery = `
        INSERT INTO user_sessions (user_id, ip_address, user_agent, request_count, risk_score)
        VALUES (?, ?, ?, 1, ?)
      `;

      db.run(insertQuery, [userId, ipAddress, userAgent, riskScore]);
    }

    req.riskScore = riskScore;
    next();
  });
};

module.exports = { zeroTrustMiddleware };
