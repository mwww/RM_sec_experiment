const express = require('express');
const { body, validationResult } = require('express-validator');
const { db } = require('../../config/database');
const { authenticateToken, authorizeOwner } = require('../../middleware/auth');
const { generalLimiter } = require('../../middleware/rateLimiter');
const { zeroTrustMiddleware } = require('../../middleware/zeroTrust');
const router = express.Router();

// Apply middleware
router.use(generalLimiter);
router.use(authenticateToken);
router.use(zeroTrustMiddleware);

// SECURE - Get user's own data only
router.get('/user/:userId', authorizeOwner, (req, res) => {
  const userId = parseInt(req.params.userId);

  // Only return data that belongs to the authenticated user
  // and respect privacy settings
  const query = `
    SELECT id, title, content, is_private, created_at
    FROM sensitive_data
    WHERE user_id = ? AND (is_private = 0 OR user_id = ?)
  `;

  db.all(query, [userId, req.user.id], (err, data) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    res.json(data);
  });
});

// SECURE - Get only public data
router.get('/public', (req, res) => {
  const query = `
    SELECT d.id, d.title, d.content, d.created_at, u.username
    FROM sensitive_data d
    JOIN users u ON d.user_id = u.id
    WHERE d.is_private = 0
  `;

  db.all(query, (err, data) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    res.json(data);
  });
});

// SECURE - Create data with validation
router.post(
  '/',
  [
    body('title').isLength({ min: 1, max: 100 }).trim().escape(),
    body('content').isLength({ min: 1, max: 1000 }).trim().escape(),
    body('is_private').isBoolean(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { title, content, is_private } = req.body;
    const user_id = req.user.id; // Use authenticated user's ID

    const query = `
    INSERT INTO sensitive_data (user_id, title, content, is_private)
    VALUES (?, ?, ?, ?)
  `;

    db.run(query, [user_id, title, content, is_private], function (err) {
      if (err) {
        return res.status(500).json({ error: 'Data creation failed' });
      }

      res.status(201).json({
        success: true,
        id: this.lastID,
        message: 'Data created successfully',
      });
    });
  }
);

module.exports = router;
