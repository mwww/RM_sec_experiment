const express = require('express');
const { body, validationResult } = require('express-validator');
const { db } = require('../../config/database');
const { authenticateToken, authorizeRole, authorizeOwner } = require('../../middleware/auth');
const { generalLimiter } = require('../../middleware/rateLimiter');
const { zeroTrustMiddleware } = require('../../middleware/zeroTrust');
const router = express.Router();

// Apply middleware to all routes
router.use(generalLimiter);
router.use(authenticateToken);
router.use(zeroTrustMiddleware);

// SECURE - Get user by ID (with proper authorization)
router.get('/:id', authorizeOwner, (req, res) => {
  const userId = parseInt(req.params.id);

  // Parameterized query
  const query = 'SELECT id, username, email, role, created_at FROM users WHERE id = ?';

  db.get(query, [userId], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (user) {
      // Return only safe data
      res.json({
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        created_at: user.created_at,
      });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  });
});

// SECURE - List users (admin only, limited data)
router.get('/', authorizeRole(['admin']), (req, res) => {
  const query = 'SELECT id, username, email, role, created_at FROM users';

  db.all(query, (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    // Return only safe data
    res.json(
      users.map((user) => ({
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        created_at: user.created_at,
      }))
    );
  });
});

// SECURE - Update user (with proper validation and authorization)
router.put(
  '/:id',
  [
    authorizeOwner,
    body('username').optional().isLength({ min: 3, max: 20 }).trim().escape(),
    body('email').optional().isEmail().normalizeEmail(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const userId = parseInt(req.params.id);
    const { username, email } = req.body;

    // Build dynamic query safely
    const updates = [];
    const values = [];

    if (username) {
      updates.push('username = ?');
      values.push(username);
    }
    if (email) {
      updates.push('email = ?');
      values.push(email);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }

    values.push(userId);
    const query = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;

    db.run(query, values, function (err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ error: 'Username or email already exists' });
        }
        return res.status(500).json({ error: 'Update failed' });
      }

      res.json({
        success: true,
        message: 'User updated successfully',
        changes: this.changes,
      });
    });
  }
);

module.exports = router;
