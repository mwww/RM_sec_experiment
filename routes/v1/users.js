const express = require('express');
const { db } = require('../../config/database');
const router = express.Router();

// INSECURE - No authentication required
// BOLA vulnerability - can access any user's data
router.get('/:id', (req, res) => {
  const userId = req.params.id;

  // No authorization check
  const query = `SELECT * FROM users WHERE id = ${userId}`;

  db.get(query, (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (user) {
      // Exposing all sensitive data
      res.json({
        id: user.id,
        username: user.username,
        email: user.email,
        password: user.password, // Exposing password
        role: user.role,
        api_key: user.api_key, // Exposing API key
        created_at: user.created_at,
      });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  });
});

// INSECURE - List all users with sensitive data
router.get('/', (req, res) => {
  db.all('SELECT * FROM users', (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    // Returning all sensitive information
    res.json(users);
  });
});

// INSECURE - Update any user without authentication
router.put('/:id', (req, res) => {
  const userId = req.params.id;
  const { username, email, password, role } = req.body;

  // No authentication or authorization
  // SQL injection vulnerable
  const query = `UPDATE users SET username = '${username}', email = '${email}', password = '${password}', role = '${role}' WHERE id = ${userId}`;

  db.run(query, function (err) {
    if (err) {
      return res.status(500).json({ error: 'Update failed' });
    }

    res.json({
      success: true,
      message: 'User updated successfully',
      changes: this.changes,
    });
  });
});

module.exports = router;
