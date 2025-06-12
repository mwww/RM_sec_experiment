const express = require('express');
const { db } = require('../../config/database');
const router = express.Router();

// INSECURE - No authentication, BOLA vulnerability
router.get('/user/:userId', (req, res) => {
  const userId = req.params.userId;

  // No authorization check - can access any user's data
  const query = `SELECT * FROM sensitive_data WHERE user_id = ${userId}`;

  db.all(query, (err, data) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    // Returning all data including private
    res.json(data);
  });
});

// INSECURE - Expose all sensitive data
router.get('/all', (req, res) => {
  db.all('SELECT * FROM sensitive_data', (err, data) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    res.json(data);
  });
});

// INSECURE - Create data without authentication
router.post('/', (req, res) => {
  const { user_id, title, content, is_private } = req.body;

  // No validation or authentication
  const query = `INSERT INTO sensitive_data (user_id, title, content, is_private) VALUES (${user_id}, '${title}', '${content}', ${is_private})`;

  db.run(query, function (err) {
    if (err) {
      return res.status(500).json({ error: 'Data creation failed' });
    }

    res.json({
      success: true,
      id: this.lastID,
      message: 'Data created successfully',
    });
  });
});

module.exports = router;
