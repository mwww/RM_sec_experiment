const express = require('express');
const { db } = require('../../config/database');
const router = express.Router();

// INSECURE LOGIN - No password hashing, SQL injection vulnerable
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Vulnerable SQL query (SQL injection possible)
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.get(query, (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (user) {
      // Return sensitive information
      res.json({
        success: true,
        message: 'Login successful',
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          api_key: user.api_key, // Exposing API key
          password: user.password, // Exposing password!
        },
        // Weak token (predictable)
        token: `token_${user.id}_${Date.now()}`,
      });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});

// INSECURE REGISTER - No validation
router.post('/register', (req, res) => {
  const { username, email, password } = req.body;

  // No input validation
  // No password strength check
  // Direct insertion (SQL injection vulnerable)
  const query = `INSERT INTO users (username, email, password, api_key) VALUES ('${username}', '${email}', '${password}', 'api_key_${Date.now()}')`;

  db.run(query, function (err) {
    if (err) {
      return res.status(400).json({ error: 'User creation failed' });
    }

    res.json({
      success: true,
      message: 'User created successfully',
      userId: this.lastID,
      api_key: `api_key_${Date.now()}`, // Exposing API key immediately
    });
  });
});

module.exports = router;
