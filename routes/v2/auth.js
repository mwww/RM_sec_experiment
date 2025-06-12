const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { db } = require('../../config/database');
const { JWT_SECRET, JWT_EXPIRES_IN, BCRYPT_ROUNDS } = require('../../config/security');
const { authLimiter } = require('../../middleware/rateLimiter');
const router = express.Router();

// Apply rate limiting to auth routes
router.use(authLimiter);

// SECURE LOGIN
router.post(
  '/login',
  [body('username').isLength({ min: 3 }).trim().escape(), body('password').isLength({ min: 6 })],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    // Parameterized query to prevent SQL injection
    const query = 'SELECT * FROM users WHERE username = ?';

    db.get(query, [username], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Generate secure JWT token
      const token = jwt.sign(
        {
          id: user.id,
          username: user.username,
          role: user.role,
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      // Return minimal user info
      res.json({
        success: true,
        message: 'Login successful',
        token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
        },
      });
    });
  }
);

// SECURE REGISTER
router.post(
  '/register',
  [
    body('username').isLength({ min: 3, max: 20 }).trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('password')
      .isLength({ min: 8 })
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;

    try {
      // Hash password securely
      const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

      // Parameterized query
      const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';

      db.run(query, [username, email, hashedPassword], function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Username or email already exists' });
          }
          return res.status(500).json({ error: 'User creation failed' });
        }

        res.status(201).json({
          success: true,
          message: 'User created successfully',
          userId: this.lastID,
        });
      });
    } catch (error) {
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

module.exports = router;
