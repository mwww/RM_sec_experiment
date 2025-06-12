const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config/security');
const { db } = require('../config/database');

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    req.user = user;
    next();
  });
};

const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

const authorizeOwner = (req, res, next) => {
  const resourceUserId = parseInt(req.params.userId || req.params.id);
  const currentUserId = req.user.id;

  if (currentUserId !== resourceUserId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied: You can only access your own resources' });
  }

  next();
};

module.exports = { authenticateToken, authorizeRole, authorizeOwner };
