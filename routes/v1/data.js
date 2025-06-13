const express = require('express');
const { db } = require('../../config/database');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const request = require('request');

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

// VULNERABLE: Server-Side Request Forgery (SSRF)
router.post('/fetch-url', (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL required' });
  }

  // Vulnerable: No URL validation, allows internal network access
  request(url, (error, response, body) => {
    if (error) {
      return res.status(500).json({ error: 'Request failed', details: error.message });
    }

    res.json({
      success: true,
      status: response.statusCode,
      headers: response.headers,
      body: body.substring(0, 1000), // Limit response size
    });
  });
});

// VULNERABLE: Path Traversal / Directory Traversal
router.get('/file/:filename', (req, res) => {
  const filename = req.params.filename;

  // Vulnerable: No path sanitization
  const filepath = path.join(__dirname, '../../uploads/', filename);

  try {
    // Dangerous: Can read any file on the system
    const content = fs.readFileSync(filepath, 'utf8');
    res.json({
      success: true,
      filename: filename,
      content: content,
    });
  } catch (error) {
    res.status(404).json({ error: 'File not found', details: error.message });
  }
});

// VULNERABLE: File Upload without validation
router.post('/upload', (req, res) => {
  const { filename, content, fileType } = req.body;

  if (!filename || !content) {
    return res.status(400).json({ error: 'Filename and content required' });
  }

  // Vulnerable: No file type validation, no size limits
  const uploadPath = path.join(__dirname, '../../uploads/', filename);

  try {
    // Create uploads directory if it doesn't exist
    const uploadsDir = path.dirname(uploadPath);
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }

    // Dangerous: Can write any file anywhere
    fs.writeFileSync(uploadPath, content);

    res.json({
      success: true,
      message: 'File uploaded successfully',
      path: uploadPath,
      size: content.length,
    });
  } catch (error) {
    res.status(500).json({ error: 'Upload failed', details: error.message });
  }
});

// VULNERABLE: NoSQL-style injection (even with SQL database)
router.get('/search', (req, res) => {
  const { query: searchQuery, options } = req.query;

  if (!searchQuery) {
    return res.status(400).json({ error: 'Search query required' });
  }

  // Vulnerable: Dynamic query construction
  let sql = `SELECT * FROM sensitive_data WHERE content LIKE '%${searchQuery}%'`;

  // Additional vulnerable parameter handling
  if (options) {
    try {
      const opts = JSON.parse(options);
      if (opts.orderBy) {
        sql += ` ORDER BY ${opts.orderBy}`;
      }
      if (opts.limit) {
        sql += ` LIMIT ${opts.limit}`;
      }
    } catch (e) {
      // Ignore JSON parsing errors
    }
  }

  db.all(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Search failed', details: err.message });
    }

    res.json({
      success: true,
      results: results,
      query: searchQuery,
    });
  });
});

module.exports = router;
