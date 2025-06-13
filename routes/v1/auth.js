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

// VULNERABLE: JWT Token Validation (accepts any token format)
router.post('/validate-token', (req, res) => {
  const { token } = req.body;

  // Insecure: No proper JWT validation, just string checks
  if (token && token.includes('token_')) {
    res.json({
      valid: true,
      message: 'Token accepted',
      decoded: {
        // Fake decoding - security through obscurity
        user_id: token.split('_')[1],
        timestamp: token.split('_')[2],
      },
    });
  } else {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// VULNERABLE: Password Reset with predictable tokens
router.post('/reset-password', (req, res) => {
  const { email } = req.body;

  // Insecure: Predictable reset tokens
  const resetToken = `reset_${email}_${Date.now()}`;

  res.json({
    success: true,
    message: 'Reset token generated',
    token: resetToken, // Exposing reset token directly
    expires: Date.now() + 3600000, // 1 hour
  });
});

// VULNERABLE: XML Processing (XXE) - EXTREMELY DANGEROUS!
router.post('/process-xml', (req, res) => {
  const fs = require('fs');
  const { xmlData } = req.body;

  if (!xmlData) {
    return res.status(400).json({ error: 'XML data required' });
  }

  try {
    // EXTREMELY VULNERABLE: Manual XML entity processing
    // This is intentionally dangerous for demonstration purposes
    let processedXml = xmlData;

    // Look for DOCTYPE declarations with ENTITY definitions
    const entityPattern = /<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>/gi;
    const entityMatches = [...xmlData.matchAll(entityPattern)];

    // Process each external entity
    for (const match of entityMatches) {
      const entityName = match[1];
      const entityPath = match[2];

      try {
        // VULNERABILITY: Read external files (file:// URLs)
        if (entityPath.startsWith('file://')) {
          const filePath = entityPath.replace('file://', '');

          // Try to read the file
          if (fs.existsSync(filePath)) {
            const fileContent = fs.readFileSync(filePath, 'utf8');
            // Replace entity references with file content
            const entityRef = new RegExp(`&${entityName};`, 'g');
            processedXml = processedXml.replace(entityRef, fileContent);
          } else {
            // If file doesn't exist, replace with error message
            const entityRef = new RegExp(`&${entityName};`, 'g');
            processedXml = processedXml.replace(entityRef, `[FILE_NOT_FOUND: ${filePath}]`);
          }
        } else if (entityPath.startsWith('http://') || entityPath.startsWith('https://')) {
          // VULNERABILITY: Make HTTP requests to external URLs (SSRF via XXE)
          const request = require('request');
          const entityRef = new RegExp(`&${entityName};`, 'g');

          // Synchronous request (blocking) - very dangerous in production
          try {
            const response = require('child_process').execSync(`curl -s -m 5 "${entityPath}"`, {
              encoding: 'utf8',
              timeout: 5000,
            });
            processedXml = processedXml.replace(entityRef, response);
          } catch (error) {
            processedXml = processedXml.replace(entityRef, `[HTTP_ERROR: ${error.message}]`);
          }
        }
      } catch (error) {
        console.log(`XXE Processing error for entity ${entityName}: ${error.message}`);
      }
    }

    // Simple XML parsing after entity processing
    const xml2js = require('xml2js');
    const parser = new xml2js.Parser({
      explicitArray: false,
      ignoreAttrs: false,
    });

    parser.parseString(processedXml, (err, result) => {
      if (err) {
        // Even if parsing fails, return the processed XML content
        return res.json({
          success: true,
          message: 'XML entity processing completed',
          processedXml: processedXml,
          error: 'Final XML parsing failed but entities were processed',
        });
      }

      res.json({
        success: true,
        message: 'XML processed successfully',
        parsed: result,
        processedXml: processedXml.length > 1000 ? processedXml.substring(0, 1000) + '...' : processedXml,
      });
    });
  } catch (error) {
    res.status(500).json({
      error: 'Processing failed',
      details: error.message,
    });
  }
});

module.exports = router;
