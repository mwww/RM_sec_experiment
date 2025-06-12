const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const db = new sqlite3.Database(':memory:');

const initDatabase = () => {
  db.serialize(() => {
    // Users table
    db.run(`
      CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        api_key TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Data table
    db.run(`
      CREATE TABLE sensitive_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        is_private BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    // Sessions table for ZTA
    db.run(`
      CREATE TABLE user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        session_token TEXT,
        ip_address TEXT,
        user_agent TEXT,
        request_count INTEGER DEFAULT 0,
        last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
        risk_score INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    // Insert sample data
    const hashedPassword = bcrypt.hashSync('password123', 10);
    const weakPassword = 'admin'; // Intentionally weak for V1

    // Sample users
    db.run(
      `
      INSERT INTO users (username, email, password, role, api_key) VALUES
      ('admin', 'admin@test.com', ?, 'admin', 'api_key_12345'),
      ('user1', 'user1@test.com', ?, 'user', 'api_key_67890'),
      ('user2', 'user2@test.com', ?, 'user', 'api_key_11111')
    `,
      [weakPassword, hashedPassword, hashedPassword]
    );

    // Sample sensitive data
    db.run(`
      INSERT INTO sensitive_data (user_id, title, content, is_private) VALUES
      (1, 'Admin Secret', 'Super secret admin data', 1),
      (2, 'User1 Data', 'User1 personal information', 1),
      (3, 'User2 Data', 'User2 personal information', 1),
      (1, 'Public Info', 'This is public information', 0)
    `);
  });
};

module.exports = { db, initDatabase };
