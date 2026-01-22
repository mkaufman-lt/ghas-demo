const express = require('express');
const router = express.Router();
const mysql = require('mysql');

// Database connection configuration
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'testdb'
});

/**
 * WARNING: This file contains SQL injection vulnerabilities for TESTING purposes only.
 * DO NOT use these patterns in production code.
 */

// ============================================
// VULNERABLE ROUTE - SQL Injection Risk
// ============================================

/**
 * VULNERABLE: Direct string concatenation in SQL query
 * Example attack: /api/user?id=' OR '1'='1
 */
router.get('/api/user', (req, res) => {
  const userId = req.query.id;

  // VULNERABLE: String concatenation creates SQL injection
  const query = `SELECT * FROM users WHERE id = '${userId}'`;

  db.query(query, (error, results) => {
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    res.json(results);
  });
});

/**
 * VULNERABLE: Login endpoint with SQL injection
 * Example attack: username=' OR '1'='1' --&password=anything
 */
router.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // VULNERABLE: Direct interpolation in SQL query
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.query(query, (error, results) => {
    if (error) {
      return res.status(500).json({ error: error.message });
    }

    if (results.length > 0) {
      res.json({ success: true, user: results[0] });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  });
});

/**
 * VULNERABLE: Search endpoint with SQL injection
 * Example attack: /api/search?term='; DROP TABLE users; --
 */
router.get('/api/search', (req, res) => {
  const searchTerm = req.query.term;

  // VULNERABLE: Unescaped user input in LIKE clause
  const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;

  db.query(query, (error, results) => {
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    res.json(results);
  });
});

module.exports = router;
