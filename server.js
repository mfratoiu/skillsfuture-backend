require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

app.use(cors({ origin: '*' }));
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'API is running' });
});

// Get all courses
app.get('/api/courses', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM courses LIMIT 100');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, userType: user.user_type },
      process.env.JWT_SECRET || 'test-secret',
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        userType: user.user_type,
        credits: user.credits
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Signup
app.post('/api/auth/signup', async (req, res) => {
  const { email, fullName, password, userType, organization } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, full_name, password_hash, user_type, organization, credits) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, full_name, user_type, credits',
      [email, fullName, hashedPassword, userType || 'student', organization || '', 1000]
    );

    const user = result.rows[0];
    const token = jwt.sign(
      { id: user.id, email: user.email, userType: user.user_type },
      process.env.JWT_SECRET || 'test-secret',
      { expiresIn: '7d' }
    );

    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ API running on port ${PORT}`);
});
