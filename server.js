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
 
// Create tables on startup
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        full_name VARCHAR(255),
        password_hash VARCHAR(255),
        user_type VARCHAR(50) DEFAULT 'student',
        credits INTEGER DEFAULT 1000,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
 
      CREATE TABLE IF NOT EXISTS courses (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255),
        description TEXT,
        category VARCHAR(100),
        price INTEGER DEFAULT 0,
        instructor_id INTEGER,
        instructor_name VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
 
      CREATE TABLE IF NOT EXISTS enrollments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        course_id INTEGER,
        enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('✅ Database schema ready');
  } catch (err) {
    console.error('DB error:', err.message);
  }
}
 
initDB();
 
// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});
 
// Initialize demo data (ONLY FOR TESTING - visit this URL once to set up)
app.get('/init-demo', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash('password123', 10);
    
    // Create demo user
    await pool.query(
      'INSERT INTO users (email, full_name, password_hash, user_type, credits) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (email) DO NOTHING',
      ['student@demo.com', 'Demo Student', hashedPassword, 'student', 1000]
    );
 
    // Create sample courses
    await pool.query(
      'INSERT INTO courses (title, description, category, price, instructor_name) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING',
      ['AI Fundamentals', 'Learn basics of artificial intelligence', 'AI', 200, 'John Doe']
    );
    await pool.query(
      'INSERT INTO courses (title, description, category, price, instructor_name) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING',
      ['Web Development', 'Build modern web apps', 'Development', 300, 'Jane Smith']
    );
    await pool.query(
      'INSERT INTO courses (title, description, category, price, instructor_name) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING',
      ['Data Science', 'Master data analysis', 'Data', 400, 'Bob Johnson']
    );
 
    res.json({ success: true, message: 'Demo data initialized!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
 
// Get courses
app.get('/api/courses', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM courses LIMIT 50');
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
    if (!result.rows.length) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        credits: user.credits
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
 
// Signup
app.post('/api/auth/signup', async (req, res) => {
  const { email, fullName, password } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, full_name, password_hash, user_type, credits) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, full_name, credits',
      [email, fullName, hashed, 'student', 1000]
    );
    const user = result.rows[0];
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
 
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ API running on ${PORT}`);
});
 
