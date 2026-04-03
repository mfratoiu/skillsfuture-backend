require('dotenv').config();
require('express-async-errors');
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware
app.use(cors({
  origin: '*',
  credentials: true
}));
app.use(express.json());

// Database Connection with better error handling
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
});

// Init Database - runs once, doesn't crash app if it fails
const initDB = async () => {
  try {
    console.log('🔄 Initializing database schema...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        organization VARCHAR(255),
        user_type VARCHAR(50) NOT NULL,
        credits INTEGER DEFAULT 1000,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS courses (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        category VARCHAR(100) NOT NULL,
        price INTEGER NOT NULL,
        level VARCHAR(50) NOT NULL,
        instructor_id INTEGER NOT NULL,
        instructor_name VARCHAR(255) NOT NULL,
        rating DECIMAL(3,1) DEFAULT 4.8,
        students INTEGER DEFAULT 0,
        hours INTEGER DEFAULT 12,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS enrollments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        course_id INTEGER NOT NULL,
        enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        progress INTEGER DEFAULT 0,
        UNIQUE(user_id, course_id)
      );

      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        course_id INTEGER NOT NULL,
        amount INTEGER NOT NULL,
        stripe_payment_id VARCHAR(255),
        status VARCHAR(50) DEFAULT 'completed',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS payouts (
        id SERIAL PRIMARY KEY,
        trainer_id INTEGER NOT NULL,
        amount INTEGER NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    // Migrations - add columns missing from older deployments
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS organization VARCHAR(255) DEFAULT ''`);
    console.log('✅ Database schema initialized');
  } catch (err) {
    console.error('⚠️  Database init warning:', err.message);
    // Don't crash - try again later
  }
};

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'No token' });

  jwt.verify(token, process.env.JWT_SECRET || 'test-secret', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'SkillsFuture API is running' });
});

// ===== AUTH ROUTES =====
app.post('/api/auth/signup', async (req, res) => {
  const { email, fullName, password, userType, organization } = req.body;

  try {
    if (!email || !fullName || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

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
    console.error('Signup error:', err);
    res.status(400).json({ error: err.message || 'Signup failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

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
    console.error('Login error:', err);
    res.status(400).json({ error: err.message || 'Login failed' });
  }
});

// ===== COURSES ROUTES =====
app.get('/api/courses', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM courses ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Courses error:', err);
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/courses/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM courses WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Course detail error:', err);
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/courses', authenticateToken, async (req, res) => {
  const { title, description, category, price, level } = req.body;

  try {
    if (!title || !description || !category || !price || !level) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const userResult = await pool.query('SELECT full_name FROM users WHERE id = $1', [req.user.id]);
    const instructorName = userResult.rows[0].full_name;

    const result = await pool.query(
      'INSERT INTO courses (title, description, category, price, level, instructor_id, instructor_name) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [title, description, category, price, level, req.user.id, instructorName]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Create course error:', err);
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const course = await pool.query('SELECT instructor_id FROM courses WHERE id = $1', [req.params.id]);
    if (course.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found' });
    }
    if (course.rows[0].instructor_id !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    await pool.query('DELETE FROM courses WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete course error:', err);
    res.status(400).json({ error: err.message });
  }
});

// ===== ENROLLMENTS ROUTES =====
app.get('/api/enrollments', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT c.* FROM courses c JOIN enrollments e ON c.id = e.course_id WHERE e.user_id = $1',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Enrollments error:', err);
    res.status(400).json({ error: err.message });
  }
});

// ===== PAYMENT ROUTES =====
app.post('/api/payments/enroll', authenticateToken, async (req, res) => {
  const { courseId } = req.body;

  try {
    if (!courseId) {
      return res.status(400).json({ error: 'Course ID required' });
    }

    // Get course and user
    const courseResult = await pool.query('SELECT price FROM courses WHERE id = $1', [courseId]);
    const userResult = await pool.query('SELECT credits FROM users WHERE id = $1', [req.user.id]);

    if (courseResult.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found' });
    }

    const course = courseResult.rows[0];
    const user = userResult.rows[0];

    if (user.credits < course.price) {
      return res.status(400).json({ error: 'Insufficient credits' });
    }

    // Create enrollment
    await pool.query(
      'INSERT INTO enrollments (user_id, course_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.user.id, courseId]
    );

    // Deduct credits
    await pool.query('UPDATE users SET credits = credits - $1 WHERE id = $2', [course.price, req.user.id]);

    // Record transaction
    await pool.query(
      'INSERT INTO transactions (user_id, course_id, amount, status) VALUES ($1, $2, $3, $4)',
      [req.user.id, courseId, course.price, 'completed']
    );

    // Get instructor for payout
    const instructorResult = await pool.query('SELECT instructor_id FROM courses WHERE id = $1', [courseId]);
    const trainerPayout = Math.floor(course.price * 0.85);
    await pool.query(
      'INSERT INTO payouts (trainer_id, amount, status) VALUES ($1, $2, $3)',
      [instructorResult.rows[0].instructor_id, trainerPayout, 'pending']
    );

    res.json({ success: true, message: 'Enrolled successfully' });
  } catch (err) {
    console.error('Enrollment error:', err);
    res.status(400).json({ error: err.message });
  }
});

// ===== DASHBOARD ROUTES =====
app.get('/api/dashboard/student', authenticateToken, async (req, res) => {
  try {
    const enrolledResult = await pool.query(
      'SELECT COUNT(*) FROM enrollments WHERE user_id = $1',
      [req.user.id]
    );
    const creditsResult = await pool.query('SELECT credits FROM users WHERE id = $1', [req.user.id]);

    const enrolled = parseInt(enrolledResult.rows[0].count);

    res.json({
      enrolled: enrolled,
      credits: creditsResult.rows[0].credits,
      inProgress: Math.floor(enrolled * 0.5),
      completed: 2
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/dashboard/trainer', authenticateToken, async (req, res) => {
  try {
    const coursesResult = await pool.query('SELECT COUNT(*) FROM courses WHERE instructor_id = $1', [req.user.id]);
    const enrollmentsResult = await pool.query(
      'SELECT COUNT(*) FROM enrollments e JOIN courses c ON e.course_id = c.id WHERE c.instructor_id = $1',
      [req.user.id]
    );
    const payoutsResult = await pool.query(
      'SELECT COALESCE(SUM(amount), 0) as total FROM payouts WHERE trainer_id = $1',
      [req.user.id]
    );

    res.json({
      courses: parseInt(coursesResult.rows[0].count),
      learners: parseInt(enrollmentsResult.rows[0].count),
      revenue: Math.floor(parseInt(payoutsResult.rows[0].total) / 1000),
      rating: 4.8
    });
  } catch (err) {
    console.error('Trainer dashboard error:', err);
    res.status(400).json({ error: err.message });
  }
});

// ===== TRAINER COURSES ROUTES =====
app.get('/api/trainer/courses', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT c.*, (SELECT COUNT(*) FROM enrollments WHERE course_id = c.id) as students FROM courses c WHERE c.instructor_id = $1',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Trainer courses error:', err);
    res.status(400).json({ error: err.message });
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Server error', message: err.message });
});

// Start server
const PORT = process.env.PORT || 3001;

app.listen(PORT, async () => {
  console.log(`✅ SkillsFuture API running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🗄️  DATABASE_URL set: ${!!process.env.DATABASE_URL}`);

  // Test DB connection first, then init schema
  try {
    const client = await pool.connect();
    console.log('✅ Database connection successful');
    client.release();
    await initDB();
  } catch (err) {
    console.error('❌ Database connection FAILED:', err.message);
    console.error('   Check DATABASE_URL env var and Postgres availability');
  }
});
