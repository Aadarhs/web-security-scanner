const express = require('express');
const request = require('supertest');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

// Set test env before requiring modules
process.env.JWT_SECRET = 'test-secret-key';
process.env.ADMIN_EMAIL = 'test@securityscanner.local';
process.env.ADMIN_PASSWORD = 'Test@123456';

// Use a separate test database
const TEST_DB_PATH = path.resolve(__dirname, '..', '..', '..', 'database', 'test-scanner.db');
process.env.DB_PATH = TEST_DB_PATH;

// Clean up any previous test DB
try { fs.unlinkSync(TEST_DB_PATH); } catch {}

const db = require('../../config/db');

describe('Auth API Integration', () => {
  let app;

  beforeAll(async () => {
    await db.init();

    // Seed a test user
    const hashedPassword = bcrypt.hashSync('Test@123456', 4); // low rounds for speed
    db.prepare(
      'INSERT OR REPLACE INTO users (id, email, password, name, role) VALUES (?, ?, ?, ?, ?)'
    ).run(1, 'test@securityscanner.local', hashedPassword, 'Test Admin', 'admin');
    db.save();

    // Create Express app with auth routes
    app = express();
    app.use(express.json());
    app.use('/api/auth', require('../auth'));
  });

  afterAll(() => {
    db.close();
    try { fs.unlinkSync(TEST_DB_PATH); } catch {}
  });

  describe('POST /api/auth/login', () => {
    it('should return 400 when email is missing', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ password: 'Test@123456' });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('required');
    });

    it('should return 400 when password is missing', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'test@securityscanner.local' });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('required');
    });

    it('should return 401 with invalid credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'test@securityscanner.local', password: 'wrongpassword' });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Invalid credentials');
    });

    it('should return 401 with non-existent user', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'nobody@test.com', password: 'Test@123456' });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Invalid credentials');
    });

    it('should return token and user on successful login', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'test@securityscanner.local', password: 'Test@123456' });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('token');
      expect(res.body.user).toHaveProperty('id');
      expect(res.body.user.email).toBe('test@securityscanner.local');
      expect(res.body.user.name).toBe('Test Admin');
      expect(res.body.user.role).toBe('admin');
      expect(res.body.token).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/); // JWT format
    });
  });

  describe('GET /api/auth/me', () => {
    it('should return 401 without token', async () => {
      const res = await request(app).get('/api/auth/me');
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('No token provided');
    });

    it('should return 401 with invalid token', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer invalid-token-here');

      expect(res.status).toBe(401);
    });

    it('should return user profile with valid token', async () => {
      // First login to get a token
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({ email: 'test@securityscanner.local', password: 'Test@123456' });

      const token = loginRes.body.token;

      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.email).toBe('test@securityscanner.local');
      expect(res.body.name).toBe('Test Admin');
      expect(res.body).not.toHaveProperty('password');
    });
  });
});
