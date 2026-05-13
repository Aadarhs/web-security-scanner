const express = require('express');
const request = require('supertest');
const path = require('path');
const fs = require('fs');

// Set test env before requiring modules
process.env.JWT_SECRET = 'test-secret-key';

// Use a separate test database
const TEST_DB_PATH = path.resolve(__dirname, '..', '..', '..', 'database', 'test-scan.db');
process.env.DB_PATH = TEST_DB_PATH;

// Clean up any previous test DB
try { fs.unlinkSync(TEST_DB_PATH); } catch {}

const db = require('../../config/db');

describe('Scan API Integration', () => {
  let app;

  beforeAll(async () => {
    await db.init();
    db.save();

    app = express();
    app.use(express.json());

    // Mock socket.io on the app
    app.set('io', null);

    app.use('/api/scan', require('../scan'));
  });

  afterAll(() => {
    try { fs.unlinkSync(TEST_DB_PATH); } catch {}
  });

  describe('POST /api/scan', () => {
    it('should return 400 when URL is missing', async () => {
      const res = await request(app)
        .post('/api/scan')
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('URL is required');
    });

    it('should return 400 when URL is invalid', async () => {
      const res = await request(app)
        .post('/api/scan')
        .send({ url: 'not a valid url at all !!!' });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid URL');
    });

    it('should return scanId and status for valid URL', async () => {
      const res = await request(app)
        .post('/api/scan')
        .send({ url: 'https://example.com' });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('scanId');
      expect(res.body.targetUrl).toBe('https://example.com/');
      expect(res.body.status).toBe('running');
    });

    it('should accept http protocol', async () => {
      const res = await request(app)
        .post('/api/scan')
        .send({ url: 'http://example.com' });

      expect(res.status).toBe(200);
      expect(res.body.targetUrl).toBe('http://example.com/');
      expect(res.body.status).toBe('running');
    });

    it('should prepend https:// when no protocol is given', async () => {
      const res = await request(app)
        .post('/api/scan')
        .send({ url: 'example.com' });

      expect(res.status).toBe(200);
      expect(res.body.targetUrl).toBe('https://example.com/');
    });

    it('should accept optional modules array', async () => {
      const res = await request(app)
        .post('/api/scan')
        .send({ url: 'https://example.com', modules: ['sqli', 'xss'] });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('scanId');
      expect(res.body.status).toBe('running');
    });

    it('should create a scan record in the database', async () => {
      const res = await request(app)
        .post('/api/scan')
        .send({ url: 'https://test-scan-db.example.com' });

      expect(res.status).toBe(200);

      // Verify the scan record was created
      const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(res.body.scanId);
      expect(scan).toBeTruthy();
      expect(scan.target_url).toBe('https://test-scan-db.example.com/');
      expect(scan.status).toBe('running');
    });
  });

  describe('GET /api/scan/history', () => {
    it('should return paginated scan history', async () => {
      const res = await request(app).get('/api/scan/history');

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('scans');
      expect(res.body).toHaveProperty('total');
      expect(res.body).toHaveProperty('page');
      expect(res.body).toHaveProperty('pages');
      expect(Array.isArray(res.body.scans)).toBe(true);
    });

    it('should support pagination parameters', async () => {
      const res = await request(app)
        .get('/api/scan/history')
        .query({ page: 1, limit: 5 });

      expect(res.status).toBe(200);
      expect(res.body.page).toBe(1);
      expect(res.body.limit).toBe(5);
    });
  });

  describe('GET /api/scan/recent', () => {
    it('should return recent scans', async () => {
      const res = await request(app).get('/api/scan/recent');

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
    });

    it('should return at most 10 recent scans', async () => {
      const res = await request(app).get('/api/scan/recent');
      expect(res.body.length).toBeLessThanOrEqual(10);
    });
  });
});
