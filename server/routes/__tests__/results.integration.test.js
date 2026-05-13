const express = require('express');
const request = require('supertest');
const path = require('path');
const fs = require('fs');

process.env.JWT_SECRET = 'test-secret-key';

const TEST_DB_PATH = path.resolve(__dirname, '..', '..', '..', 'database', 'test-results.db');
process.env.DB_PATH = TEST_DB_PATH;

try { fs.unlinkSync(TEST_DB_PATH); } catch {}

const db = require('../../config/db');

describe('Results API Integration — Ignore Feature', () => {
  let app;
  let scanId;

  beforeAll(async () => {
    await db.init();

    app = express();
    app.use(express.json());
    app.set('io', null);
    app.use('/api/results', require('../results'));

    // Insert a test scan and vulnerability
    scanId = 'test-scan-ignore-001';
    db.prepare(
      'INSERT OR REPLACE INTO scans (id, target_url, status) VALUES (?, ?, ?)'
    ).run(scanId, 'https://test-ignore.example.com', 'completed');
    db.save();

    // Insert a test vulnerability
    db.prepare(`
      INSERT OR REPLACE INTO vulnerabilities (id, scan_id, type, severity, title, description, endpoint, payload, remediation)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(1, scanId, 'sqli', 'high', 'Test SQLi', 'A test vulnerability', '/test', "' OR 1=1--", 'Use parameterized queries');
    db.save();
  });

  afterAll(() => {
    try { fs.unlinkSync(TEST_DB_PATH); } catch {}
  });

  describe('PUT /api/results/:scanId/vulnerabilities/:vulnId/ignore', () => {
    it('should mark a vulnerability as ignored', async () => {
      const res = await request(app)
        .put(`/api/results/${scanId}/vulnerabilities/1/ignore`)
        .send({ reason: 'False positive - test environment' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toContain('ignored');

      // Verify in DB
      const vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = 1').get();
      expect(vuln.ignored).toBe(1);
      expect(vuln.ignored_reason).toBe('False positive - test environment');
    });

    it('should return 404 for non-existent vulnerability', async () => {
      const res = await request(app)
        .put(`/api/results/${scanId}/vulnerabilities/999/ignore`)
        .send({ reason: 'test' });

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Vulnerability not found');
    });

    it('should use default reason when none provided', async () => {
      // Insert another vuln
      db.prepare(`
        INSERT OR REPLACE INTO vulnerabilities (id, scan_id, type, severity, title, description, endpoint, payload, remediation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(2, scanId, 'xss', 'medium', 'Test XSS', 'XSS test', '/test2', '<script>', 'Sanitize input');
      db.save();

      const res = await request(app)
        .put(`/api/results/${scanId}/vulnerabilities/2/ignore`)
        .send({});

      expect(res.status).toBe(200);
      const vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = 2').get();
      expect(vuln.ignored).toBe(1);
      expect(vuln.ignored_reason).toBe('Marked as ignored');
    });
  });

  describe('PUT /api/results/:scanId/vulnerabilities/:vulnId/unignore', () => {
    it('should restore a previously ignored vulnerability', async () => {
      const res = await request(app)
        .put(`/api/results/${scanId}/vulnerabilities/1/unignore`)
        .send();

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toContain('restored');

      // Verify in DB
      const vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = 1').get();
      expect(vuln.ignored).toBe(0);
      expect(vuln.ignored_reason).toBeNull();
    });

    it('should return 404 for non-existent vulnerability', async () => {
      const res = await request(app)
        .put(`/api/results/${scanId}/vulnerabilities/999/unignore`);

      expect(res.status).toBe(404);
    });
  });

  describe('GET /api/results/ignored', () => {
    it('should return ignored vulnerabilities list', async () => {
      // Ensure vuln 2 is still ignored
      db.prepare('UPDATE vulnerabilities SET ignored = 1, ignored_reason = "test ignore" WHERE id = 2').run();
      db.save();

      const res = await request(app)
        .get('/api/results/ignored')
        .query({ scanId });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('vulnerabilities');
      expect(res.body).toHaveProperty('total');
      expect(res.body.total).toBeGreaterThanOrEqual(1);
    });

    it('should return empty list when no vulns ignored', async () => {
      // Restore all
      db.prepare('UPDATE vulnerabilities SET ignored = 0, ignored_reason = NULL').run();
      db.save();

      const res = await request(app)
        .get('/api/results/ignored');

      expect(res.status).toBe(200);
      expect(res.body.total).toBe(0);
      expect(res.body.vulnerabilities.length).toBe(0);
    });

    it('should return paginated results', async () => {
      const res = await request(app)
        .get('/api/results/ignored')
        .query({ page: 1, limit: 10 });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('page', 1);
      expect(res.body).toHaveProperty('limit', 10);
      expect(res.body).toHaveProperty('pages');
    });
  });
});
