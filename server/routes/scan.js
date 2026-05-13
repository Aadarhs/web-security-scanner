const express = require('express');
const db = require('../config/db');
const { sanitizeUrl, generateId, calculateRiskScore, severityCounts } = require('../utils/helpers');
const { runScan, scannerModules } = require('../../scanner-engine/index');
const { scanLimiter } = require('../middleware/rateLimiter');
const { optionalAuth } = require('../middleware/auth');

const router = express.Router();

router.post('/', scanLimiter, optionalAuth, async (req, res) => {
  let { url, modules: requestedModules } = req.body;
  if (!url) return res.status(400).json({ error: 'Target URL is required' });

  url = sanitizeUrl(url);
  if (!url) return res.status(400).json({ error: 'Invalid URL format' });

  const scanId = generateId();
  const io = req.app.get('io');
  const socketId = req.body.socketId;

  db.prepare(`
    INSERT INTO scans (id, target_url, status, user_id)
    VALUES (?, ?, 'running', ?)
  `).run(scanId, url, req.user?.id || null);
  db.save();

  res.json({ scanId, targetUrl: url, status: 'running' });

  if (io && socketId) {
    io.to(socketId).emit('scan:started', { scanId, targetUrl: url });
  }

  const onProgress = (id, progress) => {
    db.prepare('UPDATE scans SET progress = ? WHERE id = ?').run(progress, id);
    if (io) io.to(socketId).emit('scan:progress', { scanId: id, progress });
  };

  const onLog = (id, level, message, module) => {
    db.prepare('INSERT INTO scan_logs (scan_id, level, message, module) VALUES (?, ?, ?, ?)').run(id, level, message, module || 'engine');
    if (io) io.to(socketId).emit('scan:log', { scanId: id, level, message, module: module || 'engine', timestamp: new Date().toISOString() });
  };

  const onComplete = (id, vulnerabilities) => {
    const counts = severityCounts(vulnerabilities);
    const riskScore = calculateRiskScore(vulnerabilities);

    const insertVuln = db.prepare(`
      INSERT INTO vulnerabilities (scan_id, type, severity, title, description, endpoint, parameter, payload, evidence, remediation, owasp_category, cve_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const v of vulnerabilities) {
      try { insertVuln.run(id, v.type, v.severity, v.title, v.description, v.endpoint, v.parameter, v.payload, v.evidence, v.remediation, v.owasp_category, v.cve_id); } catch (e) { console.error('[Scan] Insert vuln error:', e); }
    }

    db.prepare(`
      UPDATE scans SET 
        status = 'completed', progress = 100, risk_score = ?,
        total_vulnerabilities = ?, critical_count = ?, high_count = ?,
        medium_count = ?, low_count = ?, info_count = ?,
        completed_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(riskScore, vulnerabilities.length, counts.critical, counts.high, counts.medium, counts.low, counts.info, id);

    try { db.save(); } catch {}

    if (io) {
      io.to(socketId).emit('scan:complete', {
        scanId: id,
        vulnerabilities: vulnerabilities,
        counts,
        riskScore,
      });
    }
  };

  setImmediate(() => {
    runScan(scanId, url, onProgress, onLog, onComplete, requestedModules);
  });
});

router.get('/history', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const offset = (page - 1) * limit;

  const scans = db.prepare(`
    SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?
  `).all(limit, offset);

  let total = 0;
  try {
    const row = db.prepare('SELECT COUNT(*) as count FROM scans').get();
    total = row ? row.count : 0;
  } catch {}
  
  res.json({ scans, total, page, limit, pages: Math.ceil(total / limit) || 1 });
});

router.get('/recent', (req, res) => {
  const scans = db.prepare(`
    SELECT id, target_url, status, risk_score, total_vulnerabilities, 
           critical_count, high_count, medium_count, low_count, info_count,
           created_at, completed_at
    FROM scans 
    ORDER BY created_at DESC LIMIT 10
  `).all();

  res.json(scans);
});

module.exports = router;
