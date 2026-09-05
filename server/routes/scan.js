const express = require('express');
const db = require('../config/db');
const { sanitizeUrl, generateId, calculateRiskScore } = require('../utils/helpers');
const { runNextBatch, cancelScan, scannerModules } = require('../../scanner-engine/index');
const { scanLimiter } = require('../middleware/rateLimiter');
const { optionalAuth, authenticate } = require('../middleware/auth');

const router = express.Router();

function makeCallbacks(req, socketId) {
  const io = req.app.get('io');

  const onProgress = (id, progress, eta) => {
    db.prepare('UPDATE scans SET progress = ? WHERE id = ?').run(progress, id);
    if (io) io.to(socketId).emit('scan:progress', { scanId: id, progress, eta });
  };

  const onLog = (id, level, message, module) => {
    db.prepare('INSERT INTO scan_logs (scan_id, level, message, module) VALUES (?, ?, ?, ?)').run(id, level, message, module || 'engine');
    if (io) io.to(socketId).emit('scan:log', { scanId: id, level, message, module: module || 'engine', timestamp: new Date().toISOString() });
  };

  const onComplete = (id, vulnerabilities, cancelled = false) => {
    const status = cancelled ? 'cancelled' : 'completed';
    let counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let total = vulnerabilities ? vulnerabilities.length : 0;
    let riskScore = 0;

    try {
      const rows = db.prepare('SELECT severity, COUNT(*) as c FROM vulnerabilities WHERE scan_id = ? GROUP BY severity').all(id);
      for (const r of rows) {
        if (counts[r.severity] !== undefined) { counts[r.severity] = r.c; }
      }
      const totalRow = db.prepare('SELECT COUNT(*) as c FROM vulnerabilities WHERE scan_id = ?').get(id);
      total = totalRow ? totalRow.c : total;
      const stored = db.prepare('SELECT severity FROM vulnerabilities WHERE scan_id = ?').all(id).map(r => ({ severity: r.severity }));
      riskScore = calculateRiskScore(stored);
    } catch (e) { /* counts fall back to engine array */ }

    db.prepare(`
      UPDATE scans SET 
        status = ?, progress = 100, risk_score = ?,
        total_vulnerabilities = ?, critical_count = ?, high_count = ?,
        medium_count = ?, low_count = ?, info_count = ?,
        completed_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(status, riskScore, total, counts.critical, counts.high, counts.medium, counts.low, counts.info, id);

    try { db.save(); } catch {}

    if (io) {
      io.to(socketId).emit(cancelled ? 'scan:cancelled' : 'scan:complete', {
        scanId: id,
        vulnerabilities: vulnerabilities,
        counts,
        riskScore,
      });
    }
  };

  const insertVuln = db.prepare(`
    INSERT INTO vulnerabilities (scan_id, type, severity, title, description, endpoint, parameter, payload, evidence, remediation, owasp_category, cve_id, confidence, module)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const onModuleResult = (id, moduleKey, results) => {
    db.prepare("INSERT INTO scan_metadata (scan_id, key, value) VALUES (?, 'done:' || ?, '1')").run(id, moduleKey);
    const created = [];
    for (const v of (results || [])) {
      try {
        insertVuln.run(id, v.type, v.severity, v.title, v.description, v.endpoint, v.parameter, v.payload, v.evidence, v.remediation, v.owasp_category, v.cve_id, v.confidence || 'confirmed', v.module || moduleKey);
        created.push(v);
      } catch (e) {}
    }
    try { db.save(); } catch {}
  };

  return { onProgress, onLog, onComplete, onModuleResult };
}

router.post('/', scanLimiter, optionalAuth, async (req, res) => {
  let { url, modules: requestedModules } = req.body;
  if (!url) return res.status(400).json({ error: 'Target URL is required' });

  url = sanitizeUrl(url);
  if (!url) return res.status(400).json({ error: 'Invalid URL format' });

  const scanId = generateId();
  const socketId = req.body.socketId;

  db.prepare(`
    INSERT INTO scans (id, target_url, status, user_id)
    VALUES (?, ?, 'running', ?)
  `).run(scanId, url, req.user?.id || null);

  if (requestedModules && requestedModules.length > 0) {
    db.prepare(`
      INSERT INTO scan_metadata (scan_id, key, value)
      VALUES (?, 'requestedModules', ?)
    `).run(scanId, JSON.stringify(requestedModules));
  }
  db.save();

  res.json({ scanId, targetUrl: url, status: 'running' });
});

router.post('/:id/step', optionalAuth, async (req, res) => {
  const { id } = req.params;

  let scan;
  try {
    scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(id);
  } catch (e) {
    return res.status(500).json({ error: 'Could not load scan' });
  }
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  if (scan.status !== 'running') {
    return res.json({ scanId: id, status: scan.status, progress: scan.progress ?? 100, done: true });
  }

  try {
    let requestedModules = null;
    const meta = db.prepare("SELECT value FROM scan_metadata WHERE scan_id = ? AND key = 'requestedModules'").get(id);
    if (meta && meta.value) {
      try { requestedModules = JSON.parse(meta.value); } catch (e) { requestedModules = null; }
    }

    const doneKeys = db.prepare("SELECT key FROM scan_metadata WHERE scan_id = ? AND key LIKE 'done:%'").all(id)
      .map(r => r.key.replace('done:', ''));

    const callbacks = makeCallbacks(req, req.body?.socketId || null);
    const { finished, cancelled, currentModule } = await runNextBatch(id, scan.target_url, callbacks.onProgress, callbacks.onLog, callbacks.onComplete, requestedModules, doneKeys, callbacks.onModuleResult);
    const updated = db.prepare('SELECT status, progress FROM scans WHERE id = ?').get(id);
    res.json({
      scanId: id,
      status: cancelled ? 'cancelled' : (updated ? updated.status : 'running'),
      progress: updated ? (updated.progress ?? 0) : 0,
      done: finished || cancelled,
      currentModule: currentModule || null,
    });
  } catch (e) {
    res.status(500).json({ error: 'Scan step failed: ' + e.message });
  }
});

router.post('/:id/cancel', authenticate, (req, res) => {
  const { id } = req.params;
  const scan = db.prepare('SELECT id, status FROM scans WHERE id = ?').get(id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  if (scan.status !== 'running') return res.status(400).json({ error: 'Scan is not running' });

  cancelScan(id);
  db.prepare("UPDATE scans SET status = 'cancelled', progress = 100 WHERE id = ?").run(id);
  db.save();

  const io = req.app.get('io');
  if (io) io.emit('scan:cancelled', { scanId: id });

  res.json({ success: true, message: 'Scan cancelled' });
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

router.get('/:id/status', (req, res) => {
  const { id } = req.params;

  let scan;
  try {
    scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(id);
  } catch (e) {
    return res.status(500).json({ error: 'Could not load scan' });
  }
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  let logs = [];
  try {
    logs = db.prepare('SELECT level, message, module, created_at AS timestamp FROM scan_logs WHERE scan_id = ? ORDER BY id ASC LIMIT 500').all(id);
  } catch (e) {}

  let vulnerabilities = [];
  if (scan.status === 'completed') {
    try {
      vulnerabilities = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(id);
    } catch (e) {}
  }

  const counts = (() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const v of vulnerabilities) { if (c[v.severity] !== undefined) c[v.severity]++; }
    return c;
  })();

  res.json({
    id,
    status: scan.status,
    progress: scan.progress ?? (scan.status === 'completed' ? 100 : 0),
    total_vulnerabilities: vulnerabilities.length,
    risk_score: scan.risk_score || 0,
    counts,
    logs,
    vulnerabilities: scan.status === 'completed' ? vulnerabilities : [],
    scan: {
      target_url: scan.target_url,
      created_at: scan.created_at,
      completed_at: scan.completed_at,
    },
  });
});

module.exports = router;
