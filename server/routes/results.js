const express = require('express');
const db = require('../config/db');

const router = express.Router();

// IMPORTANT: Literal routes must come BEFORE parameterized routes
// to avoid Express matching 'ignored' as ':id'

// GET /api/results/ignored?scanId=xxx&page=1&limit=50
// List all ignored vulnerabilities, optionally filtered by scan
router.get('/ignored', (req, res) => {
  const { scanId, page, limit } = req.query;
  const p = parseInt(page) || 1;
  const l = parseInt(limit) || 50;
  const offset = (p - 1) * l;

  let query;
  let countQuery;

  if (scanId) {
    query = 'SELECT v.*, s.target_url FROM vulnerabilities v JOIN scans s ON v.scan_id = s.id WHERE v.ignored = 1 AND v.scan_id = ? ORDER BY v.created_at DESC LIMIT ? OFFSET ?';
    countQuery = 'SELECT COUNT(*) as count FROM vulnerabilities WHERE ignored = 1 AND scan_id = ?';
  } else {
    query = 'SELECT v.*, s.target_url FROM vulnerabilities v JOIN scans s ON v.scan_id = s.id WHERE v.ignored = 1 ORDER BY v.created_at DESC LIMIT ? OFFSET ?';
    countQuery = 'SELECT COUNT(*) as count FROM vulnerabilities WHERE ignored = 1';
  }

  const vulnerabilities = scanId
    ? db.prepare(query).all(scanId, l, offset)
    : db.prepare(query).all(l, offset);
  const total = scanId
    ? db.prepare(countQuery).get(scanId)
    : db.prepare(countQuery).get();
  const totalCount = total ? total.count : 0;

  res.json({
    vulnerabilities,
    total: totalCount,
    page: p,
    limit: l,
    pages: Math.ceil(totalCount / l) || 1,
  });
});

// PUT /api/results/:scanId/vulnerabilities/:vulnId/ignore
// Mark a vulnerability as ignored (false positive / won't fix)
router.put('/:scanId/vulnerabilities/:vulnId/ignore', (req, res) => {
  const { scanId, vulnId } = req.params;
  const { reason } = req.body;

  const vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = ? AND scan_id = ?').get(vulnId, scanId);
  if (!vuln) return res.status(404).json({ error: 'Vulnerability not found' });

  db.prepare('UPDATE vulnerabilities SET ignored = 1, ignored_reason = ? WHERE id = ?')
    .run(reason || 'Marked as ignored', vulnId);
  db.save();

  res.json({ success: true, message: 'Vulnerability ignored', id: parseInt(vulnId) });
});

// PUT /api/results/:scanId/vulnerabilities/:vulnId/unignore
// Unmark a previously ignored vulnerability
router.put('/:scanId/vulnerabilities/:vulnId/unignore', (req, res) => {
  const { scanId, vulnId } = req.params;

  const vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = ? AND scan_id = ?').get(vulnId, scanId);
  if (!vuln) return res.status(404).json({ error: 'Vulnerability not found' });

  db.prepare('UPDATE vulnerabilities SET ignored = 0, ignored_reason = NULL WHERE id = ?').run(vulnId);
  db.save();

  res.json({ success: true, message: 'Vulnerability restored', id: parseInt(vulnId) });
});

// GET /api/results/:id — Get scan results by scan ID
router.get('/:id', (req, res) => {
  const { id } = req.params;
  
  const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const vulnerabilities = db.prepare(
    'SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY CASE severity WHEN \'critical\' THEN 0 WHEN \'high\' THEN 1 WHEN \'medium\' THEN 2 WHEN \'low\' THEN 3 ELSE 4 END'
  ).all(id);

  const logs = db.prepare(
    'SELECT * FROM scan_logs WHERE scan_id = ? ORDER BY created_at ASC'
  ).all(id);

  res.json({ scan, vulnerabilities, logs });
});

// GET /api/results/:id/summary — Get scan summary
router.get('/:id/summary', (req, res) => {
  const { id } = req.params;

  const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const severityBreakdown = db.prepare(`
    SELECT severity, COUNT(*) as count FROM vulnerabilities 
    WHERE scan_id = ? GROUP BY severity
  `).all(id);

  const typeBreakdown = db.prepare(`
    SELECT type, COUNT(*) as count FROM vulnerabilities 
    WHERE scan_id = ? GROUP BY type
  `).all(id);

  res.json({ scan, severityBreakdown, typeBreakdown });
});

module.exports = router;
