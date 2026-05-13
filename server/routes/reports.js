const express = require('express');
const path = require('path');
const db = require('../config/db');
const { generatePDFReport, generateJSONReport } = require('../../reports/index');
const { generateId } = require('../utils/helpers');
const { optionalAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/', (req, res) => {
  const reports = db.prepare(`
    SELECT r.*, s.target_url 
    FROM reports r 
    JOIN scans s ON r.scan_id = s.id 
    ORDER BY r.created_at DESC LIMIT 50
  `).all();
  res.json(reports);
});

router.get('/:id', (req, res) => {
  const report = db.prepare('SELECT r.*, s.target_url FROM reports r JOIN scans s ON r.scan_id = s.id WHERE r.id = ?').get(req.params.id);
  if (!report) return res.status(404).json({ error: 'Report not found' });
  res.json(report);
});

router.get('/:id/download', (req, res) => {
  const report = db.prepare('SELECT * FROM reports WHERE id = ?').get(req.params.id);
  if (!report) return res.status(404).json({ error: 'Report not found' });

  const filePath = path.resolve(report.file_path);
  if (report.format === 'pdf') {
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${path.basename(filePath)}"`);
  } else {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${path.basename(filePath)}"`);
  }
  res.sendFile(filePath);
});

router.post('/generate/:scanId', optionalAuth, async (req, res) => {
  const { scanId } = req.params;
  const { format } = req.body;

  const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const vulnerabilities = db.prepare(
    'SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity'
  ).all(scanId);

  const reportId = generateId();
  let filePath;

  try {
    if (format === 'pdf') {
      filePath = await generatePDFReport(scan, vulnerabilities, reportId);
    } else {
      filePath = await generateJSONReport(scan, vulnerabilities, reportId);
    }

    db.prepare(
      'INSERT INTO reports (id, scan_id, format, file_path) VALUES (?, ?, ?, ?)'
    ).run(reportId, scanId, format || 'json', filePath);

    res.json({ reportId, format: format || 'json', filePath, message: 'Report generated successfully' });
  } catch (err) {
    res.status(500).json({ error: `Report generation failed: ${err.message}` });
  }
});

module.exports = router;
