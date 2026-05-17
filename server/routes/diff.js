const express = require('express');
const db = require('../config/db');

const router = express.Router();

router.get('/compare', (req, res) => {
  const { scanId1, scanId2 } = req.query;
  if (!scanId1 || !scanId2) {
    return res.status(400).json({ error: 'scanId1 and scanId2 query parameters required' });
  }

  const scan1 = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId1);
  const scan2 = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId2);

  if (!scan1) return res.status(404).json({ error: `Scan ${scanId1} not found` });
  if (!scan2) return res.status(404).json({ error: `Scan ${scanId2} not found` });

  const vulns1 = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scanId1) || [];
  const vulns2 = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scanId2) || [];

  const vulnKey = v => `${v.type}|${v.severity}|${v.endpoint || ''}|${v.title}`;
  const set1 = new Map(vulns1.map(v => [vulnKey(v), v]));
  const set2 = new Map(vulns2.map(v => [vulnKey(v), v]));

  const newFindings = [];
  const fixedFindings = [];
  const unchanged = [];

  for (const [key, vuln] of set2) {
    if (set1.has(key)) {
      unchanged.push(vuln);
    } else {
      newFindings.push(vuln);
    }
  }

  for (const [key, vuln] of set1) {
    if (!set2.has(key)) {
      fixedFindings.push(vuln);
    }
  }

  const riskChange = ((scan2.risk_score || 0) - (scan1.risk_score || 0)).toFixed(1);
  const vulnCount1 = vulns1.length;
  const vulnCount2 = vulns2.length;

  res.json({
    scan1: { id: scan1.id, targetUrl: scan1.target_url, date: scan1.created_at, riskScore: scan1.risk_score, totalVulns: vulnCount1 },
    scan2: { id: scan2.id, targetUrl: scan2.target_url, date: scan2.created_at, riskScore: scan2.risk_score, totalVulns: vulnCount2 },
    diff: {
      newFindings,
      fixedFindings,
      unchanged,
      newCount: newFindings.length,
      fixedCount: fixedFindings.length,
      unchangedCount: unchanged.length,
      riskChange: parseFloat(riskChange),
    },
  });
});

router.get('/history/:scanId', (req, res) => {
  const scan = db.prepare('SELECT id, target_url, created_at FROM scans WHERE id = ?').get(req.params.scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const sameTarget = db.prepare(
    'SELECT id, target_url, status, risk_score, total_vulnerabilities, created_at FROM scans WHERE target_url = ? AND id != ? ORDER BY created_at DESC LIMIT 10'
  ).all(scan.target_url, scan.id);

  res.json({ currentScan: scan, comparableScans: sameTarget });
});

module.exports = router;
