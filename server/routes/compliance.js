const express = require('express');
const db = require('../config/db');
const { generateComplianceReport, getFrameworkSummary, COMPLIANCE_FRAMEWORKS } = require('../../scanner-engine/compliance');

const router = express.Router();

router.get('/frameworks', (req, res) => {
  res.json({
    frameworks: Object.entries(COMPLIANCE_FRAMEWORKS).map(([key, val]) => ({
      id: key, name: val.name, version: val.version,
    })),
  });
});

router.post('/analyze/:scanId', (req, res) => {
  const { framework } = req.body;
  const scanId = req.params.scanId;

  const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const vulnerabilities = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scanId);
  if (!vulnerabilities || vulnerabilities.length === 0) {
    return res.json({ message: 'No vulnerabilities to analyze', framework, totalFindings: 0, mappings: [] });
  }

  if (framework && COMPLIANCE_FRAMEWORKS[framework]) {
    const report = generateComplianceReport(vulnerabilities, framework);
    return res.json({ ...report, scanTarget: scan.target_url });
  }

  const summaries = getFrameworkSummary(vulnerabilities);
  res.json({ scanTarget: scan.target_url, frameworks: summaries });
});

module.exports = router;
