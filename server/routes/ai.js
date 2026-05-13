const express = require('express');
const db = require('../config/db');
const { calculateRiskScore } = require('../utils/helpers');
const { authenticate } = require('../middleware/auth');
const { generateAnalysis, generateRemediation } = require('../../scanner-engine/ai-analyzer');

const router = express.Router();

router.post('/analyze/:scanId', authenticate, async (req, res) => {
  const { scanId } = req.params;

  const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const vulnerabilities = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scanId);

  try {
    const analysis = await generateAnalysis(scan.target_url, scan.risk_score || 0, vulnerabilities);
    res.json({ scanId, analysis, generatedAt: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: `AI analysis failed: ${err.message}` });
  }
});

router.post('/remediate', authenticate, async (req, res) => {
  const { title, type, severity, description, remediation, owaspCategory } = req.body;
  if (!title) return res.status(400).json({ error: 'Vulnerability title is required' });

  try {
    const guide = await generateRemediation(title, type, severity, description, remediation, owaspCategory);
    res.json({ remediationGuide: guide, generatedAt: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: `Remediation generation failed: ${err.message}` });
  }
});

router.get('/status', (req, res) => {
  const enabled = process.env.AI_ANALYSIS_ENABLED === 'true';
  const provider = enabled ? (process.env.OPENAI_API_KEY ? 'openai' : process.env.OLLAMA_URL ? 'ollama' : 'local-fallback') : 'disabled';
  res.json({ enabled, provider });
});

module.exports = router;