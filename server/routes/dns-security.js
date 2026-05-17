const express = require('express');
const { analyzeDNS, scanDNS } = require('../../scanner-engine/dns-security');
const { authenticate } = require('../middleware/auth');
const db = require('../config/db');

const router = express.Router();

router.get('/analyze', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Domain query parameter required' });

  try {
    const result = await analyzeDNS(domain);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/records', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Domain query parameter required' });

  try {
    const result = await scanDNS(domain);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/save', authenticate, async (req, res) => {
  const { scanId, domain, hasSpf, hasDkim, hasDmarc, hasDnssec, securityScore, issues, recommendations } = req.body;
  if (!scanId || !domain) return res.status(400).json({ error: 'scanId and domain required' });

  try {
    db.prepare('INSERT INTO dns_security (scan_id, domain, has_spf, has_dkim, has_dmarc, has_dnssec, security_score, issues, recommendations) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(scanId, domain, hasSpf ? 1 : 0, hasDkim ? 1 : 0, hasDmarc ? 1 : 0, hasDnssec ? 1 : 0, securityScore, JSON.stringify(issues || []), JSON.stringify(recommendations || []));
    db.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/history/:scanId', (req, res) => {
  const results = db.prepare('SELECT * FROM dns_security WHERE scan_id = ? ORDER BY created_at DESC').all(req.params.scanId);
  res.json({ results });
});

module.exports = router;
