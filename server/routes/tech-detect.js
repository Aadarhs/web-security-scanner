const express = require('express');
const { scanTech } = require('../../scanner-engine/tech-detect');
const db = require('../config/db');
const axios = require('axios');

const router = express.Router();

const httpClient = axios.create({
  timeout: 15000,
  headers: { 'User-Agent': 'WebSecurityScanner/2.0' },
  maxRedirects: 5,
  validateStatus: s => s < 500,
});

router.post('/detect', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  try {
    const result = await scanTech(url, httpClient);
    const scanId = req.body.scanId || null;

    if (scanId && result.technologies.length > 0) {
      const insert = db.prepare('INSERT INTO tech_detections (scan_id, technology, category, confidence) VALUES (?, ?, ?, ?)');
      for (const tech of result.technologies) {
        try { insert.run(scanId, tech.name, tech.category, tech.confidence); } catch {}
      }
      try { db.save(); } catch {}
    }

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/history/:scanId', (req, res) => {
  const detections = db.prepare('SELECT * FROM tech_detections WHERE scan_id = ? ORDER BY created_at DESC').all(req.params.scanId);
  res.json({ technologies: detections });
});

module.exports = router;
