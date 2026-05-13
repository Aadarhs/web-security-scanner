const express = require('express');
const db = require('../config/db');
const fs = require('fs');
const path = require('path');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

function adminAuth(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

router.get('/modules', authenticate, adminAuth, (req, res) => {
  const scannerPath = path.join(__dirname, '..', '..', 'scanner-engine');
  const modules = [];
  try {
    const files = fs.readdirSync(scannerPath);
    for (const file of files) {
      if (file.endsWith('.js') && file !== 'index.js' && file !== 'ai-analyzer.js' && file !== 'api-integration.js') {
        const stats = fs.statSync(path.join(scannerPath, file));
        modules.push({
          file,
          name: file.replace('.js', ''),
          size: stats.size,
          modified: stats.mtime,
        });
      }
    }
  } catch {}
  res.json({ modules, total: modules.length });
});

router.get('/modules/:name', authenticate, adminAuth, (req, res) => {
  const scannerPath = path.join(__dirname, '..', '..', 'scanner-engine');
  const filePath = path.join(scannerPath, req.params.name + '.js');

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Module not found' });
  }

  const content = fs.readFileSync(filePath, 'utf8');
  res.json({ name: req.params.name, content, size: content.length });
});

router.put('/modules/:name', authenticate, adminAuth, (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'Content is required' });

  const scannerPath = path.join(__dirname, '..', '..', 'scanner-engine');
  const filePath = path.join(scannerPath, req.params.name + '.js');

  try {
    fs.writeFileSync(filePath, content, 'utf8');
    res.json({ success: true, message: 'Module updated. Restart the server for changes to take effect.' });
  } catch (err) {
    res.status(500).json({ error: `Failed to update module: ${err.message}` });
  }
});

router.post('/modules/:name/test', authenticate, adminAuth, async (req, res) => {
  const { payload, endpoint } = req.body;
  if (!payload || !endpoint) {
    return res.status(400).json({ error: 'Payload and endpoint are required' });
  }

  try {
    const axios = require('axios');
    const response = await axios.get(endpoint, {
      timeout: 10000,
      headers: { 'User-Agent': 'WebSecurityScanner/1.0' },
      validateStatus: s => s < 500,
    });
    res.json({
      success: true,
      status: response.status,
      bodyLength: (typeof response.data === 'string' ? response.data : JSON.stringify(response.data)).length,
      headers: response.headers,
    });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

router.get('/stats', authenticate, adminAuth, (req, res) => {
  const totalScans = db.prepare('SELECT COUNT(*) as c FROM scans').get()?.c || 0;
  const totalVulns = db.prepare('SELECT COUNT(*) as c FROM vulnerabilities').get()?.c || 0;
  const totalUsers = db.prepare('SELECT COUNT(*) as c FROM users').get()?.c || 0;
  const totalReports = db.prepare('SELECT COUNT(*) as c FROM reports').get()?.c || 0;
  const dbSize = (() => { try { return fs.statSync(path.join(__dirname, '..', '..', 'database', 'scanner.db')).size; } catch { return 0; } })();
  const scansToday = db.prepare("SELECT COUNT(*) as c FROM scans WHERE date(created_at) = date('now')").get()?.c || 0;
  const scansByStatus = db.prepare("SELECT status, COUNT(*) as count FROM scans GROUP BY status").all();
  const topVulnTypes = db.prepare("SELECT type, COUNT(*) as count FROM vulnerabilities GROUP BY type ORDER BY count DESC LIMIT 10").all();
  const recentScans = db.prepare("SELECT id, target_url, status, created_at FROM scans ORDER BY created_at DESC LIMIT 5").all();

  res.json({
    totalScans, totalVulns, totalUsers, totalReports,
    dbSize, scansToday, scansByStatus, topVulnTypes, recentScans,
  });
});

router.get('/env', authenticate, adminAuth, (req, res) => {
  const safeKeys = ['PORT', 'NODE_ENV', 'SCAN_TIMEOUT', 'MAX_CONCURRENT_SCANS', 'AI_ANALYSIS_ENABLED', 'API_ENRICHMENT_ENABLED', 'LLM_ENABLED'];
  const env = {};
  for (const key of safeKeys) {
    env[key] = process.env[key] || 'Not set';
  }
  res.json(env);
});

module.exports = router;