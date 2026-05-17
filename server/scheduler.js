const db = require('./config/db');
const { runScan } = require('../scanner-engine/index');
const { sendNotification } = require('./utils/notifications');

const scheduledScans = new Map();
let schedulerInterval = null;

function initScheduler() {
  const configs = db.prepare('SELECT * FROM scheduled_scans WHERE enabled = 1').all() || [];
  for (const config of configs) {
    scheduleScan(config);
  }

  if (schedulerInterval) clearInterval(schedulerInterval);
  schedulerInterval = setInterval(checkScheduledScans, 30000);

  return { active: configs.length };
}

function scheduleScan(config) {
  const existing = scheduledScans.get(config.id);
  if (existing) clearTimeout(existing.timeout);
  scheduledScans.set(config.id, { config, nextRun: calculateNextRun(config.interval, config.last_run) });
}

function calculateNextRun(interval, lastRun) {
  const intervals = {
    hourly: 3600000,
    daily: 86400000,
    weekly: 604800000,
    biweekly: 1209600000,
    monthly: 2592000000,
  };
  const ms = intervals[interval] || 86400000;
  const last = lastRun ? new Date(lastRun).getTime() : 0;
  const next = Math.max(last + ms, Date.now());
  return next;
}

function checkScheduledScans() {
  const now = Date.now();
  for (const [id, entry] of scheduledScans) {
    if (entry.nextRun <= now) {
      executeScheduledScan(entry.config).catch(err => console.error('[Scheduler] Scan failed:', err.message));
      entry.lastRun = now;
      entry.nextRun = calculateNextRun(entry.config.interval, new Date(now).toISOString());
      db.prepare('UPDATE scheduled_scans SET last_run = CURRENT_TIMESTAMP WHERE id = ?').run(id);
      db.save();
    }
  }
}

async function executeScheduledScan(config) {
  const { generateId, sanitizeUrl } = require('./utils/helpers');
  const scanId = generateId();

  db.prepare(`
    INSERT INTO scans (id, target_url, status, user_id)
    VALUES (?, ?, 'running', ?)
  `).run(scanId, config.target_url, config.user_id || null);
  db.save();

  const io = null;
  const notifications = [];

  const onProgress = () => {};
  const onLog = () => {};
  const onComplete = async (id, vulnerabilities, cancelled) => {
    const { severityCounts, calculateRiskScore } = require('./utils/helpers');
    const counts = severityCounts(vulnerabilities);
    const riskScore = calculateRiskScore(vulnerabilities);

    const insertVuln = db.prepare(`INSERT INTO vulnerabilities (scan_id, type, severity, title, description, endpoint, parameter, payload, evidence, remediation, owasp_category, cve_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    for (const v of vulnerabilities) {
      try { insertVuln.run(id, v.type, v.severity, v.title, v.description, v.endpoint, v.parameter, v.payload, v.evidence, v.remediation, v.owasp_category, v.cve_id); } catch {}
    }

    const status = cancelled ? 'cancelled' : 'completed';
    db.prepare(`UPDATE scans SET status = ?, progress = 100, risk_score = ?, total_vulnerabilities = ?, critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, info_count = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?`).run(status, riskScore, vulnerabilities.length, counts.critical, counts.high, counts.medium, counts.low, counts.info, id);
    db.save();

    if (config.notify_types) {
      const types = config.notify_types.split(',');
      const payload = {
        targetUrl: config.target_url,
        riskScore, totalVulns: vulnerabilities.length,
        critical: counts.critical, high: counts.high, medium: counts.medium, low: counts.low, info: counts.info,
        topFindings: vulnerabilities.filter(v => v.severity === 'critical' || v.severity === 'high').slice(0, 5),
        reportUrl: `${process.env.BASE_URL || 'http://localhost:3000'}/#history`,
      };

      const webhookConfigs = db.prepare('SELECT * FROM webhook_configs WHERE enabled = 1').all() || [];
      for (const wc of webhookConfigs) {
        if (types.includes(wc.type)) {
          try {
            await sendNotification(wc.type, JSON.parse(wc.config_json || '{}'), payload);
          } catch (err) {
            console.error(`[Scheduler] Notification failed: ${err.message}`);
          }
        }
      }
    }
  };

  runScan(scanId, config.target_url, onProgress, onLog, onComplete, config.modules ? config.modules.split(',') : undefined);
}

function getScheduledScans() {
  return db.prepare('SELECT * FROM scheduled_scans ORDER BY created_at DESC').all() || [];
}

function addScheduledScan(config) {
  const { generateId } = require('./utils/helpers');
  const id = config.id || generateId();

  db.prepare(`
    INSERT INTO scheduled_scans (id, name, target_url, interval, modules, notify_types, user_id, enabled)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
  `).run(id, config.name, config.target_url, config.interval, config.modules || '', config.notify_types || '', config.user_id || null);
  db.save();

  scheduleScan({ id, ...config });
  return { id, success: true };
}

function removeScheduledScan(id) {
  scheduledScans.delete(id);
  db.prepare('DELETE FROM scheduled_scans WHERE id = ?').run(id);
  db.save();
  return { success: true };
}

function updateScheduledScan(id, updates) {
  const fields = [];
  const values = [];
  for (const [key, val] of Object.entries(updates)) {
    if (['name', 'target_url', 'interval', 'modules', 'notify_types', 'enabled'].includes(key)) {
      fields.push(`${key} = ?`);
      values.push(val);
    }
  }
  if (fields.length > 0) {
    values.push(id);
    db.prepare(`UPDATE scheduled_scans SET ${fields.join(', ')} WHERE id = ?`).run(...values);
    db.save();
  }
  const config = { id, ...updates };
  scheduleScan(config);
  return { success: true };
}

module.exports = { initScheduler, getScheduledScans, addScheduledScan, removeScheduledScan, updateScheduledScan };
