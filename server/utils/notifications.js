const axios = require('axios');
const db = require('../config/db');

async function sendNotification(type, config, payload) {
  switch (type) {
    case 'slack': return sendSlack(config, payload);
    case 'discord': return sendDiscord(config, payload);
    case 'email': return sendEmail(config, payload);
    case 'webhook': return sendWebhook(config, payload);
    default: throw new Error(`Unknown notification type: ${type}`);
  }
}

async function sendSlack(config, payload) {
  if (!config.webhookUrl) throw new Error('Slack webhook URL required');
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: `Scan Complete: ${payload.targetUrl}` } },
    { type: 'section', fields: [
      { type: 'mrkdwn', text: `*Risk Score:* ${payload.riskScore}/100` },
      { type: 'mrkdwn', text: `*Vulnerabilities:* ${payload.totalVulns}` },
    ]},
    { type: 'section', fields: [
      { type: 'mrkdwn', text: `*Critical:* ${payload.critical || 0}` },
      { type: 'mrkdwn', text: `*High:* ${payload.high || 0}` },
      { type: 'mrkdwn', text: `*Medium:* ${payload.medium || 0}` },
      { type: 'mrkdwn', text: `*Low:* ${payload.low || 0}` },
    ]},
  ];

  if (payload.topFindings && payload.topFindings.length > 0) {
    const findings = payload.topFindings.slice(0, 3).map(f =>
      `• [${f.severity.toUpperCase()}] ${f.title}`
    ).join('\n');
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `*Top Findings:*\n${findings}` } });
  }

  blocks.push({ type: 'actions', elements: [
    { type: 'button', text: { type: 'plain_text', text: 'View Report' }, url: payload.reportUrl || config.baseUrl + '/#history', style: 'primary' },
  ]});

  return axios.post(config.webhookUrl, { blocks }, {
    timeout: 10000,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function sendDiscord(config, payload) {
  if (!config.webhookUrl) throw new Error('Discord webhook URL required');

  const color = payload.riskScore > 50 ? 0xff0044 : payload.riskScore > 25 ? 0xff6600 : 0x00cc66;
  const embed = {
    title: `Scan Complete: ${payload.targetUrl}`,
    color,
    fields: [
      { name: 'Risk Score', value: `${payload.riskScore}/100`, inline: true },
      { name: 'Total Vulnerabilities', value: String(payload.totalVulns), inline: true },
      { name: 'Critical', value: String(payload.critical || 0), inline: true },
      { name: 'High', value: String(payload.high || 0), inline: true },
      { name: 'Medium', value: String(payload.medium || 0), inline: true },
      { name: 'Low/Info', value: String((payload.low || 0) + (payload.info || 0)), inline: true },
    ],
    timestamp: new Date().toISOString(),
    footer: { text: 'Web Security Scanner' },
  };

  if (payload.topFindings && payload.topFindings.length > 0) {
    embed.fields.push({
      name: 'Top Findings',
      value: payload.topFindings.slice(0, 3).map(f => `[${f.severity.toUpperCase()}] ${f.title}`).join('\n'),
    });
  }

  return axios.post(config.webhookUrl, { embeds: [embed] }, {
    timeout: 10000,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function sendEmail(config, payload) {
  if (!config.smtpHost || !config.smtpPort) throw new Error('SMTP configuration required');
  let nodemailer;
  try {
    nodemailer = require('nodemailer');
  } catch {
    throw new Error('nodemailer not installed — run: npm install nodemailer');
  }

  const transporter = nodemailer.createTransport({
    host: config.smtpHost,
    port: parseInt(config.smtpPort),
    secure: config.smtpSecure === 'true',
    auth: config.smtpUser ? { user: config.smtpUser, pass: config.smtpPass } : undefined,
  });

  const severityList = payload.topFindings && payload.topFindings.length > 0
    ? payload.topFindings.slice(0, 5).map(f =>
        `<tr><td>${f.severity.toUpperCase()}</td><td>${f.title}</td></tr>`
      ).join('')
    : '';

  const html = `
    <h2>Scan Complete: ${payload.targetUrl}</h2>
    <p>Risk Score: <strong>${payload.riskScore}/100</strong></p>
    <p>Total Vulnerabilities: <strong>${payload.totalVulns}</strong></p>
    <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;margin:10px 0">
      <tr><th>Severity</th><th>Count</th></tr>
      <tr><td style="color:red">Critical</td><td>${payload.critical || 0}</td></tr>
      <tr><td style="color:orange">High</td><td>${payload.high || 0}</td></tr>
      <tr><td style="color:gold">Medium</td><td>${payload.medium || 0}</td></tr>
      <tr><td>Low</td><td>${payload.low || 0}</td></tr>
    </table>
    ${severityList ? `<h3>Top Findings</h3><table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse">${severityList}</table>` : ''}
    <p><a href="${config.baseUrl || 'http://localhost:3000'}">View Full Report</a></p>
  `;

  return transporter.sendMail({
    from: config.fromEmail || 'scanner@localhost',
    to: config.toEmail,
    subject: `Scan Complete: ${payload.targetUrl} — Risk Score: ${payload.riskScore}/100`,
    html,
  });
}

async function sendWebhook(config, payload) {
  if (!config.webhookUrl) throw new Error('Webhook URL required');
  return axios.post(config.webhookUrl, {
    event: 'scan.complete',
    timestamp: new Date().toISOString(),
    data: payload,
  }, {
    timeout: 10000,
    headers: { 'Content-Type': 'application/json', ...(config.customHeaders || {}) },
  });
}

function getWebhookConfigs() {
  try {
    return db.prepare('SELECT * FROM webhook_configs ORDER BY created_at DESC').all() || [];
  } catch { return []; }
}

function saveWebhookConfig(config) {
  const existing = db.prepare('SELECT id FROM webhook_configs WHERE type = ? AND name = ?').get(config.type, config.name);
  if (existing) {
    db.prepare('UPDATE webhook_configs SET webhook_url = ?, config_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(config.webhookUrl, JSON.stringify(config), existing.id);
  } else {
    db.prepare('INSERT INTO webhook_configs (type, name, webhook_url, config_json) VALUES (?, ?, ?, ?)')
      .run(config.type, config.name, config.webhookUrl, JSON.stringify(config));
  }
  db.save();
  return { success: true };
}

function deleteWebhookConfig(id) {
  db.prepare('DELETE FROM webhook_configs WHERE id = ?').run(id);
  db.save();
  return { success: true };
}

async function testWebhook(type, config) {
  const testPayload = {
    targetUrl: 'https://test.example.com',
    riskScore: 42,
    totalVulns: 3,
    critical: 1, high: 1, medium: 1, low: 0, info: 0,
    topFindings: [
      { severity: 'critical', title: 'Test finding 1' },
      { severity: 'high', title: 'Test finding 2' },
    ],
    reportUrl: config.baseUrl || 'http://localhost:3000',
  };

  try {
    await sendNotification(type, config, testPayload);
    return { success: true, message: 'Test notification sent successfully' };
  } catch (err) {
    return { success: false, message: err.message };
  }
}

module.exports = { sendNotification, getWebhookConfigs, saveWebhookConfig, deleteWebhookConfig, testWebhook };
