const axios = require('axios');
const { scanSQLi } = require('./sqli');
const { scanXSS } = require('./xss');
const { scanCSRF } = require('./csrf');
const { scanHeaders } = require('./headers');
const { scanAuth } = require('./authCheck');
const { scanDirectory } = require('./directory');
const { scanCORS } = require('./cors');
const { scanOpenRedirect } = require('./openredirect');
const { scanLFI } = require('./lfi');
const { scanCMDI } = require('./cmdi');
const { scanSSRF } = require('./ssrf');
const { scanXXE } = require('./xxe');
const { scanNetwork } = require('./network');
const { scanServerStatus } = require('./serverStatus');
const { scanWebSocket } = require('./websocket-scanner');
const { scanGraphQL } = require('./graphql-scanner');
const { scanPassive } = require('./passive-scanner');
const { enrichVulnerabilities } = require('./api-integration');
const { generateAnalysis } = require('./ai-analyzer');

const scanQueue = [];
let activeScans = 0;
const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT_SCANS) || 3;
const scanCancelled = new Set();

const httpClient = axios.create({
  timeout: parseInt(process.env.SCAN_TIMEOUT) || 15000,
  headers: {
    'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0',
    'Accept': 'text/html,application/json,*/*',
  },
  maxRedirects: 5,
  validateStatus: status => status < 500,
});

const scannerModules = [
  { key: 'sqli', name: 'SQL Injection', module: scanSQLi, weight: 12 },
  { key: 'xss', name: 'Cross-Site Scripting (XSS)', module: scanXSS, weight: 12 },
  { key: 'csrf', name: 'CSRF', module: scanCSRF, weight: 6 },
  { key: 'headers', name: 'Security Headers', module: scanHeaders, weight: 6 },
  { key: 'auth', name: 'Authentication', module: scanAuth, weight: 8 },
  { key: 'directory', name: 'Sensitive File/Path Discovery', module: scanDirectory, weight: 10 },
  { key: 'cors', name: 'CORS Misconfiguration', module: scanCORS, weight: 6 },
  { key: 'openredirect', name: 'Open Redirect', module: scanOpenRedirect, weight: 5 },
  { key: 'lfi', name: 'Local File Inclusion', module: scanLFI, weight: 5 },
  { key: 'cmdi', name: 'Command Injection', module: scanCMDI, weight: 8 },
  { key: 'ssrf', name: 'Server-Side Request Forgery', module: scanSSRF, weight: 7 },
  { key: 'xxe', name: 'XML External Entity (XXE)', module: scanXXE, weight: 5 },
  { key: 'network', name: 'Network & SSL/TLS', module: scanNetwork, weight: 12 },
  { key: 'serverstatus', name: 'Server Status & Info', module: scanServerStatus, weight: 4 },
  { key: 'websocket', name: 'WebSocket Vulnerability Scan', module: scanWebSocket, weight: 6 },
  { key: 'graphql', name: 'GraphQL Injection Testing', module: scanGraphQL, weight: 6 },
  { key: 'passive', name: 'Passive Scan (No Active Probing)', module: scanPassive, weight: 4 },
];

const MODULE_BATCH_SIZE = parseInt(process.env.SCAN_MODULE_CONCURRENCY) || 2;

async function runScan(scanId, targetUrl, onProgress, onLog, onComplete, requestedModules) {
  onLog(scanId, 'info', `Initializing scan for ${targetUrl}`, 'engine');

  onLog(scanId, 'info', `Target resolved: ${targetUrl}`, 'engine');
  onLog(scanId, 'info', 'Starting vulnerability assessment...', 'engine');

  let modulesToRun = scannerModules;
  if (requestedModules && Array.isArray(requestedModules) && requestedModules.length > 0) {
    modulesToRun = scannerModules.filter(m => requestedModules.includes(m.key));
    onLog(scanId, 'info', `Loading ${modulesToRun.length} of ${scannerModules.length} selected scanner modules`, 'engine');
  } else {
    onLog(scanId, 'info', `Loading all ${scannerModules.length} scanner modules`, 'engine');
  }

  let completedWeight = 0;
  const totalWeight = modulesToRun.reduce((s, m) => s + m.weight, 0);
  const allVulnerabilities = [];
  const scanStartTime = Date.now();

  let passiveResponse = null;

  async function runSingleModule(mod) {
    if (scanCancelled.has(scanId)) return 'cancelled';

    onLog(scanId, 'info', `Running ${mod.name} scanner...`, mod.name);

    try {
      let results;
      if (mod.key === 'passive') {
        if (!passiveResponse) {
          try {
            passiveResponse = await httpClient.get(targetUrl, { timeout: 15000, validateStatus: s => s < 500 });
          } catch {
            passiveResponse = { data: '', headers: {} };
          }
        }
        results = await mod.module(targetUrl, passiveResponse);
      } else {
        results = await mod.module(targetUrl, httpClient);
      }

      if (results.length > 0) {
        onLog(scanId, 'warning', `${mod.name}: Found ${results.length} vulnerability(s)`, mod.name);
        for (const vuln of results) {
          allVulnerabilities.push(vuln);
          onLog(scanId, vuln.severity === 'critical' || vuln.severity === 'high' ? 'warning' : 'info',
            `[${vuln.severity.toUpperCase()}] ${vuln.title}`, mod.name);
        }
      } else {
        onLog(scanId, 'info', `${mod.name}: No vulnerabilities detected`, mod.name);
      }
    } catch (err) {
      onLog(scanId, 'error', `${mod.name} scanner failed: ${err.message}`, mod.name);
    }

    completedWeight += mod.weight;
    const pct = Math.min(Math.round((completedWeight / totalWeight) * 100), 100);
    const elapsed = Date.now() - scanStartTime;
    const remainingWeight = totalWeight - completedWeight;
    const eta = completedWeight > 0 ? Math.round((elapsed / completedWeight) * remainingWeight / 1000) : 0;
    onProgress(scanId, pct, eta);
    return 'ok';
  }

  for (let i = 0; i < modulesToRun.length; i += MODULE_BATCH_SIZE) {
    if (scanCancelled.has(scanId)) {
      onLog(scanId, 'warning', 'Scan cancelled by user', 'engine');
      onComplete(scanId, allVulnerabilities, true);
      scanCancelled.delete(scanId);
      return;
    }

    const batch = modulesToRun.slice(i, i + MODULE_BATCH_SIZE);
    const batchResults = await Promise.all(batch.map(m => runSingleModule(m)));

    if (batchResults.some(r => r === 'cancelled')) {
      onLog(scanId, 'warning', 'Scan cancelled by user', 'engine');
      onComplete(scanId, allVulnerabilities, true);
      scanCancelled.delete(scanId);
      return;
    }
  }

  onLog(scanId, 'info', `Scan complete. Found ${allVulnerabilities.length} total vulnerability(s)`, 'engine');

  const typedVulns = {};
  for (const v of allVulnerabilities) {
    typedVulns[v.type] = (typedVulns[v.type] || 0) + 1;
  }
  onLog(scanId, 'info', `Breakdown: ${Object.entries(typedVulns).map(([k, c]) => `${k}: ${c}`).join(', ')}`, 'engine');

  if (process.env.API_ENRICHMENT_ENABLED === 'true') {
    onLog(scanId, 'info', 'Enriching vulnerabilities with CVE/CWE data...', 'engine');
    try {
      const enriched = await enrichVulnerabilities(allVulnerabilities);
      onLog(scanId, 'info', `Enriched ${enriched.length} vulnerabilities with CVE data`, 'engine');
      allVulnerabilities.splice(0, allVulnerabilities.length, ...enriched);
    } catch (err) {
      onLog(scanId, 'warning', `API enrichment failed: ${err.message}`, 'engine');
    }
  }

  if (process.env.AI_ANALYSIS_ENABLED === 'true') {
    onLog(scanId, 'info', 'Generating AI-powered analysis...', 'engine');
  }

  onComplete(scanId, allVulnerabilities);
}

function cancelScan(scanId) {
  scanCancelled.add(scanId);
  return true;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

module.exports = { runScan, cancelScan, scannerModules };