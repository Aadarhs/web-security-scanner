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

const scanCancelled = new Set();

const httpClient = axios.create({
  timeout: parseInt(process.env.SCAN_TIMEOUT) || 8000,
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

const scanStates = new Map();

function ensureScanState(scanId, targetUrl, requestedModules) {
  if (scanStates.has(scanId)) return scanStates.get(scanId);

  let modulesToRun = scannerModules;
  if (requestedModules && Array.isArray(requestedModules) && requestedModules.length > 0) {
    modulesToRun = scannerModules.filter(m => requestedModules.includes(m.key));
  }

  const st = {
    url: targetUrl,
    modulesToRun,
    index: 0,
    completedWeight: 0,
    totalWeight: modulesToRun.reduce((s, m) => s + m.weight, 0),
    vulnerabilities: [],
    startedAt: Date.now(),
    passiveResponse: null,
    loadLogged: false,
  };
  scanStates.set(scanId, st);
  return st;
}

function cancelScan(scanId) {
  scanCancelled.add(scanId);
  return true;
}

async function runNextBatch(scanId, targetUrl, onProgress, onLog, onComplete, requestedModules) {
  const st = ensureScanState(scanId, targetUrl, requestedModules);

  if (!st.loadLogged) {
    st.loadLogged = true;
    onLog(scanId, 'info', `Loading ${st.modulesToRun.length} of ${scannerModules.length} scanner modules`, 'engine');
  }

  async function runSingleModule(mod) {
    if (scanCancelled.has(scanId)) return 'cancelled';

    onLog(scanId, 'info', `Running ${mod.name} scanner...`, mod.name);

    try {
      let results;
      if (mod.key === 'passive') {
        if (!st.passiveResponse) {
          try {
            st.passiveResponse = await httpClient.get(st.url, { timeout: 8000, validateStatus: s => s < 500 });
          } catch {
            st.passiveResponse = { data: '', headers: {} };
          }
        }
        results = await mod.module(st.url, st.passiveResponse);
      } else {
        results = await mod.module(st.url, httpClient);
      }

      if (results.length > 0) {
        onLog(scanId, 'warning', `${mod.name}: Found ${results.length} vulnerability(s)`, mod.name);
        for (const vuln of results) {
          st.vulnerabilities.push(vuln);
          onLog(scanId, vuln.severity === 'critical' || vuln.severity === 'high' ? 'warning' : 'info',
            `[${vuln.severity.toUpperCase()}] ${vuln.title}`, mod.name);
        }
      } else {
        onLog(scanId, 'info', `${mod.name}: No vulnerabilities detected`, mod.name);
      }
    } catch (err) {
      onLog(scanId, 'error', `${mod.name} scanner failed: ${err.message}`, mod.name);
    }

    st.completedWeight += mod.weight;
    const pct = Math.min(Math.round((st.completedWeight / st.totalWeight) * 100), 100);
    const elapsed = Date.now() - st.startedAt;
    const remainingWeight = st.totalWeight - st.completedWeight;
    const eta = st.completedWeight > 0 ? Math.round((elapsed / st.completedWeight) * remainingWeight / 1000) : 0;
    onProgress(scanId, pct, eta);
    return 'ok';
  }

  if (scanCancelled.has(scanId)) {
    onLog(scanId, 'warning', 'Scan cancelled by user', 'engine');
    onComplete(scanId, st.vulnerabilities, true);
    scanCancelled.delete(scanId);
    scanStates.delete(scanId);
    return { finished: true, cancelled: true };
  }

  const batch = st.modulesToRun.slice(st.index, st.index + MODULE_BATCH_SIZE);
  st.index += batch.length;
  const batchResults = await Promise.all(batch.map(m => runSingleModule(m)));

  if (batchResults.some(r => r === 'cancelled') || scanCancelled.has(scanId)) {
    onLog(scanId, 'warning', 'Scan cancelled by user', 'engine');
    onComplete(scanId, st.vulnerabilities, true);
    scanCancelled.delete(scanId);
    scanStates.delete(scanId);
    return { finished: true, cancelled: true };
  }

  const finished = st.index >= st.modulesToRun.length;
  if (finished) {
    onLog(scanId, 'info', `Scan complete. Found ${st.vulnerabilities.length} total vulnerability(s)`, 'engine');

    const typedVulns = {};
    for (const v of st.vulnerabilities) {
      typedVulns[v.type] = (typedVulns[v.type] || 0) + 1;
    }
    onLog(scanId, 'info', `Breakdown: ${Object.entries(typedVulns).map(([k, c]) => `${k}: ${c}`).join(', ')}`, 'engine');

    if (process.env.API_ENRICHMENT_ENABLED === 'true') {
      onLog(scanId, 'info', 'Enriching vulnerabilities with CVE/CWE data...', 'engine');
      try {
        const enriched = await enrichVulnerabilities(st.vulnerabilities);
        onLog(scanId, 'info', `Enriched ${enriched.length} vulnerabilities with CVE data`, 'engine');
        st.vulnerabilities.splice(0, st.vulnerabilities.length, ...enriched);
      } catch (err) {
        onLog(scanId, 'warning', `API enrichment failed: ${err.message}`, 'engine');
      }
    }

    onComplete(scanId, st.vulnerabilities);
    scanStates.delete(scanId);
  }

  return { finished, cancelled: false };
}

function runScan(scanId, targetUrl, onProgress, onLog, onComplete, requestedModules) {
  return (async () => {
    for (;;) {
      const { finished, cancelled } = await runNextBatch(scanId, targetUrl, onProgress, onLog, onComplete, requestedModules);
      if (finished || cancelled) break;
    }
  })();
}

module.exports = { runScan, runNextBatch, cancelScan, scannerModules };