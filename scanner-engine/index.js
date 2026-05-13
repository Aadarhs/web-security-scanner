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

const scanQueue = [];
let activeScans = 0;
const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT_SCANS) || 3;

const httpClient = axios.create({
  timeout: parseInt(process.env.SCAN_TIMEOUT) || 30000,
  headers: {
    'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0',
    'Accept': 'text/html,application/json,*/*',
  },
  maxRedirects: 5,
  validateStatus: status => status < 500,
});

const scannerModules = [
  { key: 'sqli', name: 'SQL Injection', module: scanSQLi, weight: 15 },
  { key: 'xss', name: 'Cross-Site Scripting (XSS)', module: scanXSS, weight: 15 },
  { key: 'csrf', name: 'CSRF', module: scanCSRF, weight: 10 },
  { key: 'headers', name: 'Security Headers', module: scanHeaders, weight: 10 },
  { key: 'auth', name: 'Authentication', module: scanAuth, weight: 10 },
  { key: 'directory', name: 'Sensitive File/Path Discovery', module: scanDirectory, weight: 15 },
  { key: 'cors', name: 'CORS Misconfiguration', module: scanCORS, weight: 10 },
  { key: 'openredirect', name: 'Open Redirect', module: scanOpenRedirect, weight: 8 },
  { key: 'lfi', name: 'Local File Inclusion', module: scanLFI, weight: 7 },
];

async function runScan(scanId, targetUrl, onProgress, onLog, onComplete, requestedModules) {
  onLog(scanId, 'info', `Initializing scan for ${targetUrl}`, 'engine');
  await sleep(100);

  onLog(scanId, 'info', `Target resolved: ${targetUrl}`, 'engine');
  onLog(scanId, 'info', 'Starting vulnerability assessment...', 'engine');

  let modulesToRun = scannerModules;
  if (requestedModules && Array.isArray(requestedModules) && requestedModules.length > 0) {
    modulesToRun = scannerModules.filter(m => requestedModules.includes(m.key));
    onLog(scanId, 'info', `Loading ${modulesToRun.length} of ${scannerModules.length} selected scanner modules`, 'engine');
  } else {
    onLog(scanId, 'info', `Loading all ${scannerModules.length} scanner modules`, 'engine');
  }
  await sleep(100);

  let completedWeight = 0;
  const totalWeight = modulesToRun.reduce((s, m) => s + m.weight, 0);
  const allVulnerabilities = [];

  for (const mod of modulesToRun) {
    onLog(scanId, 'info', `Running ${mod.name} scanner...`, mod.name);
    
    try {
      const results = await mod.module(targetUrl, httpClient);
      
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
    onProgress(scanId, pct);
    await sleep(50);
  }

  onLog(scanId, 'info', `Scan complete. Found ${allVulnerabilities.length} total vulnerability(s)`, 'engine');
  onComplete(scanId, allVulnerabilities);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

module.exports = { runScan, scannerModules };
