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
  timeout: parseInt(process.env.SCAN_TIMEOUT) || 5000,
  headers: {
    'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0',
    'Accept': 'text/html,application/json,*/*',
  },
  maxRedirects: 5,
  validateStatus: status => status < 500,
});

// On serverless (Vercel) each HTTP request can hit a fresh cold-started instance,
// so nothing can be kept in a per-process Map and expected to survive between
// /step calls. We instead derive all state deterministically from the database:
// completed modules are tracked via 'done:<module>' entries in scan_metadata,
// and per-scan context (chosen modules, passive response cache decision) is
// stored alongside. In long-lived local mode we still reuse the in-memory cache
// as an optimization, but correctness never depends on it.
const IS_SERVERLESS = process.env.VERCEL === '1';
const MODULE_BATCH_SIZE = parseInt(process.env.SCAN_MODULE_CONCURRENCY) || (IS_SERVERLESS ? 1 : 2);
const PER_MODULE_TIMEOUT = parseInt(process.env.SCAN_MODULE_TIMEOUT) || (IS_SERVERLESS ? 20000 : 40000);
// Hard wall-clock budget for a single synchronous scan run (used on serverless).
// Vercel's default function limit is 60s; give ~10s headroom for the HTTP
// request itself and finalization so the response always returns successfully.
// Read per-call so tests can override cheaply; defaults if unset.
const syncBudgetMs = () => parseInt(process.env.SCAN_BUDGET_MS) || 50000;

function withTimeout(promise, ms, label) {
  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms / 1000}s`)), ms);
  });
  return Promise.race([promise, timeoutPromise]).finally(() => clearTimeout(timer));
}

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

// Track scan-level cancellation flags. These are best-effort: on stateless
// serverless, cancel is honoured via a 'cancel' metadata row so any instance
// can observe it.
function cancelScan(scanId) {
  scanCancelled.add(scanId);
  try {
    const db = require('../server/config/db');
    if (db && db._db) db.prepare("INSERT INTO scan_metadata (scan_id, key, value) VALUES (?, 'cancel', '1')").run(scanId);
  } catch (e) { /* local/unit mode: set is enough */ }
  return true;
}

// Build the ORIGINAL module list the user asked for (no done-filtering).
function buildModuleList(requestedModules) {
  if (requestedModules && Array.isArray(requestedModules) && requestedModules.length > 0) {
    return scannerModules.filter(m => requestedModules.includes(m.key));
  }
  return scannerModules;
}

function weightOf(mods) {
  return mods.reduce((s, m) => s + (m.weight || 1), 0);
}

// Light-weight per-process cache for the passive (homepage) fetch. Not
// correctness-critical: if it's lost on a cold start it is simply re-fetched.
const passiveResponseCache = new Map();

// The engine is fully stateless and derives all progress from the database
// ("done:*" scan_metadata rows + the requested module list). Each /step call
// picks the next not-yet-done module and runs it. This survives serverless
// cold starts because nothing depends on a per-process Map.
async function runNextBatch(scanId, targetUrl, onProgress, onLog, onComplete, requestedModules, resumeKeys, onModuleResult) {
  const doneKeys = new Set((resumeKeys || []).filter(k => typeof k === 'string'));
  const allModules = buildModuleList(requestedModules);
  const pending = allModules.filter(m => !doneKeys.has(m.key));

  const totalWeight = weightOf(allModules);
  const doneWeight = weightOf(allModules.filter(m => doneKeys.has(m.key)));

  if (pending.length === 0) {
    // All modules already done but the scan was not finalized (e.g. the
    // finalizing invocation died before onComplete). Finalize now.
    onLog(scanId, 'info', 'All modules already complete - finalizing scan', 'engine');
    await finalizeScan(scanId, onLog, onComplete);
    return { finished: true, cancelled: false, currentModule: null };
  }

  onLog(scanId, 'info', `Queued: ${pending.length} module(s) pending (${doneKeys.size} of ${allModules.length} done)`, 'engine');

  const batch = pending.slice(0, MODULE_BATCH_SIZE);
  let cancelled = scanCancelled.has(scanId);

  if (!cancelled) {
    await Promise.all(batch.map(async (mod, i) => {
      const r = await runSingleModule(scanId, targetUrl, mod, i, doneWeight, pending, totalWeight, onProgress, onLog, onModuleResult);
      if (r === 'cancelled') cancelled = true;
    }));
  }

  const finished = !cancelled && pending.length === batch.length;

  if (cancelled) {
    onLog(scanId, 'warning', 'Scan cancelled by user', 'engine');
    onComplete(scanId, [], true);
    scanCancelled.delete(scanId);
    passiveResponseCache.delete(scanId);
    return { finished: true, cancelled: true, currentModule: null };
  }

  if (finished) {
    await finalizeScan(scanId, onLog, onComplete);
  }

  return { finished, cancelled: false, currentModule: batch.length > 0 ? batch[batch.length - 1].name : null };
}

async function runSingleModule(scanId, targetUrl, mod, batchIndex, doneWeight, pending, totalWeight, onProgress, onLog, onModuleResult) {
  onLog(scanId, 'info', `Running ${mod.name} scanner...`, mod.name);

  let results = [];
  let timedOut = false;
  try {
    const runModule = async () => {
      if (mod.key === 'passive') {
        const cached = passiveResponseCache.get(scanId);
        if (cached && cached.failed) {
          throw new Error('target unreachable - passive scan skipped');
        }
        if (cached && cached.response) {
          return mod.module(targetUrl, cached.response);
        }
        let response;
        try {
          response = await httpClient.get(targetUrl, { timeout: 8000, validateStatus: s => s < 500 });
        } catch {
          passiveResponseCache.set(scanId, { failed: true });
          throw new Error('target unreachable - passive scan skipped');
        }
        passiveResponseCache.set(scanId, { response });
        return mod.module(targetUrl, response);
      }
      return mod.module(targetUrl, httpClient);
    };
    results = await withTimeout(runModule(), PER_MODULE_TIMEOUT, mod.name);
  } catch (err) {
    timedOut = true;
    const msg = err && err.message;
    if (msg && /passive scan skipped|target unreachable/i.test(msg)) {
      onLog(scanId, 'error', `${mod.name}: ${msg}`, mod.name);
    } else {
      onLog(scanId, 'error', `${mod.name} ${msg ? ('timed out or failed: ' + msg) : 'errored'} - skipped`, mod.name);
    }
  }

  if (!timedOut) {
    if (results.length > 0) {
      onLog(scanId, 'warning', `${mod.name}: Found ${results.length} vulnerability(s)`, mod.name);
      for (const vuln of results) {
        onLog(scanId, vuln.severity === 'critical' || vuln.severity === 'high' ? 'warning' : 'info',
          `[${vuln.severity.toUpperCase()}] ${vuln.title}`, mod.name);
      }
    } else {
      onLog(scanId, 'info', `${mod.name}: No vulnerabilities detected`, mod.name);
    }
  }

  if (onModuleResult) {
    try { onModuleResult(scanId, mod.key, results); } catch (e) { onLog(scanId, 'error', `Failed to persist module results: ${e.message}`, mod.name); }
  }

  // Progress = weight already done + weight of pending modules before this one in
// list order + this module's weight, over the full total. Deterministic and
// monotonic regardless of which serverless instance runs which steps.
  const prefixWeight = weightOf(pending.slice(0, batchIndex));
  const completedAfter = doneWeight + prefixWeight + (mod.weight || 1);
  const pct = Math.min(Math.round((completedAfter / totalWeight) * 100), 100);
  const elapsedMs = await scanElapsedMs(scanId);
  const remainingWeight = Math.max(totalWeight - completedAfter, 0);
  const eta = completedAfter > 0 ? Math.round((elapsedMs / completedAfter) * remainingWeight / 1000) : 0;
  onProgress(scanId, pct, eta);

  return timedOut ? 'skipped' : 'ok';
}

async function scanElapsedMs(scanId) {
  try {
    const db = require('../server/config/db');
    const row = db.prepare('SELECT created_at FROM scans WHERE id = ?').get(scanId);
    if (row && row.created_at) {
      const t = new Date(String(row.created_at).replace(' ', 'T') + 'Z');
      if (!isNaN(t.getTime())) return Math.max(Date.now() - t.getTime(), 0);
    }
  } catch (e) {}
  return 0;
}

async function countVulns(scanId) {
  try {
    const db = require('../server/config/db');
    const row = db.prepare('SELECT COUNT(*) as c FROM vulnerabilities WHERE scan_id = ?').get(scanId);
    return row ? row.c : 0;
  } catch (e) { return 0; }
}

async function loadVulns(scanId) {
  try {
    const db = require('../server/config/db');
    return db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scanId);
  } catch (e) { return []; }
}

async function enrichPersistedVulns(scanId, onLog) {
  const db = require('../server/config/db');
  const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scanId);
  if (!vulns.length) return { ok: true, enriched: 0 };
  const enriched = await enrichVulnerabilities(vulns);
  let updated = 0;
  for (const v of enriched) {
    if (!v.id) continue;
    try {
      const res = db.prepare('UPDATE vulnerabilities SET cve_id = ?, description = ? WHERE id = ?').run(v.cve_id || '', v.description || '', v.id);
      if (res.changes > 0) updated++;
    } catch (e) { /* best effort */ }
  }
  try { db.save(); } catch (e) {}
  return { ok: true, enriched: updated };
}

async function finalizeScan(scanId, onLog, onComplete) {
  const db = require('../server/config/db');
  const vulnCount = await countVulns(scanId);
  onLog(scanId, 'info', `Scan complete. Found ${vulnCount} total vulnerability(s)`, 'engine');

  let types = [];
  try {
    const rows = db.prepare('SELECT type, COUNT(*) as c FROM vulnerabilities WHERE scan_id = ? GROUP BY type').all(scanId);
    types = rows.map(r => `${r.type}: ${r.c}`);
  } catch (e) {}
  if (types.length) onLog(scanId, 'info', `Breakdown: ${types.join(', ')}`, 'engine');

  if (process.env.API_ENRICHMENT_ENABLED === 'true') {
    onLog(scanId, 'info', 'Enriching vulnerabilities with CVE/CWE data...', 'engine');
    try {
      const r = await enrichPersistedVulns(scanId, onLog);
      onLog(scanId, 'info', `Enriched ${r.enriched} vulnerabilities with CVE data`, 'engine');
    } catch (err) {
      onLog(scanId, 'warning', `API enrichment failed: ${err.message}`, 'engine');
    }
  }

  onComplete(scanId, await loadVulns(scanId));
  passiveResponseCache.delete(scanId);
}

function runScan(scanId, targetUrl, onProgress, onLog, onComplete, requestedModules) {
  return (async () => {
    for (;;) {
      const { finished, cancelled } = await runNextBatch(scanId, targetUrl, onProgress, onLog, onComplete, requestedModules);
      if (finished || cancelled) break;
    }
  })();
}

function readDoneKeys(scanId) {
  try {
    const db = require('../server/config/db');
    return db.prepare("SELECT key FROM scan_metadata WHERE scan_id = ? AND key LIKE 'done:%'").all(scanId)
      .map(r => r.key.replace(/^done:/, ''));
  } catch (e) { return []; }
}

// Serverless-friendly variant: run every pending module inside a single async
// call and stop when (a) all modules are done, (b) the scan was cancelled, or
// (c) the wall-clock budget is exhausted. Whichever stop happens, the scan row
// is finalized so the collector sees status 'completed' (or 'cancelled').
// Returns the final scan state { status, cancelled }.
async function runScanSync(scanId, targetUrl, onProgress, onLog, onComplete, requestedModules, onModuleResult) {
  const startedAt = Date.now();
  for (;;) {
    if (scanCancelled.has(scanId)) {
      scanCancelled.delete(scanId);
      passiveResponseCache.delete(scanId);
      onLog(scanId, 'warning', 'Scan cancelled by user', 'engine');
      if (typeof onComplete === 'function') onComplete(scanId, [], true);
      return { status: 'cancelled', cancelled: true };
    }
    const { finished, cancelled } = await runNextBatch(scanId, targetUrl, onProgress, onLog, onComplete, requestedModules, readDoneKeys(scanId), onModuleResult);
    if (finished) return { status: cancelled ? 'cancelled' : 'completed', cancelled };
    if (Date.now() - startedAt >= syncBudgetMs()) {
      onLog(scanId, 'warning', `Scan time budget (${Math.round(syncBudgetMs() / 1000)}s) reached - marking remaining modules as skipped. Retry with fewer modules or a faster target for full coverage.`, 'engine');
      await markRemainingSkipped(scanId, onLog, onComplete, requestedModules);
      return { status: 'completed', cancelled: false };
    }
  }
}

// Mark every not-yet-done module as skipped (so the finalize/collector sees a
// complete scan) and finalize. This keeps the scan honest: the result only
// contains modules that actually ran, and the log says the rest were skipped.
async function markRemainingSkipped(scanId, onLog, onComplete, requestedModules) {
  const doneKeys = new Set(readDoneKeys(scanId));
  const allModules = buildModuleList(requestedModules);
  const pending = allModules.filter(m => !doneKeys.has(m.key));
  for (const mod of pending) {
    try {
      const db = require('../server/config/db');
      db.prepare("INSERT INTO scan_metadata (scan_id, key, value) VALUES (?, 'done:' || ?, '1')").run(scanId, mod.key);
      onLog(scanId, 'warning', `Module skipped (time budget): ${mod.name}`, mod.name);
    } catch (e) {}
  }
  try {
    const db = require('../server/config/db');
    db.save();
  } catch (e) {}
  await finalizeScan(scanId, onLog, onComplete);
}

module.exports = { runScan, runScanSync, runNextBatch, cancelScan, scannerModules };