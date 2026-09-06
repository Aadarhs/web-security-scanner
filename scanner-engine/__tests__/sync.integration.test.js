const http = require('http');
const path = require('path');
const fs = require('fs');

const TEST_DB_PATH = path.resolve(__dirname, '..', '..', 'database', 'test-sync.db');
process.env.DB_PATH = TEST_DB_PATH;

let server;
let baseUrl;

beforeAll(async () => {
  try { fs.unlinkSync(TEST_DB_PATH); } catch {}

  server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Server', 'TestServer/1.0');
    res.end('<html><head><title>Test</title></head><body><h1>Hello</h1></body></html>');
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  baseUrl = `http://127.0.0.1:${addr.port}/`;
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  try { fs.unlinkSync(TEST_DB_PATH); } catch {}
});

const engine = require('../index');
const db = require('../../server/config/db');

describe('synchronous scan (serverless path)', () => {
  beforeAll(async () => {
    await db.init();
    db.save();
  });

  function makeScanRow(id, url) {
    db.prepare('INSERT INTO scans (id, target_url, status, user_id) VALUES (?, ?, ?, ?)').run(id, url, 'running', null);
    db.save();
  }

  // Mirrors server/routes/scan.js makeCallbacks().onComplete: persists the final
  // scan status/counters. The engine calls this exactly once on finalize.
  function persistComplete(id, _vulns, cancelled = false) {
    db.prepare(`
      UPDATE scans SET status = ?, progress = 100,
        total_vulnerabilities = (SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ?),
        critical_count = (SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND severity = 'critical'),
        high_count = (SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND severity = 'high'),
        medium_count = (SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND severity = 'medium'),
        low_count = (SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND severity = 'low'),
        info_count = (SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND severity = 'info'),
        completed_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(cancelled ? 'cancelled' : 'completed', id, id, id, id, id, id, id);
    db.save();
  }

  it('completes all requested modules and finalizes the scan', async () => {
    const scanId = 'test-sync-complete';
    makeScanRow(scanId, baseUrl);

    const logs = [];
    const progress = [];
    const callbacks = {
      onProgress: (id, p) => progress.push(p),
      onLog: (id, level, message, module) => logs.push({ level, message, module }),
      onModuleResult: (id, moduleKey, results) => {
        db.prepare("INSERT INTO scan_metadata (scan_id, key, value) VALUES (?, 'done:' || ?, '1')").run(id, moduleKey);
        db.save();
      },
      onComplete: persistComplete,
    };

    const result = await engine.runScanSync(scanId, baseUrl, callbacks.onProgress, callbacks.onLog, callbacks.onComplete, ['passive', 'serverstatus'], callbacks.onModuleResult);

    const meta = db.prepare("SELECT key FROM scan_metadata WHERE scan_id = ? AND key LIKE 'done:%'").all(scanId)
      .map(r => r.key.replace('done:', ''));
    const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);

    expect(result.status).toBe('completed');
    expect(scan.status).toBe('completed');
    expect(scan.progress).toBe(100);
    expect(meta).toEqual(expect.arrayContaining(['passive', 'serverstatus']));
    // final log line confirms scan summary
    expect(logs.some(l => /Scan complete/.test(l.message))).toBe(true);
    // progress is monotonic and reaches 100
    expect(progress[progress.length - 1]).toBe(100);
  });

  it('marks remaining modules as skipped, never hangs, and still finalizes when the time budget is exhausted', async () => {
    process.env.SCAN_BUDGET_MS = '1';
    try {
      const scanId = 'test-sync-budget';
      makeScanRow(scanId, baseUrl);

      const logs = [];
      const result = await engine.runScanSync(scanId, baseUrl, () => {}, (id, level, msg) => logs.push(msg), persistComplete, ['passive', 'serverstatus', 'headers']);

      const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
      expect(result.status).toBe('completed');
      expect(scan.status).toBe('completed');
      expect(scan.progress).toBe(100);
      expect(logs.some(l => /time budget/.test(l))).toBe(true);
      expect(logs.some(l => /Module skipped/.test(l))).toBe(true);
    } finally {
      delete process.env.SCAN_BUDGET_MS;
    }
  });
});