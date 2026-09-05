const path = require('path');
const fs = require('fs');

const DB_PATH = path.resolve(__dirname, '..', '..', 'database', 'scanner.db');
const SCHEMA_PATH = path.join(__dirname, '..', '..', 'database', 'schema.sql');
const DB_DIR = path.dirname(DB_PATH);
const IS_SERVERLESS = process.env.VERCEL === '1';
const WRITABLE_DB_PATH = IS_SERVERLESS ? '/tmp/scanner.db' : DB_PATH;
const LOADABLE_DB_PATH =
  IS_SERVERLESS && fs.existsSync('/tmp/scanner.db') ? '/tmp/scanner.db' : DB_PATH;

if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

let db = null;

function dbg(...args) {
  // Uncomment for debugging: console.log('[DB]', ...args);
}

const api = {
  _dirty: false,

  exec(sql) {
    dbg('exec', sql.substring(0, 60));
    this._db.exec(sql);
  },

  prepare(sql) {
    dbg('prepare', sql.substring(0, 60));
    const self = this;

    // sql.js export() (via saveDb) closes ALL open statements, so prepared
    // statements can never be safely reused across calls. Re-prepare and free
    // per invocation to stay immune to statement closure.
    const wrapper = {
      _sql: sql,

      get(...params) {
        let s = null;
        try {
          s = self._db.prepare(wrapper._sql);
          if (params.length > 0) {
            s.bind(params);
          }
          if (s.step()) {
            const result = s.getAsObject();
            return result && typeof result === 'object' ? result : undefined;
          }
          return undefined;
        } catch (e) {
          return undefined;
        } finally {
          if (s) {
            try { s.free(); } catch (e) {}
          }
        }
      },

      all(...params) {
        const results = [];
        let s = null;
        try {
          s = self._db.prepare(wrapper._sql);
          if (params.length > 0) {
            s.bind(params);
          }
          while (s.step()) {
            results.push(s.getAsObject());
          }
          return results;
        } finally {
          if (s) {
            try { s.free(); } catch (e) {}
          }
        }
      },

      run(...params) {
        let s = null;
        try {
          s = self._db.prepare(wrapper._sql);
          if (params.length > 0) {
            s.bind(params);
          }
          s.step();
          // Persist to disk after successful writes
          const result = { changes: self._db.getRowsModified() };
          if (result.changes > 0) {
            api._dirty = true;
            saveDb();
          }
          return result;
        } catch (e) {
          console.error('[DB] Statement error:', e && e.message || e);
          return { changes: 0, error: e.message };
        } finally {
          if (s) {
            try { s.free(); } catch (e) {}
          }
        }
      },
    };

    return wrapper;
  },

  close() {
    if (this._db) {
      this._db.close();
      this._db = null;
    }
  },

  transaction(fn) {
    return function(...args) {
      api._db.exec('BEGIN TRANSACTION');
      try {
        fn(...args);
        api._db.exec('COMMIT');
      } catch (e) {
        api._db.exec('ROLLBACK');
        throw e;
      }
    };
  },
};

async function init() {
  if (db) return db;

  const initSqlJs = require('sql.js/dist/sql-asm.js');
  const SQL = await initSqlJs();

  let buffer = null;
  let sqlDb = null;
  let loadError = null;
  try {
    buffer = fs.readFileSync(LOADABLE_DB_PATH);
    sqlDb = new SQL.Database(buffer);
    // sql.js opens lazily; force validation now so a torn file is detected
    // here (and quarantined below) instead of failing the first real query.
    sqlDb.exec("SELECT 'ok'");
  } catch (e) {
    // The file exists but can't be loaded (e.g. torn write from a killed or
    // concurrent serverless instance). Fall back to a fresh database so the
    // server can always start, and quarantine the bad file.
    loadError = e;
    console.warn('[DB] Loading existing database failed, starting fresh:', e.message);
    if (buffer) {
      try {
        fs.renameSync(LOADABLE_DB_PATH, LOADABLE_DB_PATH + '.corrupt.' + Date.now());
      } catch (ignored) {}
    }
    try {
      sqlDb = new SQL.Database();
    } catch (e2) {
      sqlDb = null;
    }
  }

  if (!sqlDb) {
    throw new Error('Failed to create in-memory database: ' + (loadError && loadError.message || 'unknown'));
  }

  api._db = sqlDb;

  // sql.js doesn't implement PRAGMA journal_mode/WAL; keep the DB in-memory.
  api.exec('PRAGMA foreign_keys=ON');

  // Run schema
  const schema = fs.readFileSync(SCHEMA_PATH, 'utf8');
  api.exec(schema);

  // Migrations for existing databases
  // Add ignored column to vulnerabilities (if not exists)
  try {
    api.exec("ALTER TABLE vulnerabilities ADD COLUMN ignored INTEGER DEFAULT 0");
  } catch (e) {
    // Column already exists - ignore error
  }
  try {
    api.exec("ALTER TABLE vulnerabilities ADD COLUMN ignored_reason TEXT");
  } catch (e) {
    // Column already exists - ignore error
  }
  // Migration: add scan_metadata table
  try {
    api.exec("CREATE TABLE IF NOT EXISTS scan_metadata (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id), key TEXT NOT NULL, value TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    api.exec("CREATE INDEX IF NOT EXISTS idx_meta_scan ON scan_metadata(scan_id)");
  } catch (e) {
  }

  // Migration: add webhook_configs table
  try {
    api.exec("CREATE TABLE IF NOT EXISTS webhook_configs (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, name TEXT NOT NULL, webhook_url TEXT NOT NULL, config_json TEXT, enabled INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    api.exec("CREATE INDEX IF NOT EXISTS idx_webhook_type ON webhook_configs(type)");
  } catch (e) {
  }

  // Migration: add tech_detections table
  try {
    api.exec("CREATE TABLE IF NOT EXISTS tech_detections (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id), technology TEXT NOT NULL, category TEXT, confidence TEXT, version TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    api.exec("CREATE INDEX IF NOT EXISTS idx_tech_scan ON tech_detections(scan_id)");
  } catch (e) {
  }

  // Migration: add dns_security table
  try {
    api.exec("CREATE TABLE IF NOT EXISTS dns_security (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id), domain TEXT NOT NULL, has_spf INTEGER DEFAULT 0, has_dkim INTEGER DEFAULT 0, has_dmarc INTEGER DEFAULT 0, has_dnssec INTEGER DEFAULT 0, security_score INTEGER DEFAULT 0, issues TEXT, recommendations TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    api.exec("CREATE INDEX IF NOT EXISTS idx_dns_scan ON dns_security(scan_id)");
  } catch (e) {
  }

  // Migration: add breach_checks table
  try {
    api.exec("CREATE TABLE IF NOT EXISTS breach_checks (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, breached INTEGER DEFAULT 0, breach_count INTEGER DEFAULT 0, breaches TEXT, checked_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    api.exec("CREATE INDEX IF NOT EXISTS idx_breach_email ON breach_checks(email)");
  } catch (e) {
  }

  // Save initial database
  saveDb();

  db = api;
  return api;
}

function saveDb() {
  if (api._db) {
    try {
      const data = api._db.export();
      const outPath = WRITABLE_DB_PATH;
      // Write to a temp file then rename so readers never observe a torn file.
      const tmpPath = outPath + '.tmp';
      fs.writeFileSync(tmpPath, Buffer.from(data));
      fs.renameSync(tmpPath, outPath);
    } catch (err) {
      console.error('[DB] Save error:', err.message);
    }
  }
}

// Auto-save periodically (only when something changed this interval)
setInterval(() => {
  if (api._dirty) {
    api._dirty = false;
    saveDb();
  }
}, 5000);
process.on('exit', saveDb);
process.on('SIGINT', () => { saveDb(); process.exit(); });
process.on('SIGTERM', () => { saveDb(); process.exit(); });

module.exports = api;
module.exports.init = init;
module.exports.save = saveDb;
