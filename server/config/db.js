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
  exec(sql) {
    dbg('exec', sql.substring(0, 60));
    this._db.exec(sql);
  },

  prepare(sql) {
    dbg('prepare', sql.substring(0, 60));
    const self = this;
    const stmt = self._db.prepare(sql);

    return {
      get(...params) {
        try {
          if (params.length > 0) {
            stmt.bind(params);
          }
          if (stmt.step()) {
            const result = stmt.getAsObject();
            return result && typeof result === 'object' ? result : undefined;
          }
          return undefined;
        } catch (e) {
          return undefined;
        } finally {
          stmt.reset();
        }
      },

      all(...params) {
        try {
          const results = [];
          if (params.length > 0) {
            stmt.bind(params);
          }
          while (stmt.step()) {
            results.push(stmt.getAsObject());
          }
          return results;
        } finally {
          stmt.reset();
        }
      },

      run(...params) {
        try {
          if (params.length > 0) {
            stmt.bind(params);
            stmt.step();
          } else {
            stmt.step();
          }
          // Persist to disk after successful writes
          const result = { changes: self._db.getRowsModified() };
          if (result.changes > 0) {
            saveDb();
          }
          return result;
        } catch (e) {
          console.error('[DB] Statement error:', e.message);
          return { changes: 0, error: e.message };
        } finally {
          stmt.reset();
        }
      },
    };
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
  try {
    buffer = fs.readFileSync(LOADABLE_DB_PATH);
  } catch {
    // No existing database file, will create new
  }

  const sqlDb = buffer ? new SQL.Database(buffer) : new SQL.Database();
  api._db = sqlDb;

  // Enable WAL mode - sql.js doesn't support pragmas the same way
  api.exec('PRAGMA journal_mode=WAL');
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
      fs.writeFileSync(WRITABLE_DB_PATH, Buffer.from(data));
    } catch (err) {
      console.error('[DB] Save error:', err.message);
    }
  }
}

// Auto-save periodically
setInterval(saveDb, 5000);
process.on('exit', saveDb);
process.on('SIGINT', () => { saveDb(); process.exit(); });
process.on('SIGTERM', () => { saveDb(); process.exit(); });

module.exports = api;
module.exports.init = init;
module.exports.save = saveDb;
