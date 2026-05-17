const JSZip = require('jszip');
const fs = require('fs');
const path = require('path');

// ── Helpers ──────────────────────────────────────────────
function escXml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function p(text, opts = {}) {
  const bold = opts.bold ? ' w:rsidRPr="00000000"' : '';
  let run = '';
  if (text !== '') {
    const size = opts.size || 22;
    const color = opts.color || '0D1117';
    const font = opts.font || 'Calibri';
    run = `<w:r${bold}><w:rPr><w:rFonts w:ascii="${font}" w:hAnsi="${font}"/><w:sz w:val="${size}"/>${opts.bold ? '<w:b/>' : ''}${opts.italics ? '<w:i/>' : ''}<w:color w:val="${color}"/></w:rPr><w:t xml:space="preserve">${escXml(text)}</w:t></w:r>`;
  }
  const spacing = opts.spacingBefore || opts.spacingAfter
    ? `<w:spacing${opts.spacingBefore ? ` w:before="${opts.spacingBefore}"` : ''}${opts.spacingAfter ? ` w:after="${opts.spacingAfter}"` : ''}/>`
    : '';
  const indent = opts.indent ? `<w:ind w:left="${opts.indent}"/>` : '';
  const shading = opts.shading ? `<w:shd w:fill="${opts.shading}" w:val="clear"/>` : '';
  return `<w:p><w:pPr>${spacing}${indent}${shading}</w:pPr>${run}</w:p>`;
}

function heading(text, level = 1) {
  const sizes = {1: 36, 2: 28, 3: 24, 4: 22};
  const sz = sizes[level] || 22;
  const color = level <= 2 ? '1A237E' : level === 3 ? '00B8D4' : '0D1117';
  const before = level <= 2 ? 480 : 240;
  const after = level <= 2 ? 200 : 120;
  const border = level <= 1
    ? '<w:pBdr><w:bottom w:val="single" w:sz="8" w:space="4" w:color="00E5FF"/></w:pBdr>'
    : '';
  return `<w:p><w:pPr><w:pStyle w:val="Heading${level}"/>${border}<w:spacing w:before="${before}" w:after="${after}"/></w:pPr><w:r><w:rPr><w:rFonts w:ascii="Calibri Light" w:hAnsi="Calibri Light"/><w:b/><w:sz w:val="${sz}"/><w:color w:val="${color}"/></w:rPr><w:t>${escXml(text)}</w:t></w:r></w:p>`;
}

function bullet(text, indent = 720) {
  const numId = 1;
  return `<w:p><w:pPr><w:spacing w:before="40" w:after="40"/><w:ind w:left="${indent}" w:hanging="220"/><w:numPr><w:ilvl w:val="0"/><w:numId w:val="${numId}"/></w:numPr></w:pPr><w:r><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/><w:color w:val="0D1117"/></w:rPr><w:t>${escXml(text)}</w:t></w:r></w:p>`;
}

function codeBlock(lines) {
  const children = lines.map((l, i) => {
    const text = i < lines.length - 1 ? l + '\n' : l;
    return `<w:r><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="18"/><w:color w:val="0D1117"/></w:rPr><w:t xml:space="preserve">${escXml(text)}</w:t></w:r>`;
  }).join('');
  return `<w:p><w:pPr><w:spacing w:before="40" w:after="40"/><w:ind w:left="360"/><w:shd w:fill="F0F0F0" w:val="clear"/><w:pBdr><w:left w:val="single" w:sz="4" w:space="4" w:color="E0E0E0"/></w:pBdr></w:pPr>${children}</w:p>`;
}

function spacer() { return p('', {spacingBefore: 120, spacingAfter: 120}); }
function divider() { return p('', {spacingBefore: 160, spacingAfter: 160}); }

function makeTable(headers, rows) {
  const totalCols = headers.length;
  const tblW = 9600;
  const colW = Math.floor(tblW / totalCols);

  let xml = `<w:tbl><w:tblPr><w:tblW w:w="${tblW}" w:type="dxa"/>` +
    `<w:jc w:val="left"/><w:tblBorders>` +
    `<w:top w:val="single" w:sz="4" w:space="0" w:color="1A237E"/>` +
    `<w:bottom w:val="single" w:sz="4" w:space="0" w:color="1A237E"/>` +
    `<w:left w:val="single" w:sz="4" w:space="0" w:color="1A237E"/>` +
    `<w:right w:val="single" w:sz="4" w:space="0" w:color="1A237E"/>` +
    `<w:insideH w:val="single" w:sz="4" w:space="0" w:color="CCCCCC"/>` +
    `<w:insideV w:val="single" w:sz="4" w:space="0" w:color="CCCCCC"/>` +
    `</w:tblBorders></w:tblPr>`;

  // Header row
  xml += '<w:tr>';
  for (const h of headers) {
    xml += `<w:tc><w:tcPr><w:tcW w:w="${colW}" w:type="dxa"/><w:shd w:fill="1A237E" w:val="clear"/></w:tcPr>` +
      `<w:p><w:pPr><w:jc w:val="center"/></w:pPr>` +
      `<w:r><w:rPr><w:b/><w:sz w:val="18"/><w:color w:val="FFFFFF"/><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/></w:rPr><w:t>${escXml(h)}</w:t></w:r></w:p></w:tc>`;
  }
  xml += '</w:tr>';

  // Data rows
  for (const row of rows) {
    xml += '<w:tr>';
    for (let ci = 0; ci < row.length; ci++) {
      const cellText = row[ci];
      const bg = ci === 0 ? ' w:shd w:fill="F5F7FA" w:val="clear"' : '';
      xml += `<w:tc><w:tcPr><w:tcW w:w="${colW}" w:type="dxa"/>${bg ? '<'+bg+'/>' : ''}</w:tcPr>` +
        `<w:p><w:r><w:rPr><w:sz w:val="18"/><w:color w:val="0D1117"/><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>${ci === 0 ? '<w:b/>' : ''}</w:rPr><w:t>${escXml(cellText)}</w:t></w:r></w:p></w:tc>`;
    }
    xml += '</w:tr>';
  }

  xml += '</w:tbl>';
  return xml;
}

// ════════════════════════════════════════════════════════════
//  BUILD DOCUMENT
// ════════════════════════════════════════════════════════════

const body = [];

// ── Cover page ──
body.push(`<w:p><w:pPr><w:spacing w:before="4800"/><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:rFonts w:ascii="Calibri Light" w:hAnsi="Calibri Light"/><w:b/><w:sz w:val="56"/><w:color w:val="1A237E"/></w:rPr><w:t>WEB SECURITY SCANNER</w:t></w:r></w:p>`);
body.push(`<w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:rFonts w:ascii="Calibri Light" w:hAnsi="Calibri Light"/><w:sz w:val="36"/><w:color w:val="00E5FF"/></w:rPr><w:t>v2.0</w:t></w:r></w:p>`);
body.push(`<w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:sz w:val="24"/><w:color w:val="666666"/></w:rPr><w:t>Complete Project Architecture Document</w:t></w:r></w:p>`);
body.push(`<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:before="200"/></w:pPr><w:r><w:rPr><w:sz w:val="20"/><w:color w:val="1A237E"/></w:rPr><w:t>Generated: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</w:t></w:r></w:p>`);
body.push(spacer());

// ════════════════════════════════════════════════════════════
//  1. TECHNOLOGY STACK
// ════════════════════════════════════════════════════════════
body.push(heading('1. Technology Stack', 1));
body.push(p('The application is built entirely in JavaScript with a monolithic architecture, no frontend build step, and zero external infrastructure dependencies.'));
body.push(makeTable(
  ['Category', 'Technology', 'Version'],
  [
    ['Language', 'JavaScript (Node.js)', 'ES2021'],
    ['Runtime', 'Node.js', '18.x LTS'],
    ['Web Framework', 'Express', '4.18'],
    ['Database', 'SQLite via sql.js (WASM)', '1.10'],
    ['Authentication', 'JWT (jsonwebtoken + bcryptjs)', '-'],
    ['Real-time', 'Socket.io', '4.7'],
    ['Frontend', 'Vanilla JS SPA (no framework)', '-'],
    ['Charts', 'Chart.js', '4.4 (CDN)'],
    ['Icons', 'Font Awesome', '6.5 (CDN)'],
    ['PDF Generation', 'pdfkit', '0.13'],
    ['HTTP Client', 'axios', '1.6'],
    ['HTML Parsing', 'cheerio', '1.0'],
    ['Testing', 'Vitest', '-'],
    ['Container', 'Docker (node:18-alpine)', '-'],
  ]
));
body.push(spacer());

// ════════════════════════════════════════════════════════════
//  2. PROJECT STRUCTURE
// ════════════════════════════════════════════════════════════
body.push(heading('2. Project Structure', 1));
body.push(codeBlock([
  'web-security-scanner/',
  '+-- .env                          Environment variables',
  '+-- package.json                  Dependencies & scripts',
  '+-- Dockerfile                    Multi-stage Node 18 build',
  '+-- docker-compose.yml            Single-service orchestration',
  '+-- README.md                     Documentation',
  '+-- client/                       Vanilla JS SPA frontend',
  '|   +-- index.html                Single-page app (942 lines)',
  '|   +-- css/style.css             Cyber-themed CSS (1145 lines)',
  '|   +-- js/',
  '|       +-- app.js                Core: navigation, dashboard, AI, admin, OSINT',
  '|       +-- auth.js               JWT login, session management',
  '|       +-- scanner.js            WebSocket client: progress, vuln cards',
  '|       +-- pentest.js            17 tool UIs + payload library',
  '+-- server/                       Express backend',
  '|   +-- index.js                  Entry point: Express + HTTP + Socket.io',
  '|   +-- config/db.js              sql.js wrapper with WAL mode',
  '|   +-- middleware/',
  '|   |   +-- auth.js               JWT authenticate() + optionalAuth()',
  '|   |   +-- rateLimiter.js        Scan + auth rate limiters',
  '|   +-- routes/                   14 route files',
  '|   +-- utils/',
  '|   |   +-- helpers.js            Utility functions',
  '|   |   +-- notifications.js      Slack/Discord/Email/webhook senders',
  '|   +-- __tests__/                Integration tests',
  '+-- scanner-engine/               Detection & analysis modules',
  '|   +-- index.js                  Orchestrator: 14-module registry, queue',
  '|   +-- sqli.js, xss.js, csrf.js  ... 14 scanner modules',
  '|   +-- ai-analyzer.js            OpenAI -> Ollama -> local fallback',
  '|   +-- api-integration.js        NVD CVE lookup',
  '|   +-- pentest-tools.js          17 pentest tools',
  '|   +-- tech-detect.js            87 tech fingerprint patterns',
  '|   +-- dns-security.js           SPF/DKIM/DMARC/DNSSEC',
  '|   +-- compliance.js             5 frameworks',
  '|   +-- __tests__/                Unit tests',
  '+-- database/',
  '|   +-- schema.sql                10 tables + 10 indexes',
  '|   +-- seed.js                   Admin user seeder',
  '|   +-- scanner.db                SQLite file (auto-created)',
  '+-- reports/',
  '|   +-- index.js                  PDF + JSON report generators',
  '|   +-- generated/                Output directory',
  '+-- node_modules/                 16 runtime + 3 dev dependencies',
]));
body.push(spacer());

// ════════════════════════════════════════════════════════════
//  3. ARCHITECTURE OVERVIEW
// ════════════════════════════════════════════════════════════
body.push(heading('3. Architecture Overview', 1));
body.push(p('The system follows a client-server architecture with real-time WebSocket communication for scan progress and REST API for all other operations.'));
body.push(heading('End-to-End Scan Flow', 3));
const flowItems = [
  'User enters a target URL and selects modules, clicks "Start Scan"',
  'Frontend POSTs to /api/scan, server creates scan record, returns scanId',
  'Socket.io room joined for real-time events',
  'scanner-engine/index.js runs modules sequentially with weight-based progress',
  'Each module: (targetUrl, httpClient) => [vulnerabilities]',
  'Progress + ETA emitted after each module via scan:progress socket event',
  'On scan:complete, vulnerabilities saved to DB, results sent to frontend',
  'Optional: CVE/CWE enrichment via NVD API',
  'Optional: AI-powered analysis via OpenAI/Ollama/local fallback',
  'User can download JSON/PDF reports or generate compliance reports',
];
for (const item of flowItems) body.push(bullet(item));

body.push(heading('Progress Calculation', 3));
body.push(p('Total weight = 106 across 14 modules. Progress = (completedWeight / totalWeight) * 100. ETA is calculated as (elapsedTime / completedWeight) * remainingWeight, updated after each module completes.'));
body.push(spacer());

// ════════════════════════════════════════════════════════════
//  4. AUTHENTICATION SYSTEM
// ════════════════════════════════════════════════════════════
body.push(heading('4. Authentication System', 1));
body.push(heading('Login Flow', 2));
for (const item of [
  'User submits email + password via POST /api/auth/login',
  'Rate-limited: 10 requests per 15 minutes',
  'bcrypt.compare(password, hash) against stored hash',
  'Returns JWT with 7-day expiry',
  'Token stored in browser localStorage as authToken',
]) body.push(bullet(item));

body.push(heading('Middleware Stack', 2));
body.push(makeTable(
  ['Middleware', 'Behavior'],
  [
    ['authenticate', 'Returns 401 if token missing, invalid, or expired'],
    ['optionalAuth', 'Attaches user to req.user if valid; continues without if missing'],
    ['adminAuth', 'Checks req.user.role === "admin"; returns 403 if not admin'],
  ]
));

body.push(heading('Default Credentials', 2));
body.push(p('Admin user seeded on first start from .env:'));
body.push(codeBlock([
  'ADMIN_EMAIL=admin@securityscanner.local',
  'ADMIN_PASSWORD=Admin@123456',
  '// MUST change these in production',
]));
body.push(spacer());

// ════════════════════════════════════════════════════════════
//  5. SCANNER ENGINE
// ════════════════════════════════════════════════════════════
body.push(heading('5. Scanner Engine (14 Modules)', 1));
body.push(p('Each module is an async function accepting (targetUrl, httpClient) and returning an array of vulnerability objects.'));
body.push(makeTable(
  ['#', 'Module', 'Key', 'Weight', 'Technique'],
  [
    ['1',  'SQL Injection',       'sqli',   '12', '10 payloads, 16 error patterns, time-based >2s, UNION injection'],
    ['2',  'XSS',                 'xss',    '12', '9 payloads, checks unencoded reflection in response body'],
    ['3',  'CSRF',                'csrf',    '6', 'SameSite cookie check, form token scan, clickjacking'],
    ['4',  'Security Headers',    'headers', '6', '7 security headers + server info disclosure'],
    ['5',  'Authentication',      'auth',    '8', '13 default creds, weak password patterns, cookie flags'],
    ['6',  'Directory Discovery', 'directory', '10', '22 sensitive paths with content validation'],
    ['7',  'CORS',                'cors',    '6', '3 malicious origins tested'],
    ['8',  'Open Redirect',       'openredirect', '5', '19 params, 2 payloads, 3 detection patterns'],
    ['9',  'LFI',                 'lfi',     '5', '6 payloads, 5 params (file, page, load, path, include)'],
    ['10', 'Command Injection',   'cmdi',    '8', '14 params, 8 payloads, ping indicator, time-based'],
    ['11', 'SSRF',                'ssrf',    '7', '19 params, 13 payloads (cloud metadata, localhost, file://)'],
    ['12', 'XXE',                 'xxe',     '5', '7 payloads, POST + GET, OOB, XInclude, PHP wrapper'],
    ['13', 'Network & SSL/TLS',   'network', '12', '20-port TCP scan + SSL cert validation + TLS protocol'],
    ['14', 'Server Status',       'serverstatus', '4', '8 probe endpoints, response time, health check exposure'],
  ]
));
body.push(spacer());

// ════════════════════════════════════════════════════════════
//  6. PENTEST TOOLKIT
// ════════════════════════════════════════════════════════════
body.push(heading('6. Pentest Toolkit (17 Tools)', 1));
body.push(p('All tools are independent REST endpoints under POST /api/pentest/*. No WebSocket - each tool is a single HTTP request/response cycle.'));
body.push(makeTable(
  ['#', 'Tool', 'Endpoint', 'Key Feature'],
  [
    ['1',  'SQLi Exploiter',      '/sqli-exploit',       'UNION-based column enumeration + data extraction'],
    ['2',  'Brute Forcer',        '/brute-force',        'Custom username/password wordlists, success detection'],
    ['3',  'Payload Generator',   '/generate-payload',   '8 categories, 150+ payloads with descriptions'],
    ['4',  'Subdomain Enum',      '/subdomain-enum',     '50 common subdomains, DNS A + CNAME resolution'],
    ['5',  'Port Scanner',        '/port-scan',          '27 ports, TCP connect, configurable concurrency'],
    ['6',  'Endpoint Fuzzer',     '/fuzz-endpoints',     '50+ common paths via HTTP GET'],
    ['7',  'HTTP Method Fuzzer',  '/http-method-fuzz',   '9 methods (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS/TRACE/CONNECT)'],
    ['8',  'DNS Recon',           '/dns-recon',          'A/AAAA/MX/NS/TXT/SOA/CNAME record lookup'],
    ['9',  'CVE Search',          '/cve-search',         'NVD API keyword search + fallback sample CVEs'],
    ['10', 'Hash Identifier',     '/hash-identify',      '25 hash type patterns (MD5, SHA1, bcrypt, NTLM, Argon2)'],
    ['11', 'Whois Lookup',        '/whois',              'whois.com domain registration scraping'],
    ['12', 'SSL/TLS Analyzer',    '/ssl-analyze',        'Certificate info, expiry, SAN, cipher, issues'],
    ['13', 'CSP Evaluator',       '/csp-analyze',        'Security header analysis with CSP-specific checks'],
    ['14', 'Parameter Fuzzer',    '/param-fuzzer',       '45+ parameters, response size change analysis'],
    ['15', 'Wordlist Generator',  '/wordlist-generator', '18 mutation functions applied to base words'],
    ['16', 'JWT Decoder',         '/jwt-decode',         'Base64 decode, signature extraction, issue detection'],
    ['17', 'Email Extractor',     '/email-extract',      'Regex email extraction + external link discovery'],
  ]
));
body.push(spacer());

// ════════════════════════════════════════════════════════════
//  7. FRONTEND SPA
// ════════════════════════════════════════════════════════════
body.push(heading('7. Frontend SPA', 1));
body.push(p('Single-page application with hash-based navigation (no router library). All sections are hidden by default and toggled via CSS class .active.'));
body.push(makeTable(
  ['Section', 'Hash', 'File', 'Purpose'],
  [
    ['Dashboard', '#dashboard', 'app.js', 'Stats cards, severity doughnut chart, scan timeline'],
    ['Scanner', '#scanner', 'scanner.js', 'URL input, module toggles, progress bar, ETA, live log'],
    ['History', '#history', 'app.js', 'Paginated table, status filter, search, view/generate report'],
    ['Reports', '#reports', 'app.js', 'Generated reports table with download buttons'],
    ['Pentest', '#pentest', 'pentest.js', '17 tool UIs + payload library browser (150+ payloads)'],
    ['Admin', '#admin', 'app.js', 'Module list editor, code editor, payload tester, system stats'],
    ['OSINT', '#osint', 'app.js', 'Tech detection, DNS security analysis, HIBP breach check'],
    ['Compliance', '#compliance', 'app.js', 'Framework selector (5), compliance report table'],
    ['Diff', '#diff', 'app.js', 'Two-scan comparison: new/fixed/unchanged findings'],
    ['Docs', '#docs', 'app.js', 'Searchable vulnerability knowledge base cards'],
  ]
));
body.push(spacer());

// ════════════════════════════════════════════════════════════
//  8. API ENDPOINTS
// ════════════════════════════════════════════════════════════
body.push(heading('8. API Endpoints', 1));

body.push(heading('Authentication', 2));
for (const item of [
  'POST /api/auth/login — Login (rate-limited: 10/15min)',
  'GET /api/auth/me — Current user profile (requires JWT)',
]) body.push(bullet(item));

body.push(heading('Scanning', 2));
for (const item of [
  'POST /api/scan — Start scan (rate-limited: 100/15min)',
  'POST /api/scan/:id/cancel — Cancel scan (requires JWT)',
  'GET /api/scan/history — Paginated history (20/page)',
  'GET /api/scan/recent — Last 10 scans',
]) body.push(bullet(item));

body.push(heading('Results', 2));
for (const item of [
  'GET /api/results/:id — Full scan results + vulnerabilities + logs',
  'GET /api/results/:id/summary — Severity counts + type breakdown',
  'GET /api/results/ignored — Paginated ignored vulnerabilities',
  'PUT .../vulnerabilities/:id/ignore — Mark vuln as ignored',
  'PUT .../vulnerabilities/:id/unignore — Restore vuln',
]) body.push(bullet(item));

body.push(heading('Reports', 2));
for (const item of [
  'GET /api/reports/ — List all reports',
  'GET /api/reports/:id — Report details',
  'GET /api/reports/:id/download — Download report file',
  'POST /api/reports/generate/:scanId — Generate PDF or JSON report',
]) body.push(bullet(item));

body.push(heading('AI Analysis', 2));
for (const item of [
  'POST /api/ai/analyze/:scanId — AI analysis (requires JWT)',
  'POST /api/ai/remediate — Generate remediation guide (requires JWT)',
  'GET /api/ai/status — AI provider status',
]) body.push(bullet(item));

body.push(heading('Penetration Testing', 2));
body.push(p('/api/pentest/sqli-exploit, /brute-force, /generate-payload, /subdomain-enum, /port-scan, /fuzz-endpoints, /http-method-fuzz, /dns-recon, /cve-search, /hash-identify, /whois, /ssl-analyze, /csp-analyze, /param-fuzzer, /wordlist-generator, /jwt-decode, /email-extract'));
body.push(spacer());

// ════════════════════════════════════════════════════════════
//  9. DATABASE SCHEMA
// ════════════════════════════════════════════════════════════
body.push(heading('9. Database Schema', 1));
body.push(p('SQLite database via sql.js (WASM). Auto-created on first start with schema migration system. WAL mode enabled.'));
body.push(makeTable(
  ['Table', 'Key Columns', 'Purpose'],
  [
    ['users', 'id, email (UNIQUE), password (bcrypt), name, role', 'User accounts & admin'],
    ['scans', 'id (TEXT PK), target_url, status, risk_score, progress, severity counts', 'Scan sessions'],
    ['vulnerabilities', 'id, scan_id, type, severity, title, description, endpoint, evidence, cve_id', 'Found vulnerabilities'],
    ['scan_logs', 'id, scan_id, level, message, module, created_at', 'Terminal log streaming'],
    ['reports', 'id, scan_id, format (PDF/JSON), file_path', 'Generated reports'],
    ['scan_metadata', 'id, scan_id, key, value', 'Key-value scan metadata'],
    ['webhook_configs', 'id, type, name, webhook_url, config_json, enabled', 'Notification webhooks'],
    ['tech_detections', 'id, scan_id, technology, category, confidence, version', 'Tech fingerprints'],
    ['dns_security', 'id, scan_id, domain, spf/dkim/dmarc flags, score', 'DNS security results'],
    ['breach_checks', 'id, email, breached, breach_count, breaches (JSON)', 'HIBP cache'],
  ]
));
body.push(spacer());

// ════════════════════════════════════════════════════════════
//  10. COMMUNICATION PATTERNS
// ════════════════════════════════════════════════════════════
body.push(heading('10. Communication Patterns', 1));
body.push(p('The application uses two communication channels between frontend and backend.'));
body.push(heading('REST API', 2));
body.push(p('All CRUD operations: scan history, results, reports, admin, pentest tools, OSINT, compliance, diff, breach checks, notifications. Uses standard fetch() with JSON.'));
body.push(heading('WebSocket (Socket.io 4.7)', 2));
body.push(makeTable(
  ['Event', 'Direction', 'Payload', 'Purpose'],
  [
    ['scan:started',   'Server -> Client', '{ scanId, targetUrl }', 'Scan initialized'],
    ['scan:progress',  'Server -> Client', '{ progress, eta }', 'Percentage + ETA update'],
    ['scan:log',       'Server -> Client', '{ level, message, module }', 'Terminal log streaming'],
    ['scan:complete',  'Server -> Client', '{ scanId, vulnerabilities, counts }', 'Scan finished'],
    ['scan:cancelled', 'Server -> Client', '{ scanId }', 'Scan was cancelled'],
    ['join:scan',      'Client -> Server', '{ room }', 'Join scan room for events'],
    ['leave:scan',     'Client -> Server', '{ scanId }', 'Leave room on completion'],
  ]
));
body.push(spacer());

// ════════════════════════════════════════════════════════════
//  11. INTEGRATION SYSTEMS
// ════════════════════════════════════════════════════════════
body.push(heading('11. Integration Systems', 1));
body.push(heading('CVE/CWE Enrichment', 2));
for (const item of [
  'Enabled via API_ENRICHMENT_ENABLED=true',
  'NVD (National Vulnerability Database) API for CVE lookups',
  '1-hour in-memory cache to avoid rate limiting',
  'Local CWE database with 16 common CWE entries',
]) body.push(bullet(item));

body.push(heading('AI-Powered Analysis', 2));
for (const item of [
  '3-tier fallback chain: OpenAI API -> Ollama local -> Rule-based fallback',
  'Enabled via AI_ANALYSIS_ENABLED=true + LLM_ENABLED=true',
  'OpenAI: GPT-3.5-turbo, up to 30s timeout',
  'Ollama: Local model (codellama), up to 60s timeout',
  'Fallback: Generates analysis from severity counts and predefined templates',
  'Two modes: Full scan analysis + Per-vulnerability remediation guide',
]) body.push(bullet(item));

body.push(heading('HIBP Breach Check', 2));
for (const item of [
  'Email check via HaveIBeenPwned k-anonymity API',
  'Password check via HIBP range API (SHA-1 prefix)',
  'Results cached in breach_checks database table',
]) body.push(bullet(item));
body.push(spacer());

// ════════════════════════════════════════════════════════════
//  12. COMPLIANCE FRAMEWORKS
// ════════════════════════════════════════════════════════════
body.push(heading('12. Compliance Frameworks', 1));
body.push(p('5 industry compliance frameworks, each with vulnerability-type-to-control-ID mappings.'));
body.push(makeTable(
  ['Framework', 'Version', 'Controls', 'Focus Area'],
  [
    ['PCI-DSS',  '4.0',   '14', 'Payment card data security'],
    ['HIPAA',    '2024',  '12', 'Healthcare data privacy & security'],
    ['SOC2',     '2024',  '12', 'Service organization security controls'],
    ['GDPR',     '2018',  '12', 'EU data protection & privacy'],
    ['ISO 27001','2022',  '12', 'Information security management'],
  ]
));
body.push(spacer());

// ════════════════════════════════════════════════════════════
//  13. REPORTING & ADMIN & DOCKER & TEST SUITE
// ════════════════════════════════════════════════════════════
body.push(heading('13. Reporting System', 1));
for (const item of [
  'Two output formats: PDF (pdfkit-based) and JSON',
  'PDF includes: executive summary, finding details, risk scoring, compliance mapping',
  'JSON: structured data export for CI/CD pipeline integration',
  'Generation: POST /api/reports/generate/:scanId with format parameter',
  'Reports saved to reports/generated/ directory with DB record',
  'Download: GET /api/reports/:id/download',
]) body.push(bullet(item));
body.push(spacer());

body.push(heading('14. Admin System', 1));
for (const item of [
  'Access restricted to admin role (middleware enforced)',
  'Module list: enable/disable individual scanner modules',
  'Code editor: live edit scanner module source from admin panel',
  'Payload tester: test arbitrary payloads against target endpoints',
  'System statistics: total scans, vulnerabilities by severity, users',
  'Environment viewer: display safe environment variables',
]) body.push(bullet(item));
body.push(spacer());

body.push(heading('15. Docker & Deployment', 1));
body.push(heading('Dockerfile', 2));
for (const item of [
  'Stage 1: npm install all dependencies',
  'Stage 2: node:18-alpine, npm install --production only',
  'Exposes port 3000, HEALTHCHECK on /api/dashboard/stats',
]) body.push(bullet(item));
body.push(heading('Docker Compose', 2));
for (const item of [
  'Single service (scanner) on port 3000',
  'Volume mount: ./database for SQLite persistence',
  '.env file passed to container for configuration',
]) body.push(bullet(item));
body.push(spacer());

body.push(heading('16. Environment Configuration', 1));
body.push(makeTable(
  ['Variable', 'Default', 'Purpose'],
  [
    ['PORT', '3000', 'Server port'],
    ['JWT_SECRET', '(random)', 'JWT signing key'],
    ['JWT_EXPIRES_IN', '7d', 'Token expiry duration'],
    ['DB_PATH', './database/scanner.db', 'SQLite file location'],
    ['SCAN_TIMEOUT', '30000', 'HTTP request timeout (ms)'],
    ['MAX_CONCURRENT_SCANS', '3', 'Maximum parallel scans'],
    ['API_ENRICHMENT_ENABLED', 'true', 'CVE/CWE enrichment toggle'],
    ['AI_ANALYSIS_ENABLED', 'false', 'AI analysis toggle'],
    ['OPENAI_API_KEY', '(unset)', 'OpenAI API key'],
    ['OLLAMA_URL', 'http://localhost:11434', 'Ollama endpoint'],
    ['ADMIN_EMAIL', 'admin@securityscanner.local', 'Default admin email'],
    ['ADMIN_PASSWORD', 'Admin@123456', 'Default admin password'],
  ]
));
body.push(spacer());

body.push(heading('17. Test Suite', 1));
body.push(p('69 tests across 6 test files, all passing. Run: npx vitest run'));
body.push(makeTable(
  ['Test File', 'Tests', 'Type', 'Scope'],
  [
    ['auth.integration.test.js',   '10', 'Integration', 'Login validation, JWT issuance, /me endpoint'],
    ['scan.integration.test.js',   '11', 'Integration', 'Scan creation, history pagination, recent scans'],
    ['results.integration.test.js','10', 'Integration', 'Ignore/unignore vulns, ignored list, pagination'],
    ['helpers.test.js',            '21', 'Unit',       'Sanitize URL (11), risk score (6), severity counts (4)'],
    ['directory.test.js',          '11', 'Unit',       'SENSITIVE_PATHS validation + scanDirectory scenarios'],
    ['cors.test.js',                '6', 'Unit',       'Reflected, wildcard, credentials, no headers, errors'],
  ]
));
body.push(spacer());

// ════════════════════════════════════════════════════════════
//  BUILD XML
// ════════════════════════════════════════════════════════════

const bodyXml = body.join('\n');

const numberingXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
  xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
  mc:Ignorable="w14 w15"
  xmlns:w14="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
  xmlns:w15="http://schemas.openxmlformats.org/officeDocument/2006/bibliography">
  <w:abstractNum w:abstractNumId="0">
    <w:multiLevelType w:val="hybridMultilevel"/>
    <w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="\u2022"/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="720" w:hanging="220"/></w:pPr></w:lvl>
  </w:abstractNum>
  <w:num w:numId="1">
    <w:abstractNumId w:val="0"/>
  </w:num>
</w:numbering>`;

const stylesXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:rPr><w:b/><w:sz w:val="36"/><w:color w:val="1A237E"/><w:rFonts w:ascii="Calibri Light" w:hAnsi="Calibri Light"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="1A237E"/><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="00B8D4"/><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Normal"><w:name w:val="Normal"/><w:rPr><w:sz w:val="22"/><w:color w:val="0D1117"/><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/></w:rPr></w:style>
</w:styles>`;

const documentXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
  xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
  mc:Ignorable="w14 w15 w16se w16cex w16cid w16"
  xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml">
  <w:body>${bodyXml}
  <w:sectPr>
    <w:pgSz w:w="12240" w:h="15840"/>
    <w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720"/>
  </w:sectPr></w:body></w:document>`;

// ════════════════════════════════════════════════════════════
//  CREATE DOCX (ZIP)
// ════════════════════════════════════════════════════════════

async function main() {
  const zip = new JSZip();

  // [Content_Types].xml
  zip.file('[Content_Types].xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>
</Types>`);

  // _rels/.rels
  zip.file('_rels/.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`);

  // word/document.xml
  zip.file('word/document.xml', documentXml);

  // word/_rels/document.xml.rels
  zip.file('word/_rels/document.xml.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>
</Relationships>`);

  // word/styles.xml
  zip.file('word/styles.xml', stylesXml);

  // word/numbering.xml
  zip.file('word/numbering.xml', numberingXml);

  // Generate
  const buffer = await zip.generateAsync({
    type: 'nodebuffer',
    compression: 'DEFLATE',
    mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  });

  const outputPath = path.join(__dirname, '..', 'reports', 'generated', 'Web_Security_Scanner_v2.0_Architecture_Report.docx');
  fs.writeFileSync(outputPath, buffer);

  console.log(`\n  ✅ Report generated: ${outputPath}`);
  console.log(`  📄 Size: ${(buffer.length / 1024).toFixed(1)} KB\n`);

  // cleanup test.docx if it exists
  const testPath = path.join(__dirname, '..', 'test.docx');
  if (fs.existsSync(testPath)) fs.unlinkSync(testPath);
}

main().catch(err => {
  console.error('Error:', err);
  process.exit(1);
});
