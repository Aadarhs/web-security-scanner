# Web Security Scanner v2.0

A **production-grade OWASP Top 10 vulnerability scanner** with a futuristic cybersecurity dashboard, AI-powered analysis, network scanning, and auto-improvement admin system. Built for educational and authorized security testing.

![Version](https://img.shields.io/badge/version-2.0.0-00f0ff)
![License](https://img.shields.io/badge/license-MIT-00cc66)
![Node](https://img.shields.io/badge/node-%3E%3D18-339933)
![Tests](https://img.shields.io/badge/tests-69%20passing-00cc66)

---

## Features

### Scanner Engine (14 Modules)
| Module | Description |
|--------|-------------|
| **SQL Injection** | Error-based, boolean blind, time-based, UNION-based detection |
| **XSS** | Reflected, DOM-based cross-site scripting detection |
| **CSRF** | Missing tokens, weak cookie settings, clickjacking protection |
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options analysis |
| **Authentication** | Default credentials, weak session cookies, login exposure |
| **Directory Discovery** | Sensitive file/path discovery (.git, .env, /admin, etc.) |
| **CORS** | Misconfiguration detection with multiple origin tests |
| **Open Redirect** | URL parameter redirect testing (19 params) |
| **LFI** | Path traversal via file/page/load parameters |
| **Command Injection** | OS command injection via 8 payload types |
| **SSRF** | Server-Side Request Forgery testing (cloud metadata, internal services) |
| **XXE** | XML External Entity injection (file reads, SSRF, PHP wrappers) |
| **Network Scanner** | Port scanning, SSL/TLS certificate validation, protocol analysis |
| **Server Status** | Response analysis, health endpoints, server info disclosure |

### Dashboard
- Real-time scan progress with WebSocket updates
- Interactive severity charts (Chart.js)
- Scan history with search/filter/pagination
- Vulnerability knowledge base with OWASP references
- Dark/light theme toggle
- Terminal log output with live streaming
- PDF/JSON report generation

### AI-Powered Analysis
- Risk assessment summary
- Prioritized remediation recommendations
- Business impact analysis
- Attack chaining possibilities
- OpenAI API or local Ollama support
- Fallback analysis engine (no API key required)

### Network Scanning
- TCP port scanning (20 common ports)
- SSL/TLS certificate validation
- Cipher suite and protocol analysis
- Certificate expiry monitoring

### Auto-Improvement Admin
- System statistics dashboard
- Scanner module editor with live editing
- Payload testing tool
- Module management

### API Enrichment
- CVE data enrichment from NVD
- CWE information lookup
- OWASP category descriptions
- Cached results for performance

### Technical Stack
| Layer | Technology |
|-------|-----------|
| Frontend | HTML5, CSS3, Vanilla JS, Chart.js, Socket.io Client |
| Backend | Node.js, Express, Socket.io |
| Database | SQLite (sql.js with WASM) |
| Security | Helmet, Rate Limiting, Input Sanitization |
| Auth | JWT, bcrypt |
| AI | OpenAI API / Ollama / Local Fallback |
| Container | Docker, docker-compose |

---

## Quick Start

### Prerequisites
- Node.js >= 18.x
- npm >= 9.x

### Installation

```bash
git clone <repository-url>
cd web-security-scanner
npm install
npm run seed
npm start
```

Open **http://localhost:3000** in your browser.

### Docker

```bash
docker-compose up -d
```

### Environment Variables

Copy `.env.example` to `.env` and configure:

```env
PORT=3000
JWT_SECRET=your-secure-random-string
ADMIN_EMAIL=admin@securityscanner.local
ADMIN_PASSWORD=Admin@123456

# Optional: Enable AI analysis
AI_ANALYSIS_ENABLED=true
# OPENAI_API_KEY=sk-your-key-here
# Or use local Ollama:
# OLLAMA_URL=http://localhost:11434

# Optional: Enable CVE enrichment
API_ENRICHMENT_ENABLED=true
```

---

## API Documentation

### Authentication
```
POST /api/auth/login
Body: { email, password }
Response: { token, user }

GET /api/auth/me
Headers: Authorization: Bearer <token>
Response: User profile
```

### Scanning
```
POST /api/scan
Body: { url, socketId?, modules? }
Response: { scanId, targetUrl, status }

POST /api/scan/:id/cancel
Headers: Authorization: Bearer <token>
Response: { success, message }

GET /api/scan/history?page=1&limit=20
Response: { scans, total, page, pages }

GET /api/scan/recent
Response: Scan[]
```

### Results
```
GET /api/results/:id
Response: { scan, vulnerabilities[], logs[] }

GET /api/results/:id/summary
Response: { scan, severityBreakdown[], typeBreakdown[] }

PUT /api/results/:scanId/vulnerabilities/:vulnId/ignore
Body: { reason? }
Response: { success, message }

PUT /api/results/:scanId/vulnerabilities/:vulnId/unignore
Response: { success, message }
```

### Reports
```
POST /api/reports/generate/:scanId
Body: { format: "json" | "pdf" }
Response: { reportId, format, filePath }

GET /api/reports/
Response: Report[]

GET /api/reports/:id/download
Response: File download
```

### AI Analysis
```
POST /api/ai/analyze/:scanId
Headers: Authorization: Bearer <token>
Response: { scanId, analysis }

POST /api/ai/remediate
Headers: Authorization: Bearer <token>
Body: { title, type, severity, description, remediation, owaspCategory }
Response: { remediationGuide }

GET /api/ai/status
Response: { enabled, provider }
```

### Admin
```
GET /api/admin/modules
Headers: Authorization: Bearer <token> (admin)
Response: { modules[], total }

GET /api/admin/modules/:name
Response: { name, content, size }

PUT /api/admin/modules/:name
Body: { content }
Response: { success, message }

GET /api/admin/stats
Response: { totalScans, totalVulns, ... }
```

### Dashboard
```
GET /api/dashboard/stats
Response: { totalScans, totalVulnerabilities, averageRiskScore, ... }
```

---

## Project Structure

```
web-security-scanner/
├── client/               # Frontend SPA
│   ├── index.html        # Main dashboard + admin panel
│   ├── css/style.css     # Cyber-themed styling
│   └── js/
│       ├── app.js        # Core dashboard, AI, admin logic
│       ├── scanner.js    # Scanner client with Socket.io
│       └── auth.js       # JWT login/logout, session management
├── server/               # Express backend
│   ├── index.js          # App entry, Socket.io setup
│   ├── config/db.js      # SQLite connection
│   ├── routes/           # API routes
│   │   ├── auth.js       # Login, profile
│   │   ├── scan.js       # Scan management + cancel
│   │   ├── results.js    # Vulnerability results + ignore
│   │   ├── reports.js    # PDF/JSON report generation
│   │   ├── ai.js         # AI analysis & remediation
│   │   └── admin.js      # Module editor & system stats
│   ├── middleware/        # Auth, rate limiting
│   └── utils/            # Helpers
├── scanner-engine/       # Detection modules
│   ├── index.js          # Engine orchestrator (14 modules)
│   ├── sqli.js           # SQL Injection
│   ├── xss.js            # XSS
│   ├── csrf.js           # CSRF
│   ├── headers.js        # Security headers
│   ├── authCheck.js      # Authentication checks
│   ├── directory.js      # Path discovery
│   ├── cors.js           # CORS testing
│   ├── openredirect.js   # Open redirect
│   ├── lfi.js            # Local File Inclusion
│   ├── cmdi.js           # Command Injection (NEW)
│   ├── ssrf.js           # SSRF (NEW)
│   ├── xxe.js            # XXE (NEW)
│   ├── network.js        # Network/SSL/TLS (NEW)
│   ├── serverStatus.js   # Server info (NEW)
│   ├── ai-analyzer.js    # AI analysis engine (NEW)
│   └── api-integration.js # CVE/CWE enrichment (NEW)
├── reports/              # Report generation
│   ├── index.js          # PDF/JSON generators
│   └── generated/        # Output reports
├── database/
│   ├── schema.sql        # Database schema
│   └── seed.js          # Initial data
├── Dockerfile            # Container support (NEW)
├── docker-compose.yml    # Docker orchestration (NEW)
└── __tests__/            # Test suites (69 tests)
```

---

## OWASP Top 10 Coverage

| Category | Coverage |
|----------|----------|
| A01:2021 - Broken Access Control | CSRF, CORS, LFI, path discovery |
| A03:2021 - Injection | SQLi, XSS, Command Injection |
| A04:2021 - Insecure Design | Clickjacking checks |
| A05:2021 - Security Misconfiguration | Header analysis, XXE, network scan |
| A07:2021 - Identification Failures | Auth weakness checks |
| A08:2021 - Software Integrity | Dependency scanning |
| A10:2021 - SSRF | SSRF module (cloud metadata, internal services) |

---

## Deployment

### Docker (Recommended)
```bash
docker-compose up -d
```

### VPS/Linux Server
```bash
# Install Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Clone and setup
git clone <repo> /opt/scanner
cd /opt/scanner
npm install
npm run seed

# Run with PM2
npm install -g pm2
pm2 start server/index.js --name security-scanner
pm2 save
pm2 startup
```

---

## Disclaimer

**IMPORTANT**: This tool is for **authorized security testing and educational purposes only**.

- Only scan systems you own or have explicit written permission to test
- Unauthorized scanning is illegal in most jurisdictions
- The authors are not responsible for misuse of this software
- Always follow responsible disclosure practices

---

## License

MIT License - See LICENSE file for details.
