# Web Security Scanner v1.0

A **production-grade OWASP Top 10 vulnerability scanner** with a futuristic cybersecurity dashboard. Built for educational and authorized security testing.

![Version](https://img.shields.io/badge/version-1.0.0-00f0ff)
![License](https://img.shields.io/badge/license-MIT-00cc66)
![Node](https://img.shields.io/badge/node-%3E%3D18-339933)

---

## Features

### Scanner Engine
- **SQL Injection** - Error-based, boolean blind, time-based blind, UNION-based detection
- **Cross-Site Scripting (XSS)** - Reflected, stored, DOM-based detection
- **CSRF Detection** - Missing tokens, weak cookie settings, clickjacking protection
- **Security Headers** - CSP, HSTS, X-Frame-Options, X-Content-Type-Options analysis
- **Authentication** - Default credentials, weak session cookies, login exposure

### Dashboard
- Real-time scan progress with WebSocket updates
- Interactive severity charts (Chart.js)
- Scan history with search/filter
- Vulnerability knowledge base with OWASP references
- Dark/light theme toggle
- Terminal log output
- PDF/JSON report generation

### Technical Stack
| Layer | Technology |
|-------|-----------|
| Frontend | HTML5, CSS3, Vanilla JS, Chart.js, Socket.io Client |
| Backend | Node.js, Express, Socket.io |
| Database | SQLite (better-sqlite3) |
| Security | Helmet, Rate Limiting, Input Sanitization |
| Auth | JWT, bcrypt |

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

### Environment Variables

Copy `.env.example` to `.env` and configure:

```env
PORT=3000
JWT_SECRET=your-secure-random-string
ADMIN_EMAIL=admin@securityscanner.local
ADMIN_PASSWORD=Admin@123456
```

---

## API Documentation

### Authentication
```
POST /api/auth/login
Body: { email, password }
Response: { token, user }
```

### Scanning
```
POST /api/scan
Body: { url, socketId?, modules? }
Response: { scanId, targetUrl, status }

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
│   ├── index.html        # Main dashboard
│   ├── css/style.css     # Cyber-themed styling
│   └── js/
│       ├── app.js        # Core dashboard logic
│       └── scanner.js    # Scanner client with Socket.io
├── server/               # Express backend
│   ├── index.js          # App entry, Socket.io setup
│   ├── config/db.js      # SQLite connection
│   ├── routes/           # API routes
│   ├── middleware/        # Auth, rate limiting
│   └── utils/            # Helpers
├── scanner-engine/       # Detection modules
│   ├── index.js          # Engine orchestrator
│   ├── sqli.js           # SQL injection scanner
│   ├── xss.js            # XSS scanner
│   ├── csrf.js           # CSRF scanner
│   ├── headers.js        # Security header scanner
│   └── authCheck.js      # Authentication scanner
├── reports/              # Report generation
│   ├── index.js          # PDF/JSON generators
│   └── generated/        # Output reports
└── database/
    ├── schema.sql        # Database schema
    └── seed.js          # Initial data
```

---

## Deployment

### GitHub
```bash
git init
git add .
git commit -m "Initial commit: Web Security Scanner v1.0"
git remote add origin https://github.com/yourusername/web-security-scanner.git
git push -u origin main
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

### Cloudflare Tunnel (Optional)
```bash
cloudflared tunnel create scanner
cloudflared tunnel route dns scanner scanner.yourdomain.com
cloudflared tunnel run scanner
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

## OWASP Top 10 Coverage

| Category | Status |
|----------|--------|
| A01:2021 - Broken Access Control | CSRF, CORS checks |
| A03:2021 - Injection | SQLi, XSS detection |
| A04:2021 - Insecure Design | Clickjacking checks |
| A05:2021 - Security Misconfiguration | Header analysis |
| A07:2021 - Identification Failures | Auth weakness checks |
| A08:2021 - Software Integrity | Dependency scanning |
