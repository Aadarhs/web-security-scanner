const cheerio = require('cheerio');

const SENSITIVE_HEADERS_PASSIVE = [
  { header: 'x-powered-by', severity: 'low', desc: 'Technology info disclosure' },
  { header: 'server', severity: 'low', desc: 'Server version disclosure' },
  { header: 'x-aspnet-version', severity: 'medium', desc: 'ASP.NET version disclosure' },
  { header: 'x-aspnetmvc-version', severity: 'medium', desc: 'ASP.NET MVC version' },
  { header: 'x-drupal-cache', severity: 'low', desc: 'Drupal cache header' },
  { header: 'x-generator', severity: 'low', desc: 'CMS generator tag' },
  { header: 'x-nginx-version', severity: 'medium', desc: 'Nginx version' },
  { header: 'x-php-version', severity: 'medium', desc: 'PHP version disclosure' },
  { header: 'x-rack-cache', severity: 'low', desc: 'Rack cache header' },
  { header: 'x-runtime', severity: 'low', desc: 'Ruby/Rails runtime' },
  { header: 'x-version', severity: 'medium', desc: 'Version disclosure' },
  { header: 'x-api-version', severity: 'medium', desc: 'API version disclosure' },
];

const PASSIVE_SIGNATURES = {
  sqli: [
    { pattern: /SQL syntax.*MySQL|Warning.*mysql_|Unclosed quotation mark|error in your SQL syntax|ORA-[0-9]{5}|PostgreSQL.*ERROR|SQLite\/JDBC|Division by zero|Unknown column/i, severity: 'critical', label: 'SQL Error in response' },
    { pattern: /Microsoft OLE DB.*SQL Server|Driver.*SQL Server|DB2 SQL error|Adaptive Server|Sybase message/i, severity: 'critical', label: 'Database error message' },
  ],
  xss: [
    { pattern: /<script[\s>]/i, severity: 'info', label: 'Script tag in response' },
    { pattern: /onerror\s*=|onload\s*=|onclick\s*=|onfocus\s*=/i, severity: 'info', label: 'Inline event handler' },
    { pattern: /javascript\s*:/i, severity: 'info', label: 'Javascript protocol' },
  ],
  info: [
    { pattern: /<!--[\s\S]*?(?:TODO|FIXME|HACK|XXX|BUG|NOTE|REVIEW|REVISIT|DEBUG)/i, severity: 'low', label: 'Developer comment' },
    { pattern: /<!--[\s\S]*?(?:password|secret|key|token|api.?key|username|login)/i, severity: 'high', label: 'Sensitive data in HTML comment' },
    { pattern: /(?:password|secret|token|api.?key)\s*=\s*['"][^'"]+['"]/i, severity: 'high', label: 'Hardcoded credential pattern' },
    { pattern: /(?:AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36})/i, severity: 'critical', label: 'API key / token in response' },
    { pattern: /(?:-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)/i, severity: 'critical', label: 'Private key in response' },
    { pattern: /(?:db_(?:name|host|user|pass)|DB_(?:NAME|HOST|USER|PASS))\s*[:=]\s*['"]?[^'"\s]+/i, severity: 'high', label: 'Database credential pattern' },
    { pattern: /s3:\/\/(?:[a-z0-9.-]+)/i, severity: 'medium', label: 'S3 bucket URL in response' },
    { pattern: /(?:internal-ip|private-ip|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/i, severity: 'medium', label: 'Internal IP address disclosure' },
    { pattern: /\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0)\b/i, severity: 'low', label: 'Localhost reference' },
    { pattern: /stack trace:|at\s+\S+\.\S+\(|\.java:\d+\)|in\s+<module>|File\s+"[^"]+",\s+line/i, severity: 'medium', label: 'Stack trace in response' },
    { pattern: /(?:debug|trace|verbose)\s*[:=]\s*true/i, severity: 'medium', label: 'Debug mode enabled' },
    { pattern: /(?:jsonp_callback|callback|jsonp)\s*[:=]/i, severity: 'low', label: 'JSONP endpoint (potential data leak)' },
    { pattern: /\/(?:webdav|server-status|server-info|cgi-bin)\b/i, severity: 'medium', label: 'Server management path exposed' },
  ],
};

function scanPassive(targetUrl, response) {
  return new Promise((resolve) => {
    const vulnerabilities = [];
    const headers = {};
    for (const [k, v] of Object.entries(response.headers || {})) {
      headers[k.toLowerCase()] = v;
    }

    for (const check of SENSITIVE_HEADERS_PASSIVE) {
      if (headers[check.header]) {
        vulnerabilities.push({
          type: 'passive-info',
          severity: check.severity,
          title: `Information Disclosure - ${check.header}`,
          description: `${check.desc}: "${headers[check.header]}"`,
          endpoint: targetUrl,
          parameter: `HTTP Header: ${check.header}`,
          payload: `${check.header}: ${headers[check.header]}`,
          evidence: `Header: ${check.header}\nValue: ${headers[check.header]}\nThis reveals software/version information to attackers.`,
          remediation: 'Remove or obfuscate informative HTTP headers. Use generic values for Server and X-Powered-By headers.',
          owasp_category: 'A05:2021 – Security Misconfiguration',
          cve_id: 'CWE-200',
        });
      }
    }

    const body = typeof response.data === 'string' ? response.data : '';
    if (!body) {
      resolve(vulnerabilities);
      return;
    }

    const lower = body.toLowerCase();

    for (const sig of PASSIVE_SIGNATURES.sqli) {
      if (sig.pattern.test(body)) {
        vulnerabilities.push({
          type: 'passive-sqli',
          severity: 'critical',
          title: `Passive SQLi Detection - ${sig.label}`,
          description: `SQL error pattern detected in response: ${sig.label}`,
          endpoint: targetUrl,
          parameter: 'Response body',
          payload: sig.pattern.source,
          evidence: `Pattern: ${sig.pattern.source}\nThis indicates potential SQL injection vulnerability or information leakage.`,
          remediation: 'Use parameterized queries. Disable detailed database error messages in production.',
          owasp_category: 'A03:2021 – Injection',
          cve_id: 'CWE-89',
        });
        break;
      }
    }

    for (const sig of PASSIVE_SIGNATURES.info) {
      if (sig.pattern.test(body)) {
        vulnerabilities.push({
          type: 'passive-info',
          severity: sig.severity,
          title: `Passive Detection - ${sig.label}`,
          description: `Pattern "${sig.label}" found in response body.`,
          endpoint: targetUrl,
          parameter: 'Response body',
          payload: sig.pattern.source,
          evidence: `Pattern: ${sig.pattern.source}\nSensitive information may be exposed in the page source.`,
          remediation: 'Remove sensitive comments, credentials, and internal information from production code and responses.',
          owasp_category: 'A05:2021 – Security Misconfiguration',
          cve_id: 'CWE-200',
        });
        break;
      }
    }

    resolve(vulnerabilities);
  });
}

module.exports = { scanPassive, PASSIVE_SIGNATURES, SENSITIVE_HEADERS_PASSIVE };
