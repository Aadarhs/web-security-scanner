const SECURITY_HEADERS = {
  'strict-transport-security': {
    name: 'Strict-Transport-Security (HSTS)',
    severity: 'medium',
    description: 'Enforces HTTPS connections and prevents downgrade attacks.',
    expected: 'max-age=31536000; includeSubDomains',
    remediation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    owasp: 'A05:2021 – Security Misconfiguration',
    cve: 'CWE-523'
  },
  'content-security-policy': {
    name: 'Content-Security-Policy (CSP)',
    severity: 'high',
    description: 'Prevents XSS and data injection attacks by controlling resource loading.',
    expected: "default-src 'self'",
    remediation: "Implement CSP header: default-src 'self'; script-src 'self'; object-src 'none'",
    owasp: 'A05:2021 – Security Misconfiguration',
    cve: 'CWE-1021'
  },
  'x-frame-options': {
    name: 'X-Frame-Options',
    severity: 'medium',
    description: 'Prevents clickjacking by controlling iframe embedding.',
    expected: 'DENY or SAMEORIGIN',
    remediation: 'Add: X-Frame-Options: DENY (or SAMEORIGIN if framing allowed)',
    owasp: 'A05:2021 – Security Misconfiguration',
    cve: 'CWE-1021'
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    severity: 'low',
    description: 'Prevents MIME type sniffing attacks.',
    expected: 'nosniff',
    remediation: 'Add: X-Content-Type-Options: nosniff',
    owasp: 'A05:2021 – Security Misconfiguration',
    cve: 'CWE-693'
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    severity: 'low',
    description: 'Controls how much referrer information is sent with requests.',
    expected: 'strict-origin-when-cross-origin',
    remediation: 'Add: Referrer-Policy: strict-origin-when-cross-origin',
    owasp: 'A05:2021 – Security Misconfiguration',
    cve: 'CWE-200'
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    severity: 'low',
    description: 'Controls which browser features and APIs can be used.',
    expected: 'camera=(), microphone=(), geolocation=()',
    remediation: 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()',
    owasp: 'A05:2021 – Security Misconfiguration',
    cve: 'CWE-693'
  },
  'x-xss-protection': {
    name: 'X-XSS-Protection',
    severity: 'info',
    description: 'Enables browser XSS filter (deprecated but still relevant).',
    expected: '1; mode=block',
    remediation: 'Add: X-XSS-Protection: 1; mode=block (or rely on CSP)',
    owasp: 'A05:2021 – Security Misconfiguration',
    cve: 'CWE-79'
  },
};

async function scanHeaders(targetUrl, httpClient) {
  const vulnerabilities = [];

  try {
    const response = await httpClient.get(targetUrl, {
      timeout: 15000,
      headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
      maxRedirects: 5,
    });

    const headers = {};
    for (const [key, value] of Object.entries(response.headers)) {
      headers[key.toLowerCase()] = value;
    }

    const presentHeaders = [];
    const missingHeaders = [];

    for (const [headerKey, config] of Object.entries(SECURITY_HEADERS)) {
      if (headers[headerKey] !== undefined) {
        presentHeaders.push({ header: headerKey, value: headers[headerKey], config });
      } else {
        missingHeaders.push({ header: headerKey, config });
      }
    }

    for (const missing of missingHeaders) {
      const { config } = missing;
      vulnerabilities.push({
        type: 'security-headers',
        severity: config.severity,
        title: `Missing Security Header: ${config.name}`,
        description: config.description,
        endpoint: targetUrl,
        parameter: 'N/A (HTTP Header)',
        payload: `Missing: ${missing.header}`,
        evidence: `Header: ${missing.header}\nExpected: ${config.expected}\nFound: NOT PRESENT\nImpact: ${config.description}`,
        remediation: config.remediation,
        owasp_category: config.owasp,
        cve_id: config.cve
      });
    }

    const serverHeader = headers['server'] || headers['x-powered-by'];
    if (serverHeader) {
      vulnerabilities.push({
        type: 'security-headers',
        severity: 'low',
        title: 'Server Information Disclosure',
        description: `Server header reveals software information: "${serverHeader}"`,
        endpoint: targetUrl,
        parameter: 'N/A (HTTP Header)',
        payload: `Server: ${serverHeader}`,
        evidence: `Header: Server: ${serverHeader}\nRisk: Information leakage aids attackers in targeting specific vulnerabilities`,
        remediation: 'Remove or obfuscate Server and X-Powered-By headers. Use generic values or disable header emission.',
        owasp_category: 'A05:2021 – Security Misconfiguration',
        cve_id: 'CWE-200'
      });
    }

  } catch (err) {
    if (err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED') {
      vulnerabilities.push({
        type: 'security-headers',
        severity: 'info',
        title: 'Unable to Connect',
        description: `Could not establish connection to ${targetUrl}`,
        endpoint: targetUrl,
        parameter: 'N/A',
        payload: err.code,
        evidence: `Error: ${err.message}`,
        remediation: 'Verify the target URL is reachable and the service is running.'
      });
    } else {
      vulnerabilities.push({
        type: 'security-headers',
        severity: 'info',
        title: 'Security Header Scan Limited',
        description: `Header scan encountered an error: ${err.message}`,
        endpoint: targetUrl,
        parameter: 'N/A',
        payload: err.message,
        evidence: `Error: ${err.message}`,
        remediation: 'Manual header inspection recommended.'
      });
    }
  }

  return vulnerabilities;
}

module.exports = { scanHeaders, SECURITY_HEADERS };
