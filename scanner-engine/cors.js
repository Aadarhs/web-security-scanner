async function scanCORS(targetUrl, httpClient) {
  const vulnerabilities = [];
  const baseUrl = targetUrl.replace(/\/$/, '');

  // Test origins that should NOT be allowed
  const testOrigins = [
    { origin: 'https://evil.com', label: 'arbitrary origin', severity: 'critical' },
    { origin: 'null', label: 'null origin', severity: 'high' },
    { origin: 'https://malicious.com', label: 'arbitrary origin', severity: 'critical' },
  ];

  for (const test of testOrigins) {
    try {
      const response = await httpClient.get(baseUrl, {
        timeout: 10000,
        headers: {
          'Origin': test.origin,
          'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0',
        },
        validateStatus: status => status < 500,
      });

      const allowOrigin = response.headers['access-control-allow-origin'];
      const allowCredentials = response.headers['access-control-allow-credentials'];
      const allowMethods = response.headers['access-control-allow-methods'];

      // CORS misconfiguration: server echoes back the Origin header
      if (allowOrigin === test.origin || allowOrigin === '*') {
        const isWildcard = allowOrigin === '*';
        const credsEnabled = allowCredentials === 'true';

        let severity = test.severity;
        let title = `CORS Misconfiguration - ${isWildcard ? 'Wildcard' : 'Reflected'} Origin`;
        let description = '';

        if (isWildcard && credsEnabled) {
          severity = 'critical';
          title = 'CORS Critical - Wildcard with Credentials';
          description = 'Server uses Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. This is a severe misconfiguration allowing any site to make authenticated requests.';
        } else if (isWildcard) {
          severity = 'medium';
          description = 'Server allows all origins via wildcard (*). May be acceptable for public APIs but risky if any sensitive data is returned.';
        } else if (credsEnabled) {
          severity = 'critical';
          description = `Server reflects arbitrary Origin (${test.origin}) with credentials allowed. Any website can make authenticated cross-origin requests and read the response.`;
        } else {
          description = `Server reflects arbitrary Origin (${test.origin}) without credentials. Allows data exfiltration via cross-origin requests.`;
        }

        vulnerabilities.push({
          type: 'cors',
          severity,
          title,
          description,
          endpoint: baseUrl,
          parameter: 'Origin header',
          payload: `Origin: ${test.origin}`,
          evidence: `Request Origin: ${test.origin}\nResponse Allow-Origin: ${allowOrigin}\nAllow-Credentials: ${allowCredentials || 'Not set'}\nAllow-Methods: ${allowMethods || 'Not set'}\nHedged: ${test.label}`,
          remediation: 'Do not use Access-Control-Allow-Origin: *. Validate Origin against a whitelist. Never combine wildcard CORS with credentials. Use specific allowed origins only.',
          owasp_category: 'A01:2021 – Broken Access Control',
          cve_id: 'CWE-942',
        });

        break; // Found a misconfig, no need to test more origins
      }
    } catch (err) {
      // Connection errors mean we can't test CORS — skip
      continue;
    }
  }

  // If no CORS was found, add an informational note
  if (vulnerabilities.length === 0) {
    // Check if the server even sends CORS headers at all
    try {
      const response = await httpClient.get(baseUrl, {
        timeout: 10000,
        headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
        validateStatus: status => status < 500,
      });

      const corsHeaders = ['access-control-allow-origin', 'access-control-allow-credentials', 'access-control-allow-methods', 'access-control-expose-headers'];
      const hasCORS = corsHeaders.some(h => response.headers[h] !== undefined);

      if (!hasCORS) {
        vulnerabilities.push({
          type: 'cors',
          severity: 'info',
          title: 'CORS Headers Not Present',
          description: 'No CORS headers detected. This is fine for same-origin applications but may need CORS if accessed by cross-origin clients.',
          endpoint: baseUrl,
          parameter: 'N/A',
          payload: 'No CORS headers',
          evidence: 'No Access-Control-* headers found in response.',
          remediation: 'If your API needs to be accessed cross-origin, configure specific allowed origins. Otherwise, no action needed.',
          owasp_category: 'A01:2021 – Broken Access Control',
          cve_id: 'CWE-942',
        });
      }
    } catch {
      // skip
    }
  }

  return vulnerabilities;
}

module.exports = { scanCORS };
