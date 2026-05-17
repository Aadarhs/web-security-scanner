const { XSS_PAYLOADS_ENHANCED } = require('./payload-expansion');
const XSS_PAYLOADS = XSS_PAYLOADS_ENHANCED;

async function testXSSPayload(targetUrl, httpClient, test) {
  const encoded = encodeURIComponent(test.payload);
  const url = `${targetUrl}?q=${encoded}&search=${encoded}&s=${encoded}`;

  try {
    const response = await httpClient.get(url, {
      timeout: 8000,
      headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' }
    });

    const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
    const lower = body.toLowerCase();

    if (body.includes(test.payload) && !body.includes(test.payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'))) {
      return [{
        type: 'xss',
        severity: test.type === 'stored' ? 'critical' : 'high',
        title: `${test.type === 'dom' ? 'DOM-based' : 'Reflected'} XSS Vulnerability`,
        description: `Cross-Site Scripting (XSS) detected via ${test.description}. Payload reflected without sanitization.`,
        endpoint: targetUrl,
        parameter: 'q, search, s',
        payload: test.payload,
        evidence: `Payload found in response: ${test.payload}\nXSS Type: ${test.type}`,
        remediation: 'Implement Content Security Policy (CSP). Use context-aware output encoding.',
        owasp_category: 'A03:2021 – Injection',
        cve_id: 'CWE-79'
      }];
    }

    if (test.payload.toLowerCase().includes('<script') && lower.includes('alert(1)')) {
      return [{
        type: 'xss',
        severity: 'high',
        title: 'Potential Reflected XSS',
        description: `JavaScript execution context detected. ${test.description}`,
        endpoint: targetUrl,
        parameter: 'q, search, s',
        payload: test.payload,
        evidence: 'alert(1) found in response body - possible XSS',
        remediation: 'Apply context-dependent encoding. Use frameworks with auto-escaping.',
        owasp_category: 'A03:2021 – Injection',
        cve_id: 'CWE-79'
      }];
    }

    return [];
  } catch {
    return [];
  }
}

async function scanXSS(targetUrl, httpClient) {
  const vulnerabilities = [];
  const results = await Promise.allSettled(
    XSS_PAYLOADS.map(test => testXSSPayload(targetUrl, httpClient, test))
  );

  for (const result of results) {
    if (result.status === 'fulfilled' && result.value.length > 0) {
      vulnerabilities.push(...result.value);
    }
  }

  return vulnerabilities;
}

module.exports = { scanXSS, XSS_PAYLOADS };
