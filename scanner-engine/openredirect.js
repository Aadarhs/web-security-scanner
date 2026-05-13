const COMMON_REDIRECT_PARAMS = [
  'url', 'redirect', 'redirect_uri', 'return', 'return_to', 'return_url',
  'next', 'next_page', 'r', 'u', 'target', 'destination', 'to',
  'continue', 'continue_to', 'forward', 'fwd', 'redirect_to',
  'redir', 'uri', 'link', 'href', 'ref', 'page', 'file', 'document',
];

const REDIRECT_TEST_PAYLOADS = [
  '//example.com',
  'https://example.com',
];

const REDIRECT_PATTERNS = [
  /location:?\s*(?:https?:\/\/)?example\.com/i,
  /https?:\/\/example\.com/,
];

async function scanOpenRedirect(targetUrl, httpClient) {
  const vulnerabilities = [];
  const baseUrl = targetUrl.replace(/\/$/, '');

  try {
    // First, get the page to discover form inputs and testable params
    const initResponse = await httpClient.get(baseUrl, {
      timeout: 10000,
      headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
      maxRedirects: 0,
      validateStatus: s => s < 500,
    });

    const body = typeof initResponse.data === 'string' ? initResponse.data : '';

    // Test each common redirect parameter with each payload
    for (const param of COMMON_REDIRECT_PARAMS) {
      for (const payload of REDIRECT_TEST_PAYLOADS) {
        try {
          const testUrl = `${baseUrl}?${param}=${encodeURIComponent(payload)}`;

          const response = await httpClient.get(testUrl, {
            timeout: 10000,
            headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
            maxRedirects: 0, // Don't follow redirects — we want to detect them
            validateStatus: s => s < 500,
          });

          const status = response.status;
          const location = response.headers['location'] || '';

          // Check for redirect (3xx) that goes to our test domain
          if (status >= 301 && status <= 308 && location) {
            if (location.includes('example.com')) {
              vulnerabilities.push({
                type: 'open-redirect',
                severity: 'high',
                title: 'Open Redirect Vulnerability',
                description: `Parameter "${param}" redirects to user-controlled URL without validation. An attacker can use this to phish users.`,
                endpoint: baseUrl,
                parameter: param,
                payload: `${param}=${payload}`,
                evidence: `Test URL: ${testUrl}\nStatus: ${status}\nLocation: ${location}\nParameter: ${param}\nPayload: ${payload}\nThis allows redirecting users to arbitrary external sites.`,
                remediation: 'Never redirect based on user input without validation. Use a whitelist of allowed redirect destinations. Consider using indirect references instead of actual URLs.',
                owasp_category: 'A01:2021 – Broken Access Control',
                cve_id: 'CWE-601',
              });

              break; // One finding per parameter is enough
            }
          }

          // Check for JS-based redirects or reflected URLs in the body
          if (status === 200) {
            const responseBody = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || '');
            const hasJsRedirect = responseBody.includes(`location.href`) && responseBody.includes('example.com');
            const hasMetaRedirect = responseBody.includes(`http-equiv="refresh"`) && responseBody.includes('example.com');
            const hasReflectedPayload = responseBody.includes(payload) && !responseBody.includes('\\' + payload);

            if ((hasJsRedirect || hasMetaRedirect) && hasReflectedPayload) {
              vulnerabilities.push({
                type: 'open-redirect',
                severity: 'medium',
                title: 'Potential Open Redirect (Client-Side)',
                description: `Parameter "${param}" is reflected in a redirect mechanism (JS or meta refresh). May allow phishing if controllable.`,
                endpoint: baseUrl,
                parameter: param,
                payload: `${param}=${payload}`,
                evidence: `Test URL: ${testUrl}\nJS Redirect: ${hasJsRedirect}\nMeta Refresh: ${hasMetaRedirect}\nPayload Reflected: ${hasReflectedPayload}\nClient-side redirects can be used for phishing.`,
                remediation: 'Avoid client-side redirects based on URL parameters. If needed, validate and sanitize all redirect targets.',
                owasp_category: 'A01:2021 – Broken Access Control',
                cve_id: 'CWE-601',
              });

              break;
            }
          }
        } catch (err) {
          continue;
        }
      }
    }
  } catch (err) {
    // Connection error - can't test
  }

  return vulnerabilities;
}

module.exports = { scanOpenRedirect, COMMON_REDIRECT_PARAMS };
