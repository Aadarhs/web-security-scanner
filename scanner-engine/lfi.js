const { LFI_PAYLOADS_ENHANCED } = require('./payload-expansion');
const LFI_PAYLOADS = LFI_PAYLOADS_ENHANCED;

const TEST_PARAMS = ['file', 'page', 'load', 'path', 'include'];

async function scanLFI(targetUrl, httpClient) {
  const vulnerabilities = [];
  const baseUrl = targetUrl.replace(/\/$/, '');

  // Test common parameter names with LFI payloads (parallel per param)
  for (const param of TEST_PARAMS) {
    const paramResults = await Promise.allSettled(LFI_PAYLOADS.map(test => {
      const testUrl = `${baseUrl}?${param}=${encodeURIComponent(test.payload)}`;

      return httpClient.get(testUrl, {
        timeout: 5000,
        headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
        validateStatus: status => status < 500,
      }).then(response => {
        const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || '');

        const hasIndicator = body.includes(test.indicator);
        const isRootFile = test.payload.includes('passwd') && hasIndicator;
        const isWinIni = test.payload.includes('win.ini') && (body.includes('[fonts]') || body.includes('[extensions]'));

        if (isRootFile || isWinIni) {
          return { type: 'lfi', param, test, testUrl, body };
        }

        if (body.includes('base64_decode') || body.includes('expect:')) {
          return { type: 'phpwrapper', param, test, testUrl };
        }

        return null;
      });
    }));

    for (const result of paramResults) {
      if (result.status === 'fulfilled' && result.value) {
        const found = result.value;
        if (found.type === 'lfi') {
          vulnerabilities.push({
            type: 'lfi',
            severity: 'critical',
            title: `Local File Inclusion (LFI) - ${found.test.name}`,
            description: `Parameter "${found.param}" is vulnerable to LFI. An attacker can read arbitrary files on the server using path traversal: ${found.test.payload}`,
            endpoint: baseUrl,
            parameter: found.param,
            payload: `${found.param}=${found.test.payload}`,
            evidence: `Test URL: ${found.testUrl}\nParameter: ${found.param}\nPayload: ${found.test.payload}\nIndicator found: "${found.test.indicator}"\nFirst 300 chars of response:\n${found.body.substring(0, 300)}`,
            remediation: 'Do not use user input to construct file paths. Use a whitelist of allowed files. Disable PHP allow_url_fopen and allow_url_include. Use a database to map identifiers to file paths.',
            owasp_category: 'A01:2021 – Broken Access Control',
            cve_id: 'CWE-22',
          });
        } else {
          vulnerabilities.push({
            type: 'lfi',
            severity: 'high',
            title: 'Potential PHP Wrapper LFI',
            description: `Parameter "${found.param}" may be vulnerable to PHP wrapper-based LFI.`,
            endpoint: baseUrl,
            parameter: found.param,
            payload: `${found.param}=${found.test.payload}`,
            evidence: `PHP wrapper indicators found with payload: ${found.test.payload}`,
            remediation: 'Disable allow_url_include and allow_url_fopen. Filter PHP wrapper keywords (php://, expect://, etc.).',
            owasp_category: 'A01:2021 – Broken Access Control',
            cve_id: 'CWE-22',
          });
        }
        break;
      }
    }
  }

  return vulnerabilities;
}

module.exports = { scanLFI, LFI_PAYLOADS, TEST_PARAMS };
