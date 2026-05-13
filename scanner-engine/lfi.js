const LFI_PAYLOADS = [
  { payload: '../../../etc/passwd', os: 'unix', indicator: 'root:', name: 'Unix /etc/passwd' },
  { payload: '..\\..\\..\\windows\\win.ini', os: 'windows', indicator: '[fonts]', name: 'Windows win.ini' },
  { payload: '....//....//....//etc/passwd', os: 'unix', indicator: 'root:', name: 'Dot-dot bypass' },
  { payload: '..%252f..%252f..%252fetc/passwd', os: 'unix', indicator: 'root:', name: 'Double URL encoding' },
  { payload: '/etc/passwd', os: 'unix', indicator: 'root:', name: 'Absolute path' },
];

const TEST_PARAMS = ['file', 'page', 'load', 'path', 'include'];

async function scanLFI(targetUrl, httpClient) {
  const vulnerabilities = [];
  const baseUrl = targetUrl.replace(/\/$/, '');

  // Test common parameter names with LFI payloads
  for (const param of TEST_PARAMS) {
    for (const test of LFI_PAYLOADS) {
      try {
        const testUrl = `${baseUrl}?${param}=${encodeURIComponent(test.payload)}`;

        const response = await httpClient.get(testUrl, {
          timeout: 5000,
          headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
          validateStatus: status => status < 500,
        });

        const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || '');
        const lowerBody = body.toLowerCase();

        // Check for successful inclusion indicators
        const hasIndicator = body.includes(test.indicator);
        const isRootFile = test.payload.includes('passwd') && hasIndicator;
        const isWinIni = test.payload.includes('win.ini') && (body.includes('[fonts]') || body.includes('[extensions]'));

        if (isRootFile || isWinIni) {
          vulnerabilities.push({
            type: 'lfi',
            severity: 'critical',
            title: `Local File Inclusion (LFI) - ${test.name}`,
            description: `Parameter "${param}" is vulnerable to LFI. An attacker can read arbitrary files on the server using path traversal: ${test.payload}`,
            endpoint: baseUrl,
            parameter: param,
            payload: `${param}=${test.payload}`,
            evidence: `Test URL: ${testUrl}\nParameter: ${param}\nPayload: ${test.payload}\nIndicator found: "${test.indicator}"\nFirst 300 chars of response:\n${body.substring(0, 300)}`,
            remediation: 'Do not use user input to construct file paths. Use a whitelist of allowed files. Disable PHP allow_url_fopen and allow_url_include. Use a database to map identifiers to file paths.',
            owasp_category: 'A01:2021 – Broken Access Control',
            cve_id: 'CWE-22',
          });

          break; // Found LFI for this parameter, move to next
        }

        // Check for PHP wrapper usage indicators
        if (body.includes('base64_decode') || body.includes('expect:')) {
          vulnerabilities.push({
            type: 'lfi',
            severity: 'high',
            title: 'Potential PHP Wrapper LFI',
            description: `Parameter "${param}" may be vulnerable to PHP wrapper-based LFI.`,
            endpoint: baseUrl,
            parameter: param,
            payload: `${param}=${test.payload}`,
            evidence: `PHP wrapper indicators found with payload: ${test.payload}`,
            remediation: 'Disable allow_url_include and allow_url_fopen. Filter PHP wrapper keywords (php://, expect://, etc.).',
            owasp_category: 'A01:2021 – Broken Access Control',
            cve_id: 'CWE-22',
          });

          break;
        }
      } catch (err) {
        continue;
      }
    }
  }

  return vulnerabilities;
}

module.exports = { scanLFI, LFI_PAYLOADS, TEST_PARAMS };
