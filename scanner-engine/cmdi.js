const CMDI_PARAMS = ['cmd', 'command', 'exec', 'ping', 'run', 'system', 'shell', 'dir', 'wget', 'curl', 'host', 'ip', 'nslookup', 'traceroute'];
const { CMDI_PAYLOADS_ENHANCED } = require('./payload-expansion');
const CMDI_PAYLOADS = CMDI_PAYLOADS_ENHANCED;

async function scanCMDI(targetUrl, httpClient) {
  const vulnerabilities = [];
  const baseUrl = targetUrl.replace(/\/$/, '');

  for (const param of CMDI_PARAMS) {
    let found = false;
    const CHUNK_SIZE = 4;
    for (let i = 0; i < CMDI_PAYLOADS.length; i += CHUNK_SIZE) {
      if (found) break;
      const chunk = CMDI_PAYLOADS.slice(i, i + CHUNK_SIZE);
      const results = await Promise.all(chunk.map(test =>
        (async () => {
          try {
            const testUrl = `${baseUrl}?${param}=${encodeURIComponent(test.payload)}`;
            const startTime = Date.now();
            const response = await httpClient.get(testUrl, {
              timeout: 10000,
              headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
              validateStatus: s => s < 500,
            });
            const responseTime = Date.now() - startTime;
            const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || '');

            if (body.includes(test.indicator) || responseTime > 3000) {
              return {
                type: 'command-injection',
                severity: 'critical',
                title: `Command Injection - ${test.name}`,
                description: `Parameter "${param}" may be vulnerable to command injection using ${test.name}.`,
                endpoint: baseUrl,
                parameter: param,
                payload: `${param}=${test.payload}`,
                evidence: `Test URL: ${testUrl}\nParameter: ${param}\nPayload: ${test.payload}\nIndicator: ${body.includes(test.indicator) ? `Found "${test.indicator}" in response` : 'Time-based detection'}\nResponse time: ${responseTime}ms`,
                remediation: 'Never pass user input directly to system commands. Use language-native APIs instead. Implement strict input validation with allowlists.',
                owasp_category: 'A03:2021 – Injection',
                cve_id: 'CWE-78',
              };
            }
          } catch (err) {}
          return null;
        })()
      ));
      for (const r of results) {
        if (r) { vulnerabilities.push(r); found = true; break; }
      }
    }
  }
  return vulnerabilities;
}

module.exports = { scanCMDI, CMDI_PARAMS, CMDI_PAYLOADS };