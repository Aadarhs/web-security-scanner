const CMDI_PARAMS = ['cmd', 'command', 'exec', 'ping', 'run', 'system', 'shell', 'dir', 'wget', 'curl', 'host', 'ip', 'nslookup', 'traceroute'];
const CMDI_PAYLOADS = [
  { payload: '; ping -c 3 127.0.0.1', os: 'unix', indicator: 'PING', name: 'Basic command chaining' },
  { payload: '| ping -n 3 127.0.0.1', os: 'windows', indicator: 'PING', name: 'Pipe command injection' },
  { payload: '&& ping -c 3 127.0.0.1', os: 'unix', indicator: 'PING', name: 'AND chaining' },
  { payload: '`ping -c 3 127.0.0.1`', os: 'unix', indicator: 'PING', name: 'Backtick injection' },
  { payload: '$(ping -c 3 127.0.0.1)', os: 'unix', indicator: 'PING', name: 'Subshell injection' },
  { payload: '; echo CMITEST_$(whoami)', os: 'unix', indicator: 'CMITEST_', name: 'Command output capture' },
  { payload: '| echo CMITEST_%USERNAME%', os: 'windows', indicator: 'CMITEST_', name: 'Windows command output' },
  { payload: '& ping -n 3 127.0.0.1 &', os: 'all', indicator: 'PING', name: 'Background chaining' },
];

async function scanCMDI(targetUrl, httpClient) {
  const vulnerabilities = [];
  const baseUrl = targetUrl.replace(/\/$/, '');

  for (const param of CMDI_PARAMS) {
    for (const test of CMDI_PAYLOADS) {
      try {
        const testUrl = `${baseUrl}?${param}=${encodeURIComponent(test.payload)}`;
        const startTime = Date.now();
        const response = await httpClient.get(testUrl, {
          timeout: 15000,
          headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
          validateStatus: s => s < 500,
        });
        const responseTime = Date.now() - startTime;
        const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || '');

        if (body.includes(test.indicator) || responseTime > 3000) {
          vulnerabilities.push({
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

module.exports = { scanCMDI, CMDI_PARAMS, CMDI_PAYLOADS };