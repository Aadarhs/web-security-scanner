async function scanServerStatus(targetUrl, httpClient) {
  const vulnerabilities = [];
  const baseUrl = targetUrl.replace(/\/$/, '');
  let host;
  try {
    host = new URL(targetUrl).hostname;
  } catch {
    return [{ type: 'server-status', severity: 'info', title: 'Invalid URL', description: 'Could not parse hostname', endpoint: targetUrl, parameter: 'N/A', payload: 'N/A', evidence: 'Invalid URL', remediation: 'N/A', owasp_category: 'N/A', cve_id: 'N/A' }];
  }

  const probeEndpoints = [
    { path: '/', name: 'Root' },
    { path: '/health', name: 'Health Check' },
    { path: '/healthz', name: 'Healthz' },
    { path: '/status', name: 'Status' },
    { path: '/api/health', name: 'API Health' },
    { path: '/.well-known/security.txt', name: 'Security Contact' },
    { path: '/.well-known/', name: 'Well-Known' },
  ];

  for (const ep of probeEndpoints) {
    try {
      const startTime = Date.now();
      const response = await httpClient.get(baseUrl + ep.path, {
        timeout: 8000,
        headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
        validateStatus: s => s < 600,
      });
      const responseTime = Date.now() - startTime;
      const server = response.headers['server'] || 'Unknown';
      const poweredBy = response.headers['x-powered-by'] || '';
      const contentType = response.headers['content-type'] || 'Unknown';
      const contentLength = response.headers['content-length'] || (typeof response.data === 'string' ? response.data.length : 'N/A');

      if (ep.path === '/') {
        vulnerabilities.push({
          type: 'server-status',
          severity: 'info',
          title: `Server Response Analysis - ${host}`,
          description: `Server responded in ${responseTime}ms with status ${response.status}.`,
          endpoint: baseUrl + ep.path,
          parameter: 'N/A',
          payload: `GET ${ep.path}`,
          evidence: `URL: ${baseUrl}${ep.path}\nStatus: ${response.status}\nResponse Time: ${responseTime}ms\nServer: ${server}\nX-Powered-By: ${poweredBy || 'Not set'}\nContent-Type: ${contentType}\nContent-Length: ${contentLength}`,
          remediation: 'Remove server version headers. Minimize information disclosure in responses.',
          owasp_category: 'A05:2021 – Security Misconfiguration',
          cve_id: 'CWE-200',
        });

        if (responseTime > 3000) {
          vulnerabilities.push({
            type: 'server-status',
            severity: 'medium',
            title: 'Slow Server Response Time',
            description: `Server responded in ${responseTime}ms which may indicate performance issues or DoS vulnerability.`,
            endpoint: baseUrl,
            parameter: 'N/A',
            payload: `GET ${ep.path}`,
            evidence: `Response time: ${responseTime}ms\nThreshold: >3000ms`,
            remediation: 'Optimize server performance. Implement caching and CDN. Consider rate limiting to prevent resource exhaustion.',
            owasp_category: 'A04:2021 – Insecure Design',
            cve_id: 'CWE-400',
          });
        }
      }

      if (['/health', '/healthz', '/status', '/api/health'].includes(ep.path) && response.status === 200) {
        vulnerabilities.push({
          type: 'server-status',
          severity: 'info',
          title: `Health Endpoint Exposed - ${ep.path}`,
          description: `Health check endpoint at ${ep.path} responds with status ${response.status}. May leak system information.`,
          endpoint: baseUrl + ep.path,
          parameter: 'N/A',
          payload: `GET ${ep.path}`,
          evidence: `URL: ${baseUrl}${ep.path}\nStatus: ${response.status}\nResponse: ${JSON.stringify(response.data).substring(0, 200)}`,
          remediation: 'Ensure health endpoints do not leak sensitive system information. Restrict access to internal networks if possible.',
          owasp_category: 'A05:2021 – Security Misconfiguration',
          cve_id: 'CWE-200',
        });
      }

      if (ep.path === '/.well-known/security.txt' && response.status === 200) {
        vulnerabilities.push({
          type: 'server-status',
          severity: 'info',
          title: 'Security Contact Information Found',
          description: `Server has a security.txt file for vulnerability disclosure. This is a best practice.`,
          endpoint: baseUrl + ep.path,
          parameter: 'N/A',
          payload: `GET ${ep.path}`,
          evidence: `URL: ${baseUrl}${ep.path}\nStatus: ${response.status}\nContent: ${typeof response.data === 'string' ? response.data.substring(0, 500) : 'N/A'}`,
          remediation: 'Maintain the security.txt with up-to-date contact information.',
          owasp_category: 'A05:2021 – Security Misconfiguration',
          cve_id: 'CWE-200',
        });
      }

      if (server !== 'Unknown' && ep.path === '/') {
        vulnerabilities.push({
          type: 'server-status',
          severity: 'info',
          title: `Server Information Disclosure - ${server}`,
          description: `Server header reveals: ${server}${poweredBy ? ', X-Powered-By: ' + poweredBy : ''}. This information aids attackers.`,
          endpoint: baseUrl,
          parameter: 'N/A',
          payload: 'Server header analysis',
          evidence: `Server: ${server}\nX-Powered-By: ${poweredBy || 'Not set'}`,
          remediation: 'Remove or obfuscate server version headers. Use generic values like "webserver".',
          owasp_category: 'A05:2021 – Security Misconfiguration',
          cve_id: 'CWE-200',
        });
      }
    } catch (err) {
      continue;
    }
  }

  return vulnerabilities;
}

module.exports = { scanServerStatus };