const SENSITIVE_PATHS = [
  { path: '/.git/HEAD', severity: 'critical', title: 'Exposed Git Repository', category: 'A05:2021 – Security Misconfiguration', cve: 'CWE-200', desc: 'Git repository exposed. Source code, credentials, and history are accessible.' },
  { path: '/.git/config', severity: 'critical', title: 'Exposed Git Config', category: 'A05:2021 – Security Misconfiguration', cve: 'CWE-200', desc: 'Git config file exposed. May contain credentials and repository metadata.' },
  { path: '/.env', severity: 'critical', title: 'Exposed Environment File', category: 'A05:2021 – Security Misconfiguration', cve: 'CWE-200', desc: 'Environment file with API keys, DB credentials, and secrets exposed.' },
  { path: '/admin', severity: 'high', title: 'Admin Panel Exposed', category: 'A07:2021 – Identification and Authentication Failures', cve: 'CWE-306', desc: 'Admin login panel publicly accessible without restriction.' },
  { path: '/backup', severity: 'high', title: 'Backup Directory Exposed', category: 'A05:2021 – Security Misconfiguration', cve: 'CWE-530', desc: 'Backup directory exposed. May contain sensitive data.' },
  { path: '/dump.sql', severity: 'critical', title: 'Database Dump Exposed', category: 'A05:2021 – Security Misconfiguration', cve: 'CWE-200', desc: 'SQL database dump publicly accessible.' },
  { path: '/phpinfo.php', severity: 'critical', title: 'PHP Info Disclosure', category: 'A05:2021 – Security Misconfiguration', cve: 'CWE-200', desc: 'phpinfo() exposes PHP configuration, environment variables, and server details.' },
  { path: '/robots.txt', severity: 'low', title: 'Robots.txt - Possible Hidden Paths', category: 'A01:2021 – Broken Access Control', cve: 'CWE-200', desc: 'robots.txt may reveal hidden/disallowed paths to attackers.' },
  { path: '/sitemap.xml', severity: 'info', title: 'Sitemap XML - Endpoint Discovery', category: 'A01:2021 – Broken Access Control', cve: 'CWE-200', desc: 'Sitemap helps attackers discover all site endpoints.' },
  { path: '/.htaccess', severity: 'high', title: 'Exposed .htaccess File', category: 'A05:2021 – Security Misconfiguration', cve: 'CWE-200', desc: 'Apache .htaccess configuration file exposed.' },
  { path: '/crossdomain.xml', severity: 'medium', title: 'Crossdomain.xml Policy File', category: 'A01:2021 – Broken Access Control', cve: 'CWE-942', desc: 'Flash crossdomain policy file may allow overly permissive cross-domain requests.' },
  { path: '/server-status', severity: 'medium', title: 'Apache Server Status Exposed', category: 'A05:2021 – Security Misconfiguration', cve: 'CWE-200', desc: 'Apache server-status page exposes request metrics and server info.' },
  { path: '/actuator/health', severity: 'medium', title: 'Spring Boot Actuator Health', category: 'A05:2021 – Security Misconfiguration', cve: 'CWE-200', desc: 'Spring Boot actuator health endpoint exposed without restriction.' },
  { path: '/actuator/env', severity: 'critical', title: 'Spring Boot Env Exposed', category: 'A05:2021 – Security Misconfiguration', cve: 'CWE-200', desc: 'Spring Boot environment variables including keys and secrets exposed.' },
  { path: '/wp-admin', severity: 'high', title: 'WordPress Admin Exposed', category: 'A07:2021 – Identification and Authentication Failures', cve: 'CWE-306', desc: 'WordPress admin panel publicly accessible.' },
  { path: '/wp-config.php.bak', severity: 'critical', title: 'WordPress Config Backup', category: 'A05:2021 – Security Misconfiguration', cve: 'CWE-200', desc: 'WordPress config backup may expose DB credentials and salts.' },
  { path: '/config.php~', severity: 'high', title: 'Backup Config File', category: 'A05:2021 – Security Misconfiguration', cve: 'CWE-200', desc: 'Editor backup of config file containing sensitive configuration.' },
  { path: '/.DS_Store', severity: 'low', title: 'Exposed .DS_Store File', category: 'A05:2021 – Security Misconfiguration', cve: 'CWE-200', desc: 'macOS .DS_Store file exposes directory structure.' },
  { path: '/api/swagger.json', severity: 'medium', title: 'Swagger/OpenAPI Spec Exposed', category: 'A01:2021 – Broken Access Control', cve: 'CWE-200', desc: 'API specification exposed, revealing all endpoints and data schemas.' },
  { path: '/graphql', severity: 'medium', title: 'GraphQL Endpoint Exposed', category: 'A01:2021 – Broken Access Control', cve: 'CWE-200', desc: 'GraphQL introspection may expose entire API schema.' },
];

async function scanDirectory(targetUrl, httpClient) {
  const vulnerabilities = [];
  const baseUrl = targetUrl.replace(/\/$/, '');

  const results = await Promise.allSettled(
    SENSITIVE_PATHS.map(async (item) => {
      const testUrl = baseUrl + item.path;
      try {
        const response = await httpClient.get(testUrl, {
          timeout: 8000,
          headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
          validateStatus: status => status < 500,
        });

        if (response.status === 200) {
          const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || '');
          const contentLen = body.length;

          // Skip empty or auto-generated pages
          if (contentLen < 50) return null;

          // Skip HTML pages (likely a catch-all/404 page, not a real file)
          const htmlIndicators = ['<!DOCTYPE', '<html', '<!doctype'];
          if (htmlIndicators.some(h => body.startsWith(h) || body.includes(h))) return null;

          // Git HEAD file should contain "ref:"
          if (item.path === '/.git/HEAD' && !body.includes('ref:')) return null;
          // .env should contain '=' pattern
          if (item.path === '/.env' && !body.includes('=')) return null;
          // robots.txt specific checks
          if (item.path === '/robots.txt' && !body.match(/(Disallow|Allow|Sitemap):/i)) return null;

          return {
            type: 'sensitive-exposure',
            severity: item.severity,
            title: item.title,
            description: `${item.desc} (Path: ${item.path}, Size: ${contentLen} bytes)`,
            endpoint: testUrl,
            parameter: 'N/A (Path)',
            payload: `GET ${item.path} → ${response.status}`,
            evidence: `URL: ${testUrl}\nStatus: ${response.status}\nSize: ${contentLen} bytes\nFirst 200 chars: ${body.substring(0, 200).replace(/[\x00-\x1f]/g, '.')}`,
            remediation: `Remove or restrict access to ${item.path}. Implement proper access controls and never commit secrets to version control.`,
            owasp_category: item.category,
            cve_id: item.cve,
          };
        }

        // 403 means the path exists but access is denied - still notable
        if (response.status === 403) {
          return {
            type: 'sensitive-exposure',
            severity: 'info',
            title: `Access Denied - ${item.title}`,
            description: `Path ${item.path} exists but returns 403 Forbidden. May indicate a valid restricted resource.`,
            endpoint: testUrl,
            parameter: 'N/A (Path)',
            payload: `GET ${item.path} → 403`,
            evidence: `URL: ${testUrl}\nStatus: 403 Forbidden\nThe path exists but access is restricted.`,
            remediation: 'Ensure the resource is not accidentally exposed and proper authentication is enforced.',
            owasp_category: 'A01:2021 – Broken Access Control',
            cve_id: 'CWE-200',
          };
        }

        return null;
      } catch (err) {
        return null;
      }
    })
  );

  for (const result of results) {
    if (result.status === 'fulfilled' && result.value) {
      vulnerabilities.push(result.value);
    }
  }

  return vulnerabilities;
}

module.exports = { scanDirectory, SENSITIVE_PATHS };
