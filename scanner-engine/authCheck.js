const DEFAULT_CREDENTIALS = [
  { user: 'admin', pass: 'admin', description: 'admin/admin' },
  { user: 'admin', pass: 'password', description: 'admin/password' },
  { user: 'admin', pass: 'admin123', description: 'admin/admin123' },
  { user: 'root', pass: 'root', description: 'root/root' },
  { user: 'root', pass: 'toor', description: 'root/toor' },
  { user: 'user', pass: 'user', description: 'user/user' },
  { user: 'test', pass: 'test', description: 'test/test' },
  { user: 'guest', pass: 'guest', description: 'guest/guest' },
  { user: 'admin', pass: '123456', description: 'admin/123456' },
  { user: 'admin', pass: 'letmein', description: 'admin/letmein' },
  { user: 'administrator', pass: 'administrator', description: 'administrator/administrator' },
  { user: 'sa', pass: 'sa', description: 'sa/sa (SQL Server)' },
];

const WEAK_PASSWORD_PATTERNS = [
  { pattern: /^(?=.*[a-z])$/i, desc: 'Only letters' },
  { pattern: /^(?=.*\d)(?=.*[a-z])$/i, desc: 'Alphanumeric only' },
  { pattern: /^.{1,5}$/, desc: 'Too short (< 6 chars)' },
  { pattern: /^(password|admin|root|letmein|123456|qwerty)$/i, desc: 'Common password' },
];

async function scanAuth(targetUrl, httpClient) {
  const vulnerabilities = [];

  try {
    const response = await httpClient.get(targetUrl, {
      timeout: 15000,
      headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' }
    });

    const body = typeof response.data === 'string' ? response.data : '';
    const hasLoginForm = /<form[^>]*(?:login|signin|auth|log-in)[^>]*>/i.test(body) ||
                         /<input[^>]*(?:password|passwd)[^>]*>/i.test(body);
    const hasLoginEndpoint = /\/login|\/signin|\/auth|\/admin/i.test(targetUrl);

    if (hasLoginForm || hasLoginEndpoint) {
      vulnerabilities.push({
        type: 'authentication',
        severity: 'info',
        title: 'Authentication Endpoint Detected',
        description: 'Login form or authentication endpoint found. Should be tested for credential weaknesses.',
        endpoint: targetUrl,
        parameter: 'N/A',
        payload: 'Login form detected',
        evidence: `URL contains login-related path: ${hasLoginEndpoint}\nForm found in HTML: ${hasLoginForm}`,
        remediation: 'Ensure login endpoints implement account lockout, rate limiting, and strong password policies.'
      });

      const credResults = await Promise.allSettled(DEFAULT_CREDENTIALS.map(cred =>
        httpClient.post(targetUrl,
          new URLSearchParams({
            username: cred.user,
            password: cred.pass,
            submit: 'Login'
          }).toString(),
          {
            timeout: 8000,
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0'
            },
            maxRedirects: 3,
            validateStatus: status => status < 500
          }
        ).then(loginResponse => {
          if (loginResponse.status === 302 ||
              (loginResponse.data && (
                loginResponse.data.includes('Welcome') ||
                loginResponse.data.includes('Dashboard') ||
                loginResponse.data.includes('Logout') ||
                !loginResponse.data.includes('Invalid')
              ))) {
            return { cred, loginResponse };
          }
          return null;
        })
      ));

      for (const result of credResults) {
        if (result.status === 'fulfilled' && result.value) {
          const { cred, loginResponse } = result.value;
          vulnerabilities.push({
            type: 'authentication',
            severity: 'critical',
            title: 'Default Credentials Accepted',
            description: `Default credentials ${cred.description} were accepted by the server. This is a critical security flaw.`,
            endpoint: targetUrl,
            parameter: 'username, password',
            payload: `${cred.user}:${cred.pass}`,
            evidence: `Credentials: ${cred.user} / ${cred.pass}\nHTTP Status: ${loginResponse.status}\nRedirect/Login detected: Successful authentication`,
            remediation: 'Change all default credentials immediately. Implement mandatory password change on first login. Use strong password policies.',
            owasp_category: 'A07:2021 – Identification and Authentication Failures',
            cve_id: 'CWE-798'
          });
        }
      }

      const cookies = response.headers['set-cookie'] || [];
      for (const cookie of cookies) {
        if (cookie.toLowerCase().includes('session') || cookie.toLowerCase().includes('token')) {
          if (!cookie.toLowerCase().includes('secure')) {
            vulnerabilities.push({
              type: 'authentication',
              severity: 'high',
              title: 'Session Cookie Missing Secure Flag',
              description: 'Authentication session cookie does not have the Secure flag set.',
              endpoint: targetUrl,
              parameter: 'N/A (Session Cookie)',
              payload: cookie.split(';')[0],
              evidence: `Cookie: ${cookie.split(';')[0]}\nMissing: Secure flag\nRisk: Cookie transmitted over unencrypted HTTP`,
              remediation: 'Set Secure flag on all session cookies. Enforce HTTPS across the entire site.',
              owasp_category: 'A07:2021 – Identification and Authentication Failures',
              cve_id: 'CWE-614'
            });
          }

          if (!cookie.toLowerCase().includes('httponly')) {
            vulnerabilities.push({
              type: 'authentication',
              severity: 'medium',
              title: 'Session Cookie Missing HttpOnly Flag',
              description: 'Session cookie lacks HttpOnly flag, making it accessible to JavaScript (XSS risk).',
              endpoint: targetUrl,
              parameter: 'N/A (Session Cookie)',
              payload: cookie.split(';')[0],
              evidence: `Cookie: ${cookie.split(';')[0]}\nMissing: HttpOnly flag\nRisk: Cookie accessible via document.cookie`,
              remediation: 'Set HttpOnly flag on all session cookies to prevent XSS-based cookie theft.',
              owasp_category: 'A07:2021 – Identification and Authentication Failures',
              cve_id: 'CWE-1004'
            });
          }
        }
      }
    }

  } catch (err) {
    // Connection error - skip auth check
  }

  return vulnerabilities;
}

module.exports = { scanAuth, DEFAULT_CREDENTIALS, WEAK_PASSWORD_PATTERNS };
