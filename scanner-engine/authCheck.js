'use strict';

const { mkFinding, CONFIDENCE } = require('./evidence');

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

  let response;
  try {
    response = await httpClient.get(targetUrl, {
      timeout: 15000,
      headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
      maxRedirects: 3,
    });
  } catch {
    // Target unreachable - nothing meaningful can be assessed
    return vulnerabilities;
  }

  const body = typeof response.data === 'string' ? response.data : '';
  const hasLoginForm =
    /<form[^>]*(?:login|signin|auth|log-in)[^>]*>/i.test(body) ||
    /<input[^>]*(?:password|passwd)[^>]*>/i.test(body);
  const hasLoginEndpoint = /\/login|\/signin|\/auth|\/admin/i.test(targetUrl);

  if (!hasLoginForm && !hasLoginEndpoint) {
    return vulnerabilities;
  }

  vulnerabilities.push(mkFinding('auth', {
    type: 'authentication',
    severity: 'info',
    confidence: CONFIDENCE.CONFIRMED,
    title: 'Authentication Endpoint Detected',
    description: 'Login form or authentication endpoint found. Should be reviewed for credential hygiene.',
    endpoint: targetUrl,
    parameter: 'N/A',
    payload: 'Login form detected',
    evidence: `URL contains login-related path: ${hasLoginEndpoint}\nForm found in HTML: ${hasLoginForm}`,
    remediation: 'Enforce strong password policies, account lockout, and rate limiting on login endpoints.',
    owasp_category: 'A07:2021 – Identification and Authentication Failures',
    cve_id: 'CWE-306',
  }));

  const cookies = response.headers['set-cookie'] || [];
  for (const cookie of cookies) {
    if (!/session|token|sid|auth/i.test(cookie)) continue;
    const name = cookie.split(';')[0];

    if (!/;\s*secure/i.test(cookie)) {
      vulnerabilities.push(mkFinding('auth', {
        type: 'authentication',
        severity: 'medium',
        confidence: CONFIDENCE.CONFIRMED,
        title: 'Session Cookie Missing Secure Flag',
        description: 'Authentication session cookie is not restricted to HTTPS (Secure attribute absent).',
        endpoint: targetUrl,
        parameter: 'N/A (Session Cookie)',
        payload: name,
        evidence: `Cookie: ${name}\nMissing attribute: Secure`,
        remediation: 'Set Secure on session cookies and enforce HTTPS across the site.',
        owasp_category: 'A07:2021 – Identification and Authentication Failures',
        cve_id: 'CWE-614',
      }));
    }

    if (!/;\s*httponly/i.test(cookie)) {
      vulnerabilities.push(mkFinding('auth', {
        type: 'authentication',
        severity: 'low',
        confidence: CONFIDENCE.CONFIRMED,
        title: 'Session Cookie Missing HttpOnly Flag',
        description: 'Session cookie is readable by client-side JavaScript, increasing the impact of XSS.',
        endpoint: targetUrl,
        parameter: 'N/A (Session Cookie)',
        payload: name,
        evidence: `Cookie: ${name}\nMissing attribute: HttpOnly`,
        remediation: 'Set HttpOnly on session cookies to block document.cookie access.',
        owasp_category: 'A07:2021 – Identification and Authentication Failures',
        cve_id: 'CWE-1004',
      }));
    }
  }

  const credResults = await Promise.allSettled(DEFAULT_CREDENTIALS.map(cred =>
    httpClient.post(
      targetUrl,
      new URLSearchParams({ username: cred.user, password: cred.pass, submit: 'Login' }).toString(),
      {
        timeout: 8000,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0',
        },
        maxRedirects: 0,
        validateStatus: status => status < 500,
      }
    ).then(loginResponse => {
      if (loginResponse.status !== 302 && loginResponse.status !== 303) return null;
      const location = String(loginResponse.headers['location'] || '').toLowerCase();
      if (/login|signin|\/auth|log-?in/i.test(location)) return null;
      const cookies = loginResponse.headers['set-cookie'] || [];
      if (!cookies.some(c => /session|token|sid|auth/i.test(c))) return null;
      return { cred, loginResponse, location };
    })
  ));

  for (const result of credResults) {
    if (result.status !== 'fulfilled' || !result.value) continue;
    const { cred, loginResponse, location } = result.value;
    vulnerabilities.push(mkFinding('auth', {
      type: 'authentication',
      severity: 'critical',
      confidence: CONFIDENCE.POTENTIAL,
      title: 'Possible Default Credentials Accepted (Unverified)',
      description: `Login attempt with default credentials "${cred.description}" caused an HTTP ${loginResponse.status} redirect away from the login page and set a session cookie. An automated check cannot prove the login succeeded, so this requires manual verification.`,
      endpoint: targetUrl,
      parameter: 'username, password',
      payload: `${cred.user}:${cred.pass}`,
      evidence: `Credentials tried: ${cred.user} / ${cred.pass}\nHTTP Status: ${loginResponse.status}\nRedirect Location: ${location}\nSession cookie set: yes`,
      remediation: 'Change all default credentials immediately and enforce a password change on first login.',
      owasp_category: 'A07:2021 – Identification and Authentication Failures',
      cve_id: 'CWE-798',
    }));
  }

  return vulnerabilities;
}

module.exports = { scanAuth, DEFAULT_CREDENTIALS, WEAK_PASSWORD_PATTERNS };