const axios = require('axios');
const cheerio = require('cheerio');

async function scanCSRF(targetUrl, httpClient) {
  const vulnerabilities = [];
  const formsToCheck = [];

  try {
    const response = await httpClient.get(targetUrl, {
      timeout: 15000,
      headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
      maxRedirects: 5,
    });

    const cookies = response.headers['set-cookie'] || [];

    for (const cookie of cookies) {
      if (!cookie.toLowerCase().includes('samesite')) {
        vulnerabilities.push({
          type: 'csrf',
          severity: 'medium',
          title: 'Missing SameSite Cookie Attribute',
          description: 'Cookies are set without SameSite attribute, making them vulnerable to CSRF attacks in some browsers.',
          endpoint: targetUrl,
          parameter: 'N/A (Cookie)',
          payload: cookie.split(';')[0],
          evidence: `Cookie: ${cookie.split(';')[0]}\nMissing: SameSite attribute\nRisk: Cookie sent on cross-site requests`,
          remediation: 'Set SameSite=Lax or SameSite=Strict on all cookies. Implement CSRF tokens for state-changing requests.',
          owasp_category: 'A01:2021 – Broken Access Control',
          cve_id: 'CWE-352'
        });
      }
    }

    const body = typeof response.data === 'string' ? response.data : '';
    if (!body) return vulnerabilities;

    const $ = cheerio.load(body);

    $('form').each((i, form) => {
      const $form = $(form);
      const action = $form.attr('action') || targetUrl;
      const method = ($form.attr('method') || 'get').toUpperCase();
      const hasCSRFToken = $form.find('input[name*="csrf"], input[name*="token"], input[name*="_token"], input[name*="authenticity_token"]').length > 0;

      if (method === 'POST' && !hasCSRFToken) {
        formsToCheck.push({
          action,
          method,
          fields: $form.find('input[type!="hidden"]').length,
        });

        vulnerabilities.push({
          type: 'csrf',
          severity: 'high',
          title: 'CSRF Vulnerability - Missing Anti-CSRF Token',
          description: `POST form${action !== targetUrl ? ` to ${action}` : ''} lacks anti-CSRF token protection.`,
          endpoint: action,
          parameter: 'N/A (Form)',
          payload: `Form action: ${action}\nMethod: ${method}`,
          evidence: `Form action: ${action}\nMethod: ${method}\nFields: ${$form.find('input').length}\nMissing: CSRF token field`,
          remediation: 'Implement anti-CSRF tokens using frameworks like csurf. Ensure tokens are tied to user session. Use SameSite cookies and validate Referer/Origin headers.',
          owasp_category: 'A01:2021 – Broken Access Control',
          cve_id: 'CWE-352'
        });
      }
    });

    const hasCSP = response.headers['content-security-policy'];
    const hasXFrame = response.headers['x-frame-options'];

    if (!hasXFrame && !hasCSP) {
      vulnerabilities.push({
        type: 'csrf',
        severity: 'low',
        title: 'Missing Clickjacking Protection',
        description: 'No X-Frame-Options or CSP frame-ancestors header found. Page could be embedded in an iframe (clickjacking).',
        endpoint: targetUrl,
        parameter: 'N/A (Header)',
        payload: 'Missing X-Frame-Options and CSP frame-ancestors',
        evidence: 'Headers checked: X-Frame-Options, Content-Security-Policy\nBoth missing',
        remediation: 'Set X-Frame-Options: DENY or SAMEORIGIN. Add frame-ancestors directive to CSP header.',
        owasp_category: 'A04:2021 – Insecure Design',
        cve_id: 'CWE-1021'
      });
    }

  } catch (err) {
    if (err.response) {
      vulnerabilities.push({
        type: 'csrf',
        severity: 'info',
        title: 'CSRF Assessment Limited',
        description: `Could not fully assess CSRF posture: HTTP ${err.response.status}`,
        endpoint: targetUrl,
        parameter: 'N/A',
        payload: `HTTP ${err.response.status}`,
        evidence: `Response status: ${err.response.status}\nRecommendation: Manual review required`,
        remediation: 'Review forms manually and ensure all state-changing operations use CSRF tokens.'
      });
    }
  }

  return vulnerabilities;
}

module.exports = { scanCSRF };
