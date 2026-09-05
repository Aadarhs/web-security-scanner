'use strict';

const cheerio = require('cheerio');
const { mkFinding, CONFIDENCE } = require('./evidence');

async function scanCSRF(targetUrl, httpClient) {
  const vulnerabilities = [];

  let response;
  try {
    response = await httpClient.get(targetUrl, {
      timeout: 15000,
      headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
      maxRedirects: 5,
    });
  } catch {
    return vulnerabilities;
  }

  const cookies = response.headers['set-cookie'] || [];
  for (const cookie of cookies) {
    if (!/samesite/i.test(cookie)) {
      vulnerabilities.push(mkFinding('csrf', {
        type: 'csrf',
        severity: 'low',
        confidence: CONFIDENCE.ADVISORY,
        title: 'Cookie Missing SameSite Attribute',
        description: 'Cookie is set without a SameSite attribute. SameSite is a browser-side mitigation, not a complete CSRF defense - absence does not confirm vulnerability.',
        endpoint: targetUrl,
        parameter: 'N/A (Cookie)',
        payload: cookie.split(';')[0],
        evidence: `Cookie: ${cookie.split(';')[0]}\nMissing attribute: SameSite\nNote: SameSite alone is not sufficient CSRF protection`,
        remediation: 'Set SameSite=Lax or SameSite=Strict where appropriate and implement server-side CSRF tokens.',
        owasp_category: 'A01:2021 – Broken Access Control',
        cve_id: 'CWE-352',
      }));
    }
  }

  const body = typeof response.data === 'string' ? response.data : '';
  if (body) {
    const $ = cheerio.load(body);
    $('form').each((i, form) => {
      const $form = $(form);
      const action = $form.attr('action') || targetUrl;
      const method = ($form.attr('method') || 'get').toUpperCase();
      const hasCSRFToken =
        $form.find('input[name*="csrf"], input[name*="token"], input[name*="_token"], input[name*="authenticity_token"]').length > 0;

      if (method === 'POST' && !hasCSRFToken) {
        vulnerabilities.push(mkFinding('csrf', {
          type: 'csrf',
          severity: 'medium',
          confidence: CONFIDENCE.POTENTIAL,
          title: 'POST Form Lacks In-Page Anti-CSRF Token (Verify)',
          description: `POST form${action !== targetUrl ? ` to ${action}` : ''} contains no hidden anti-CSRF token in its HTML. This does not confirm a CSRF flaw - the server may still validate Origin/Referer, use custom headers, or rely on SameSite. Manual verification is required.`,
          endpoint: action,
          parameter: 'N/A (Form)',
          payload: `Form action: ${action}\nMethod: ${method}`,
          evidence: `Form action: ${action}\nMethod: ${method}\nInput fields: ${$form.find('input').length}\nIn-page CSRF token: not found`,
          remediation: 'If no other CSRF defense exists, add anti-CSRF tokens to state-changing forms.',
          owasp_category: 'A01:2021 – Broken Access Control',
          cve_id: 'CWE-352',
        }));
      }
    });
  }

  const hasCSP = response.headers['content-security-policy'];
  const hasXFrame = response.headers['x-frame-options'];
  if (!hasXFrame && !hasCSP) {
    vulnerabilities.push(mkFinding('csrf', {
      type: 'csrf',
      severity: 'low',
      confidence: CONFIDENCE.ADVISORY,
      title: 'Missing Clickjacking Protection',
      description: 'No X-Frame-Options or CSP frame-ancestors header found, so the page may be embeddable in an iframe (clickjacking risk).',
      endpoint: targetUrl,
      parameter: 'N/A (Header)',
      payload: 'Missing X-Frame-Options and CSP frame-ancestors',
      evidence: 'Checked headers: X-Frame-Options, Content-Security-Policy\nBoth absent',
      remediation: 'Set X-Frame-Options: DENY/SAMEORIGIN or add a frame-ancestors directive to CSP.',
      owasp_category: 'A04:2021 – Insecure Design',
      cve_id: 'CWE-1021',
    }));
  }

  return vulnerabilities;
}

module.exports = { scanCSRF };