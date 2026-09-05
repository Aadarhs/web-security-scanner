'use strict';

const { XSS_PAYLOADS_ENHANCED } = require('./payload-expansion');
const { mkFinding, CONFIDENCE } = require('./evidence');

const XSS_PAYLOADS = XSS_PAYLOADS_ENHANCED;

async function testXSSPayload(targetUrl, httpClient, test) {
  const encoded = encodeURIComponent(test.payload);
  const url = `${targetUrl}?q=${encoded}&search=${encoded}&s=${encoded}`;

  try {
    const response = await httpClient.get(url, {
      timeout: 8000,
      headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
    });

    const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

    const reflectedRaw = body.includes(test.payload);
    const reflectedEncoded = body.includes(
      test.payload
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
    );

    if (reflectedRaw && !reflectedEncoded) {
      return [mkFinding('xss', {
        type: 'xss',
        severity: 'medium',
        confidence: CONFIDENCE.POTENTIAL,
        title: 'Possible Reflected XSS - Payload Returned Unencoded (Verify)',
        description: `An XSS test payload was returned in the response without visible HTML encoding (${test.description}). This is a strong signal but not conclusive: whether it executes depends on the surrounding HTML context and the parser. Manual verification is required.`,
        endpoint: targetUrl,
        parameter: 'q, search, s',
        payload: test.payload,
        evidence: `Payload found raw in response: ${test.payload}\nXSS vector type: ${test.type}\nNote: verify the surrounding HTML context before treating as exploitable`,
        remediation: 'Use context-aware output encoding and a Content Security Policy (CSP).',
        owasp_category: 'A03:2021 – Injection',
        cve_id: 'CWE-79',
      })];
    }

    return [];
  } catch {
    return [];
  }
}

async function scanXSS(targetUrl, httpClient) {
  const vulnerabilities = [];
  const seen = new Set();
  const results = await Promise.allSettled(
    XSS_PAYLOADS.map(test => testXSSPayload(targetUrl, httpClient, test))
  );

  for (const result of results) {
    if (result.status === 'fulfilled' && result.value.length > 0) {
      for (const v of result.value) {
        const key = `xss::${v.payload}`;
        if (!seen.has(key)) {
          seen.add(key);
          vulnerabilities.push(v);
        }
      }
    }
  }

  return vulnerabilities;
}

module.exports = { scanXSS, XSS_PAYLOADS };