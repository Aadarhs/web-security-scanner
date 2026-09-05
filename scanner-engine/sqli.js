'use strict';

const { SQLI_PAYLOADS_ENHANCED } = require('./payload-expansion');
const { mkFinding, CONFIDENCE } = require('./evidence');

const SQLI_PAYLOADS = SQLI_PAYLOADS_ENHANCED;

const ERROR_PATTERNS = [
  /SQL syntax.*MySQL/i,
  /Warning.*mysql_.*:/i,
  /Unclosed quotation mark/i,
  /error in your SQL syntax/i,
  /You have an error in your SQL syntax/i,
  /ORA-[0-9]{5}/i,
  /PostgreSQL.*ERROR/i,
  /SQLite\/JDBC/i,
  /SQLite\.Exception/i,
  /Unrecognized token/i,
  /Division by zero/i,
  /Unknown column/i,
];

const TIME_PAYLOAD_RE = /sleep\(|waitfor|benchmark|pg_sleep|get_lock/i;

// Measure a single request without payloads to establish the site's normal
// response time, so slow responses are compared against a real baseline.
async function measureBaseline(targetUrl, httpClient) {
  const baselineTimes = [];
  const probeUrls = [
    `${targetUrl}?q=baseline&id=1&search=baseline`,
    `${targetUrl}?q=1&id=1&search=1`,
    targetUrl,
  ];
  for (const url of probeUrls) {
    try {
      const start = Date.now();
      await httpClient.get(url, {
        timeout: 8000,
        headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
      });
      baselineTimes.push(Date.now() - start);
    } catch {}
  }
  if (baselineTimes.length === 0) return null;
  return baselineTimes.sort((a, b) => a - b)[Math.floor(baselineTimes.length / 2)];
}

async function testPayload(targetUrl, httpClient, test, baselineMs) {
  const testUrl = `${targetUrl}?q=${encodeURIComponent(test.payload)}&id=${encodeURIComponent(test.payload)}&search=${encodeURIComponent(test.payload)}`;

  let response;
  try {
    const startTime = Date.now();
    response = await httpClient.get(testUrl, {
      timeout: 8000,
      headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
    });
    const responseTime = Date.now() - startTime;
    const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

    for (const pattern of ERROR_PATTERNS) {
      if (pattern.test(body)) {
        return [mkFinding('sqli', {
          type: 'sql-injection',
          severity: 'critical',
          confidence: CONFIDENCE.CONFIRMED,
          title: 'SQL Injection - Database Error Leaked',
          description: `A database error pattern (${pattern.source}) appeared in the response after injecting the payload. This indicates the user input reached a SQL query unparameterized.`,
          endpoint: targetUrl,
          parameter: 'q, id, search',
          payload: test.payload,
          evidence: `Error pattern matched: ${pattern.source}\nPayload: ${test.payload}\nResponse time: ${responseTime}ms`,
          remediation: 'Use parameterized queries or prepared statements. Sanitize and validate all user inputs.',
          owasp_category: 'A03:2021 – Injection',
          cve_id: 'CWE-89',
        })];
      }
    }

    if (baselineMs !== null && TIME_PAYLOAD_RE.test(test.payload)) {
      const delayGain = responseTime - baselineMs;
      if (baselineMs < 2000 && delayGain >= 2500) {
        return [mkFinding('sqli', {
          type: 'sql-injection',
          severity: 'high',
          confidence: CONFIDENCE.POTENTIAL,
          title: 'Possible Time-Based Blind SQL Injection',
          description: `The injected delay payload caused a response ${delayGain}ms slower than the measured site baseline (${baselineMs}ms). This is consistent with a time-based SQL injection but is not conclusive.`,
          endpoint: targetUrl,
          parameter: 'q, id, search',
          payload: test.payload,
          evidence: `Payload: ${test.payload}\nBaseline (median): ${baselineMs}ms\nPayload response: ${responseTime}ms\nDelta: ${delayGain}ms`,
          remediation: 'Use parameterized queries. Implement query timeout limits and review client-side input handling.',
          owasp_category: 'A03:2021 – Injection',
          cve_id: 'CWE-89',
        })];
      }
    }

    if (body.includes(test.payload)) {
      return [mkFinding('sqli', {
        type: 'sql-injection',
        severity: 'medium',
        confidence: CONFIDENCE.POTENTIAL,
        title: 'Parameter Input Reflected in Response (Verify Manually)',
        description: 'An injected SQL test string was reflected back in the response. Reflection alone does not confirm SQL injection - it only shows the input is echoed. Manual verification is required to determine whether the parameter reaches a SQL query.',
        endpoint: targetUrl,
        parameter: 'q, id, search',
        payload: test.payload,
        evidence: `Payload reflected: ${test.payload}\nResponse time: ${responseTime}ms\nNote: reflection != SQLi; verify how the parameter is used`,
        remediation: 'If the parameter is used in a database query, use parameterized queries and output encoding.',
        owasp_category: 'A03:2021 – Injection',
        cve_id: 'CWE-79',
      })];
    }

    return [];
  } catch (err) {
    if (err && err.response) {
      const body = typeof err.response.data === 'string' ? err.response.data : JSON.stringify(err.response.data || '');
      for (const pattern of ERROR_PATTERNS) {
        if (pattern.test(body)) {
          return [mkFinding('sqli', {
            type: 'sql-injection',
            severity: 'critical',
            confidence: CONFIDENCE.CONFIRMED,
            title: 'SQL Injection - Database Error Leaked',
            description: `A database error pattern (${pattern.source}) appeared in an error response after injecting the payload.`,
            endpoint: targetUrl,
            parameter: 'q, id, search',
            payload: test.payload,
            evidence: `HTTP ${err.response.status}\nError pattern: ${pattern.source}`,
            remediation: 'Disable detailed error messages in production and use parameterized queries.',
            owasp_category: 'A03:2021 – Injection',
            cve_id: 'CWE-89',
          })];
        }
      }
    }
    return [];
  }
}

async function scanSQLi(targetUrl, httpClient) {
  const baselineMs = await measureBaseline(targetUrl, httpClient);
  const vulnerabilities = [];
  const seen = new Set();
  const BATCH_SIZE = 5;

  for (let i = 0; i < SQLI_PAYLOADS.length; i += BATCH_SIZE) {
    const batch = SQLI_PAYLOADS.slice(i, i + BATCH_SIZE);
    const results = await Promise.allSettled(
      batch.map(test => testPayload(targetUrl, httpClient, test, baselineMs))
    );

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value.length > 0) {
        for (const v of result.value) {
          const key = `${v.title}::${v.payload}`;
          if (!seen.has(key)) {
            seen.add(key);
            vulnerabilities.push(v);
          }
        }
      }
    }
  }

  return vulnerabilities;
}

module.exports = { scanSQLi, SQLI_PAYLOADS, ERROR_PATTERNS };