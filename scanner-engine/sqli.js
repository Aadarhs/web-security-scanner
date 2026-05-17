const { SQLI_PAYLOADS_ENHANCED } = require('./payload-expansion');
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

async function testPayload(targetUrl, httpClient, test) {
  const testUrl = `${targetUrl}?q=${encodeURIComponent(test.payload)}&id=${encodeURIComponent(test.payload)}&search=${encodeURIComponent(test.payload)}`;

  try {
    const startTime = Date.now();
    const response = await httpClient.get(testUrl, {
      timeout: 8000,
      headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' }
    });
    const responseTime = Date.now() - startTime;
    const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

    const results = [];

    for (const pattern of ERROR_PATTERNS) {
      if (pattern.test(body)) {
        results.push({
          type: 'sql-injection',
          severity: 'critical',
          title: 'SQL Injection Vulnerability Detected',
          description: `Parameter reflection with SQL error pattern: ${pattern.source}`,
          endpoint: targetUrl,
          parameter: 'q, id, search',
          payload: test.payload,
          evidence: `Error pattern matched: ${pattern.source}\nPayload: ${test.payload}\nResponse time: ${responseTime}ms`,
          remediation: 'Use parameterized queries or prepared statements. Sanitize and validate all user inputs.',
          owasp_category: 'A03:2021 – Injection',
          cve_id: 'CWE-89'
        });
        break;
      }
    }

    if (!results.length && body.includes(test.payload) && !body.includes('\\' + test.payload)) {
      results.push({
        type: 'sql-injection',
        severity: 'high',
        title: 'SQL Injection - Payload Reflection',
        description: `The payload "${test.payload}" was reflected in the response without sanitization`,
        endpoint: targetUrl,
        parameter: 'multiple',
        payload: test.payload,
        evidence: `Payload reflected: ${test.payload}\nResponse time: ${responseTime}ms`,
        remediation: 'Implement input validation and output encoding. Use parameterized queries.',
        owasp_category: 'A03:2021 – Injection',
        cve_id: 'CWE-89'
      });
    }

    if (responseTime > 2000 && (test.payload.includes('SLEEP') || test.payload.includes('WAITFOR'))) {
      results.push({
        type: 'sql-injection',
        severity: 'high',
        title: 'SQL Injection - Time-Based Blind',
        description: `Time-based blind SQL injection detected with response time of ${responseTime}ms`,
        endpoint: targetUrl,
        parameter: 'q, id, search',
        payload: test.payload,
        evidence: `Response time: ${responseTime}ms\nExpected: <1000ms`,
        remediation: 'Use parameterized queries. Implement query timeout limits.',
        owasp_category: 'A03:2021 – Injection',
        cve_id: 'CWE-89'
      });
    }

    return results;
  } catch (err) {
    if (err.response) {
      const body = typeof err.response.data === 'string' ? err.response.data : JSON.stringify(err.response.data || '');
      for (const pattern of ERROR_PATTERNS) {
        if (pattern.test(body)) {
          return [{
            type: 'sql-injection',
            severity: 'critical',
            title: 'SQL Injection - Error-Based',
            description: `Database error leaked in error response: ${pattern.source}`,
            endpoint: targetUrl,
            parameter: 'q, id, search',
            payload: test.payload,
            evidence: `HTTP ${err.response.status}\nError pattern: ${pattern.source}`,
            remediation: 'Disable detailed error messages in production.',
            owasp_category: 'A03:2021 – Injection',
            cve_id: 'CWE-89'
          }];
        }
      }
    }
    return [];
  }
}

async function scanSQLi(targetUrl, httpClient) {
  const vulnerabilities = [];
  const BATCH_SIZE = 5;

  for (let i = 0; i < SQLI_PAYLOADS.length; i += BATCH_SIZE) {
    const batch = SQLI_PAYLOADS.slice(i, i + BATCH_SIZE);
    const results = await Promise.allSettled(
      batch.map(test => testPayload(targetUrl, httpClient, test))
    );

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value.length > 0) {
        vulnerabilities.push(...result.value);
      }
    }
  }

  return vulnerabilities;
}

module.exports = { scanSQLi, SQLI_PAYLOADS, ERROR_PATTERNS };
