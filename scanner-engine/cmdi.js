'use strict';

const { CMDI_PAYLOADS_ENHANCED } = require('./payload-expansion');
const { mkFinding, CONFIDENCE } = require('./evidence');

const CMDI_PARAMS = ['cmd', 'command', 'exec', 'ping', 'run', 'system', 'shell', 'dir', 'wget', 'curl', 'host', 'ip', 'nslookup', 'traceroute'];
const CMDI_PAYLOADS = CMDI_PAYLOADS_ENHANCED;

const TIME_PAYLOAD_RE = /ping -c 3|ping -n 3|nslookup/i;

async function measureBaselineMs(targetUrl, httpClient) {
  const times = [];
  const probes = [`${targetUrl.replace(/\/$/, '')}?cmd=baseline`, `${targetUrl.replace(/\/$/, '')}?command=1`];
  for (const url of probes) {
    try {
      const start = Date.now();
      await httpClient.get(url, { timeout: 10000, headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' }, validateStatus: s => s < 500 });
      times.push(Date.now() - start);
    } catch {}
  }
  if (times.length === 0) return null;
  return times.sort((a, b) => a - b)[Math.floor(times.length / 2)];
}

async function scanCMDI(targetUrl, httpClient) {
  const vulnerabilities = [];
  const baseUrl = targetUrl.replace(/\/$/, '');
  const baselineMs = await measureBaselineMs(targetUrl, httpClient);

  for (const param of CMDI_PARAMS) {
    let found = false;
    const CHUNK_SIZE = 4;
    for (let i = 0; i < CMDI_PAYLOADS.length; i += CHUNK_SIZE) {
      if (found) break;
      const chunk = CMDI_PAYLOADS.slice(i, i + CHUNK_SIZE);
      const results = await Promise.all(chunk.map(test =>
        (async () => {
          try {
            const testUrl = `${baseUrl}?${param}=${encodeURIComponent(test.payload)}`;
            const startTime = Date.now();
            const response = await httpClient.get(testUrl, {
              timeout: 10000,
              headers: { 'User-Agent': process.env.USER_AGENT || 'WebSecurityScanner/1.0' },
              validateStatus: s => s < 500,
            });
            const responseTime = Date.now() - startTime;
            const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || '');

            const indicatorFound = ind(body, test.indicator);

            if (indicatorFound) {
              return mkFinding('cmdi', {
                type: 'command-injection',
                severity: 'critical',
                confidence: CONFIDENCE.CONFIRMED,
                title: `Command Injection - ${test.name}`,
                description: `The response for parameter "${param}" contained the command output marker "${test.indicator}" after injecting ${test.name}. This indicates the input was executed as an OS command.`,
                endpoint: baseUrl,
                parameter: param,
                payload: `${param}=${test.payload}`,
                evidence: `Test URL: ${testUrl}\nParameter: ${param}\nPayload: ${test.payload}\nOutput marker found: "${test.indicator}"\nResponse time: ${responseTime}ms`,
                remediation: 'Never pass user input directly to system commands. Use language-native APIs instead and validate input with allowlists.',
                owasp_category: 'A03:2021 – Injection',
                cve_id: 'CWE-78',
              });
            }

            if (baselineMs !== null && TIME_PAYLOAD_RE.test(test.payload)) {
              const delayGain = responseTime - baselineMs;
              if (baselineMs < 2000 && delayGain >= 2500) {
                return mkFinding('cmdi', {
                  type: 'command-injection',
                  severity: 'high',
                  confidence: CONFIDENCE.POTENTIAL,
                  title: `Possible Time-Based Command Injection - ${test.name}`,
                  description: `Parameter "${param}" responded ${delayGain}ms slower than the measured site baseline (${baselineMs}ms) when the delay payload was injected. Consistent with command execution but not conclusive - verify manually.`,
                  endpoint: baseUrl,
                  parameter: param,
                  payload: `${param}=${test.payload}`,
                  evidence: `Parameter: ${param}\nPayload: ${test.payload}\nBaseline (median): ${baselineMs}ms\nPayload response: ${responseTime}ms\nDelta: ${delayGain}ms`,
                  remediation: 'Never pass user input directly to system commands. Use allowlist validation and native APIs.',
                  owasp_category: 'A03:2021 – Injection',
                  cve_id: 'CWE-78',
                });
              }
            }

            return null;
          } catch (err) { return null; }
        })()
      ));
      for (const r of results) {
        if (r) { vulnerabilities.push(r); found = true; break; }
      }
    }
  }
  return vulnerabilities;
}

function ind(body, indicator) {
  const markers = String(indicator || '').split('|').filter(Boolean);
  return markers.length === 0 ? false : markers.some(m => body.includes(m));
}

module.exports = { scanCMDI, CMDI_PARAMS, CMDI_PAYLOADS };