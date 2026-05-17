const BASELINE_WINDOW_SIZE = 10;

const ANOMALY_THRESHOLDS = {
  responseTime: { zscore: 2.5, label: 'Response time anomaly' },
  contentLength: { zscore: 2.5, label: 'Content length anomaly' },
  statusCode: { allowed: [200, 201, 204, 301, 302, 304, 307, 400, 401, 403, 404, 500], label: 'Unusual status code' },
};

class AnomalyDetector {
  constructor() {
    this.baselines = {};
  }

  recordBaseline(targetKey, metric, value) {
    if (!this.baselines[targetKey]) {
      this.baselines[targetKey] = {};
    }
    if (!this.baselines[targetKey][metric]) {
      this.baselines[targetKey][metric] = [];
    }
    const window = this.baselines[targetKey][metric];
    window.push(value);
    if (window.length > BASELINE_WINDOW_SIZE * 2) {
      window.splice(0, window.length - BASELINE_WINDOW_SIZE * 2);
    }
  }

  getStats(targetKey, metric) {
    const values = this.baselines[targetKey]?.[metric];
    if (!values || values.length < 3) return null;
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / values.length;
    const std = Math.sqrt(variance);
    return { mean, std, count: values.length };
  }

  isAnomaly(targetKey, metric, value) {
    const stats = this.getStats(targetKey, metric);
    if (!stats || stats.std === 0) return false;
    const z = Math.abs((value - stats.mean) / stats.std);
    const threshold = ANOMALY_THRESHOLDS[metric]?.zscore || 2.5;
    return z > threshold;
  }

  analyze(targetUrl, responses) {
    const anomalies = [];
    const targetKey = new URL(targetUrl).hostname;

    for (const resp of responses) {
      const rt = resp.responseTime || 0;
      const cl = resp.contentLength || 0;
      const sc = resp.statusCode || 200;

      this.recordBaseline(targetKey, 'responseTime', rt);
      this.recordBaseline(targetKey, 'contentLength', cl);

      if (this.isAnomaly(targetKey, 'responseTime', rt)) {
        const stats = this.getStats(targetKey, 'responseTime');
        anomalies.push({
          type: 'anomaly',
          severity: 'medium',
          title: 'Response Time Anomaly',
          description: `Response time ${rt}ms deviates from baseline (mean: ${stats.mean.toFixed(0)}ms, z-score: ${((rt - stats.mean) / stats.std).toFixed(2)})`,
          endpoint: targetUrl,
          parameter: resp.testParam || 'N/A',
          payload: resp.payload || 'N/A',
          evidence: `Test: ${resp.testName || 'Unknown'}\nResponse time: ${rt}ms\nBaseline mean: ${stats.mean.toFixed(0)}ms\nStd dev: ${stats.std.toFixed(0)}ms\nZ-score: ${((rt - stats.mean) / stats.std).toFixed(2)}`,
          remediation: 'Investigate the request that caused the timing anomaly — may indicate time-based injection vulnerability or resource exhaustion.',
          owasp_category: 'A04:2021 – Insecure Design',
          cve_id: 'CWE-200',
        });
      }

      if (this.isAnomaly(targetKey, 'contentLength', cl)) {
        const stats = this.getStats(targetKey, 'contentLength');
        anomalies.push({
          type: 'anomaly',
          severity: 'low',
          title: 'Content Length Anomaly',
          description: `Response size ${cl} bytes deviates from baseline (mean: ${stats.mean.toFixed(0)} bytes)`,
          endpoint: targetUrl,
          parameter: resp.testParam || 'N/A',
          payload: resp.payload || 'N/A',
          evidence: `Test: ${resp.testName || 'Unknown'}\nContent length: ${cl} bytes\nBaseline mean: ${stats.mean.toFixed(0)} bytes`,
          remediation: 'Review the request that produced an unusually large or small response. May indicate injection success or partial content.',
          owasp_category: 'A04:2021 – Insecure Design',
          cve_id: 'CWE-200',
        });
      }

      if (!ANOMALY_THRESHOLDS.statusCode.allowed.includes(sc)) {
        anomalies.push({
          type: 'anomaly',
          severity: 'low',
          title: 'Unusual HTTP Status Code',
          description: `HTTP ${sc} returned for request. This status code is outside the normal range for this endpoint.`,
          endpoint: targetUrl,
          parameter: resp.testParam || 'N/A',
          payload: resp.payload || 'N/A',
          evidence: `Test: ${resp.testName || 'Unknown'}\nStatus: ${sc}\nThis non-standard status may indicate an error condition triggered by the test.`,
          remediation: 'Verify that unusual status codes are handled gracefully and do not expose sensitive error information.',
          owasp_category: 'A04:2021 – Insecure Design',
          cve_id: 'CWE-200',
        });
      }
    }

    return anomalies;
  }

  detectResponsePatternAnomalies(targetUrl, responses) {
    const anomalies = [];
    const timePattern = [];
    const lengthPattern = [];

    for (const r of responses) {
      timePattern.push(r.responseTime || 0);
      lengthPattern.push(r.contentLength || 0);
    }

    if (timePattern.length >= 4) {
      for (let i = 2; i < timePattern.length; i++) {
        const ratio = timePattern[i] / (timePattern[i - 1] || 1);
        if (ratio > 3 && timePattern[i] > 2000) {
          anomalies.push({
            type: 'anomaly',
            severity: 'high',
            title: 'Time-Based Injection Indicator',
            description: `Response time spike detected: ${timePattern[i]}ms vs ${timePattern[i-1]}ms (${ratio.toFixed(1)}x). Possible time-based injection.`,
            endpoint: targetUrl,
            parameter: responses[i]?.testParam || 'N/A',
            payload: responses[i]?.payload || 'N/A',
            evidence: `Request ${i}: ${timePattern[i]}ms\nRequest ${i-1}: ${timePattern[i-1]}ms\nRatio: ${ratio.toFixed(1)}x\nThreshold: >3x with >2000ms`,
            remediation: 'Investigate for time-based blind injection vulnerability (SQLi, CMDI, SSRF).',
            owasp_category: 'A03:2021 – Injection',
            cve_id: 'CWE-208',
          });
        }
      }
    }

    return anomalies;
  }
}

const globalDetector = new AnomalyDetector();

async function scanAnomaly(targetUrl, httpClient) {
  const detector = new AnomalyDetector();
  return { detector, anomalies: [] };
}

module.exports = { AnomalyDetector, globalDetector, scanAnomaly };
