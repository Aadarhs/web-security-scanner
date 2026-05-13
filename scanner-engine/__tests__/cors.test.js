const { scanCORS } = require('../cors');

function createMockHttpClient(responseOverrides = {}) {
  return {
    get: vi.fn().mockImplementation((url, config) => {
      const defaults = {
        status: 200,
        headers: {},
        data: '',
      };
      const merged = { ...defaults, ...responseOverrides };

      if (merged.status < 500) {
        return Promise.resolve({
          status: merged.status,
          headers: merged.headers,
          data: merged.data,
        });
      }
      return Promise.reject(new Error(`HTTP ${merged.status}`));
    }),
  };
}

describe('scanCORS', () => {
  it('should detect reflected CORS origin (critical)', async () => {
    const httpClient = createMockHttpClient({
      headers: {
        'access-control-allow-origin': 'https://evil.com',
      },
    });

    const results = await scanCORS('https://example.com', httpClient);
    const criticals = results.filter(r => r.severity === 'critical');
    expect(criticals.length).toBeGreaterThanOrEqual(1);
    expect(criticals[0].type).toBe('cors');
    expect(criticals[0].title).toContain('Reflected');
  });

  it('should detect wildcard CORS (medium or critical)', async () => {
    const httpClient = createMockHttpClient({
      headers: {
        'access-control-allow-origin': '*',
      },
    });

    const results = await scanCORS('https://example.com', httpClient);
    const wildcardFindings = results.filter(r => r.title.includes('Wildcard'));
    expect(wildcardFindings.length).toBeGreaterThanOrEqual(1);
    expect(wildcardFindings[0].type).toBe('cors');
  });

  it('should detect wildcard with credentials (critical)', async () => {
    const httpClient = createMockHttpClient({
      headers: {
        'access-control-allow-origin': '*',
        'access-control-allow-credentials': 'true',
      },
    });

    const results = await scanCORS('https://example.com', httpClient);
    const criticalCreds = results.filter(r =>
      r.title.includes('Wildcard with Credentials') && r.severity === 'critical'
    );
    expect(criticalCreds.length).toBeGreaterThanOrEqual(1);
    expect(criticalCreds[0].remediation).toContain('Never combine wildcard CORS with credentials');
  });

  it('should return info-level finding when no CORS headers are present', async () => {
    const httpClient = createMockHttpClient({
      headers: {},
    });

    const results = await scanCORS('https://example.com', httpClient);
    const infoFindings = results.filter(r => r.severity === 'info');
    expect(infoFindings.length).toBeGreaterThanOrEqual(1);
    expect(infoFindings[0].title).toBe('CORS Headers Not Present');
  });

  it('should not detect anything when server has secure CORS', async () => {
    const httpClient = createMockHttpClient({
      headers: {
        'access-control-allow-origin': 'https://trusted-site.com',
      },
    });

    const results = await scanCORS('https://example.com', httpClient);
    const criticalOrHigh = results.filter(r => r.severity === 'critical' || r.severity === 'high');
    // Non-matching origin should not trigger reflected detection
    // but info level about no CORS headers is not present since there is one
    expect(criticalOrHigh.length).toBe(0);
  });

  it('should handle connection errors gracefully', async () => {
    const httpClient = {
      get: vi.fn().mockRejectedValue(new Error('ECONNREFUSED')),
    };

    const results = await scanCORS('https://example.com', httpClient);
    expect(Array.isArray(results)).toBe(true);
    // Should not crash, may return empty or info
  });
});
