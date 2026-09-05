const { scanDirectory, SENSITIVE_PATHS } = require('../directory');

function createMockHttpClient(responseMap = {}) {
  return {
    get: vi.fn().mockImplementation((url, config) => {
      // Find matching mock or return 404
      const match = Object.entries(responseMap).find(([path]) => url.includes(path));
      if (match) {
        const [, response] = match;
        return Promise.resolve({
          status: response.status || 200,
          headers: response.headers || {},
          data: response.body || '',
        });
      }
      // Default: 404 for unmocked paths
      return Promise.resolve({
        status: 404,
        headers: {},
        data: 'Not Found',
      });
    }),
  };
}

describe('SENSITIVE_PATHS', () => {
  it('should contain expected critical paths', () => {
    const paths = SENSITIVE_PATHS.map(p => p.path);
    expect(paths).toContain('/.git/HEAD');
    expect(paths).toContain('/.env');
    expect(paths).toContain('/dump.sql');
    expect(paths).toContain('/phpinfo.php');
    expect(paths).toContain('/admin');
  });

  it('should contain 20 entries', () => {
    expect(SENSITIVE_PATHS.length).toBe(20);
  });

  it('should have severity levels on all entries', () => {
    SENSITIVE_PATHS.forEach(item => {
      expect(item).toHaveProperty('severity');
      expect(item).toHaveProperty('title');
      expect(item).toHaveProperty('path');
    });
  });
});

describe('scanDirectory', () => {
  it('should detect exposed .env file as critical', async () => {
    const httpClient = createMockHttpClient({
      '/.env': {
        status: 200,
        body: 'DB_PASSWORD=super_secret_password_123\nAPI_KEY=abc123def456ghi789jkl\nSECRET=do_not_share',
      },
    });

    const results = await scanDirectory('https://example.com', httpClient);
    const envFindings = results.filter(r => r.title === 'Exposed Environment File');
    expect(envFindings.length).toBeGreaterThanOrEqual(1);
    expect(envFindings[0].severity).toBe('critical');
  });

  it('should detect exposed .git/HEAD as critical', async () => {
    const httpClient = createMockHttpClient({
      '/.git/HEAD': {
        status: 200,
        body: 'ref: refs/heads/main\nX-Content: padding to exceed 50 byte minimum threshold for content length filter',
      },
    });

    const results = await scanDirectory('https://example.com', httpClient);
    const gitFindings = results.filter(r => r.title === 'Exposed Git Repository');
    expect(gitFindings.length).toBeGreaterThanOrEqual(1);
    expect(gitFindings[0].severity).toBe('critical');
  });

  it('should suppress false positive when .git/HEAD lacks ref:', async () => {
    const httpClient = createMockHttpClient({
      '/.git/HEAD': {
        status: 200,
        body: 'padding to exceed 50 byte minimum threshold for content length filter. Not a git file',
      },
    });

    const results = await scanDirectory('https://example.com', httpClient);
    const gitFindings = results.filter(r => r.title === 'Exposed Git Repository');
    expect(gitFindings.length).toBe(0);
  });

  it('should suppress HTML pages (SPA catch-all false positive)', async () => {
    const httpClient = createMockHttpClient({
      '/admin': {
        status: 200,
        body: '<!DOCTYPE html><html><body>Admin Page</body></html>',
      },
    });

    const results = await scanDirectory('https://example.com', httpClient);
    // Should not flag as exposed since it's HTML
    const adminFindings = results.filter(r => r.title === 'Admin Panel Exposed');
    expect(adminFindings.length).toBe(0);
  });

  it('should detect 403 responses as info-level findings', async () => {
    const httpClient = createMockHttpClient({
      '/admin': {
        status: 403,
        body: 'Forbidden',
      },
    });

    const results = await scanDirectory('https://example.com', httpClient);
    const forbiddenFindings = results.filter(r =>
      r.title.includes('Access Control / WAF Detected') && r.endpoint === 'https://example.com'
    );
    expect(forbiddenFindings.length).toBeGreaterThanOrEqual(1);
    expect(forbiddenFindings[0].severity).toBe('info');
  });

  it('should ignore empty responses (size < 50 bytes)', async () => {
    const httpClient = createMockHttpClient({
      '/.env': {
        status: 200,
        body: 'x', // < 50 bytes, no '=' pattern
      },
    });

    const results = await scanDirectory('https://example.com', httpClient);
    const envFindings = results.filter(r => r.title === 'Exposed Environment File');
    expect(envFindings.length).toBe(0);
  });

  it('should handle connection errors gracefully', async () => {
    const httpClient = {
      get: vi.fn().mockRejectedValue(new Error('ECONNREFUSED')),
    };

    const results = await scanDirectory('https://example.com', httpClient);
    expect(Array.isArray(results)).toBe(true);
    expect(results.length).toBe(0);
  });

  it('should detect exposed robots.txt', async () => {
    const httpClient = createMockHttpClient({
      '/robots.txt': {
        status: 200,
        body: 'User-agent: *\nDisallow: /admin\nDisallow: /secret\nSitemap: https://example.com/sitemap.xml',
      },
    });

    const results = await scanDirectory('https://example.com', httpClient);
    const robotsFindings = results.filter(r => r.title.includes('Robots.txt'));
    expect(robotsFindings.length).toBeGreaterThanOrEqual(1);
    expect(robotsFindings[0].severity).toBe('low');
  });

  it('should suppress robots.txt without Disallow/Allow/Sitemap', async () => {
    const httpClient = createMockHttpClient({
      '/robots.txt': {
        status: 200,
        body: 'padding to exceed 50 byte minimum threshold for content length filter without Disallow keyword in this text',
      },
    });

    const results = await scanDirectory('https://example.com', httpClient);
    const robotsFindings = results.filter(r => r.title.includes('Robots.txt'));
    expect(robotsFindings.length).toBe(0);
  });
});
