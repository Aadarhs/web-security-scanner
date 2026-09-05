const { scanAuth, DEFAULT_CREDENTIALS } = require('../authCheck');
const { scanCSRF } = require('../csrf');
const { scanSQLi } = require('../sqli');
const { scanXSS } = require('../xss');
const { getRelatedCVEs, generateCVESummary } = require('../cve-rag');
const { mkFinding, CONFIDENCE } = require('../evidence');

function mockGet(body, headers = {}, status = 200) {
  const client = {
    get: () => Promise.resolve({ status, headers, data: body }),
    post: () => Promise.resolve({ status: 200, headers: {}, data: body }),
  };
  return client;
}

describe('evidence.mkFinding', () => {
  it('stamps module, confidence and safe defaults', () => {
    const f = mkFinding('sqli', { type: 'sql-injection', severity: 'high', title: 'T', endpoint: 'http://x/' });
    expect(f.module).toBe('sqli');
    expect(f.confidence).toBe('confirmed');
    expect(f.parameter).toBe('N/A');
    expect(f.owasp_category).toBeTruthy();
  });

  it('rejects unknown confidence and falls back to confirmed', () => {
    const f = mkFinding('x', { type: 't', title: 'T', endpoint: 'http://x/', confidence: 'definitely' });
    expect(f.confidence).toBe('confirmed');
  });
});

describe('authCheck - honesty', () => {
  afterEach(() => vi.restoreAllMocks());

  it('does NOT report default credentials just because response lacks the word "Invalid"', async () => {
    const loginBody = '<html><h1>Login</h1><p>Wrong username or password</p></html>';
    const client = {
      get: () => Promise.resolve({ status: 200, headers: {}, data: '<form action="/login"><input name="password"></form>' }),
      post: () => Promise.resolve({ status: 200, headers: {}, data: loginBody }),
    };
    const results = await scanAuth('http://example.com/login', client);
    const prod = results.filter(r => r.title.includes('Default Credentials'));
    expect(prod.length).toBe(0);
  });

  it('reports only "potential" when a 302 + session cookie + non-login redirect occur', async () => {
    const client = {
      get: () => Promise.resolve({ status: 200, headers: {}, data: '<form action="/login"><input name="password"></form>' }),
      post: () => Promise.resolve({
        status: 302,
        headers: {
          location: '/dashboard',
          'set-cookie': ['session=abc123; Path=/'],
        },
        data: '',
      }),
    };
    const results = await scanAuth('http://example.com/login', client);
    const prod = results.filter(r => r.title.includes('Default Credentials'));
    expect(prod.length).toBeGreaterThanOrEqual(1);
    expect(prod[0].confidence).toBe('potential');
    expect(prod[0].severity).toBe('critical');
    expect(prod[0].description).toContain('manual');
  });
});

describe('csrf - honesty', () => {
  it('flags a POST form without a token as potential (not high/confirmed)', async () => {
    const client = mockGet('<form method="POST" action="/update"><input name="email"></form>');
    const results = await scanCSRF('http://example.com/', client);
    const formFindings = results.filter(r => r.title.includes('Anti-CSRF Token'));
    expect(formFindings.length).toBe(1);
    expect(formFindings[0].severity).toBe('medium');
    expect(formFindings[0].confidence).toBe('potential');
  });

  it('honestly notes an advisory, not confirmed, for missing SameSite', async () => {
    const client = mockGet('<html>hi</html>', { 'set-cookie': ['id=1; Path=/'] });
    const results = await scanCSRF('http://example.com/', client);
    const sameSite = results.filter(r => r.title.includes('SameSite'));
    expect(sameSite.length).toBeGreaterThanOrEqual(1);
    expect(sameSite[0].confidence).toBe('advisory');
  });
});

describe('sqli - honesty', () => {
  it('downgrades plain reflection to potential/medium (not a confirmed high)', async () => {
    let baselineCalls = 0;
    const client = {
      get: (url) => {
        const payload = decodeURIComponent((new URL(url)).searchParams.get('q') || '');
        baselineCalls++;
        return Promise.resolve({ status: 200, headers: {}, data: `page ${payload}` });
      },
    };
    const results = await scanSQLi('http://example.com/', client);
    expect(results.length).toBeGreaterThanOrEqual(1);
    for (const r of results) {
      expect(r.severity).toBe('medium');
      expect(r.confidence).toBe('potential');
      expect(r.title).toContain('Verify');
    }
  });
});

describe('xss - honesty', () => {
  it('downgrades raw reflection to potential (no critical, no page-wide alert(1) heuristic)', async () => {
    const client = {
      get: (url) => {
        const payload = decodeURIComponent((new URL(url)).searchParams.get('q') || '');
        return Promise.resolve({ status: 200, headers: {}, data: `markup ${payload}` });
      },
    };
    const results = await scanXSS('http://example.com/', client);
    expect(results.length).toBeGreaterThanOrEqual(1);
    for (const r of results) {
      expect(r.severity).toBe('medium');
      expect(r.confidence).toBe('potential');
      // The old heuristic that any page containing "alert(1)" is XSS must be gone:
      expect(r.title).not.toContain('JavaScript execution context');
    }
  });
});

describe('cve-rag - honesty', () => {
  it('never attaches unrelated CVEs to a generic vulnerability type', () => {
    const summary = generateCVESummary([{ type: 'sql-injection', title: 'x', cve_id: 'CWE-89', severity: 'high' }], []);
    const entry = summary[0];
    expect(entry.matchedCVE).toBeNull();
    expect(entry.relatedReferenceCVEs.length).toBe(0);
  });

  it('only references CVEs for detected tech stack, tagged as references', () => {
    const summary = generateCVESummary([{ type: 'sql-injection', title: 'x', cve_id: 'CWE-89', severity: 'high' }], ['apache']);
    const entry = summary[0];
    expect(entry.matchedCVE).toBeNull();
    expect(entry.relatedReferenceCVEs.length).toBeGreaterThanOrEqual(1);
    expect(entry.relatedReferenceCVEs.every(c => c.matchType === 'tech-stack')).toBe(true);
  });
});

describe('ai-analyzer honesty', () => {
  it('builtin summary is labeled builtin-summary and makes no invented chains', async () => {
    vi.resetModules();
    process.env.OPENAI_API_KEY = '';
    process.env.LLM_ENABLED = '';
    delete process.env.OLLAMA_URL;
    const { generateAnalysis } = require('../ai-analyzer');
    const out = await generateAnalysis('http://example.com/', 30, []);
    expect(out.provider).toBe('builtin-summary');
    expect(out.chainingPossibilities).toEqual([]);
    expect(out.disclaimer).toBeTruthy();
  });
});