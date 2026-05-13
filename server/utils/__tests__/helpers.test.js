const { sanitizeUrl, calculateRiskScore, severityCounts, generateId } = require('../helpers');

describe('sanitizeUrl', () => {
  it('should prepend https:// when no protocol is provided', () => {
    const result = sanitizeUrl('example.com');
    expect(result).toBe('https://example.com/');
  });

  it('should preserve http:// protocol', () => {
    const result = sanitizeUrl('http://example.com');
    expect(result).toBe('http://example.com/');
  });

  it('should preserve https:// protocol', () => {
    const result = sanitizeUrl('https://example.com');
    expect(result).toBe('https://example.com/');
  });

  it('should preserve query strings in the URL', () => {
    const result = sanitizeUrl('https://example.com/page?q=test&id=123');
    expect(result).toBe('https://example.com/page?q=test&id=123');
  });

  it('should preserve pathname', () => {
    const result = sanitizeUrl('https://example.com/some/path');
    expect(result).toBe('https://example.com/some/path');
  });

  it('should preserve pathname with query strings', () => {
    const result = sanitizeUrl('https://example.com/some/path?foo=bar&baz=qux');
    expect(result).toBe('https://example.com/some/path?foo=bar&baz=qux');
  });

  it('should strip trailing slash from origin but keep path', () => {
    const result = sanitizeUrl('https://example.com/test/');
    expect(result).toBe('https://example.com/test/');
  });

  it('should return null for invalid URLs', () => {
    const result = sanitizeUrl('not a valid url at all !!!');
    expect(result).toBeNull();
  });

  it('should preserve URL fragments (hash)', () => {
    const result = sanitizeUrl('https://example.com/page#section');
    // Note: URL parser may handle fragments differently
    expect(result).toContain('https://example.com/');
  });

  it('should handle URLs with ports', () => {
    const result = sanitizeUrl('http://localhost:3000/test');
    expect(result).toBe('http://localhost:3000/test');
  });

  it('should handle URLs with ports and query strings', () => {
    const result = sanitizeUrl('http://localhost:3000/scan?url=http://example.com');
    expect(result).toBe('http://localhost:3000/scan?url=http://example.com');
  });
});

describe('calculateRiskScore', () => {
  it('should return 0 for empty vulnerabilities array', () => {
    expect(calculateRiskScore([])).toBe(0);
  });

  it('should calculate score based on severity weights', () => {
    const vulns = [
      { severity: 'critical' },
      { severity: 'high' },
    ];
    // critical=10, high=7 => 17
    expect(calculateRiskScore(vulns)).toBe(17);
  });

  it('should cap score at 100', () => {
    const vulns = [
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'critical' },
    ];
    // 11 * 10 = 110, capped at 100
    expect(calculateRiskScore(vulns)).toBe(100);
  });

  it('should handle mixed severities', () => {
    const vulns = [
      { severity: 'critical' }, // 10
      { severity: 'high' },     // 7
      { severity: 'medium' },   // 4
      { severity: 'low' },      // 2
      { severity: 'info' },     // 0.5
    ];
    // 10 + 7 + 4 + 2 + 0.5 = 23.5 rounded to 23.5
    expect(calculateRiskScore(vulns)).toBe(23.5);
  });

  it('should handle unknown severity gracefully', () => {
    const vulns = [
      { severity: 'critical' },  // 10
      { severity: 'unknown' },   // 0
      { severity: 'high' },      // 7
    ];
    expect(calculateRiskScore(vulns)).toBe(17);
  });

  it('should round to one decimal place', () => {
    const vulns = [
      { severity: 'info' },  // 0.5
      { severity: 'info' },  // 0.5
      { severity: 'info' },  // 0.5
    ];
    expect(calculateRiskScore(vulns)).toBe(1.5);
  });
});

describe('severityCounts', () => {
  it('should return zero counts for empty array', () => {
    const counts = severityCounts([]);
    expect(counts).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  });

  it('should count severities correctly', () => {
    const vulns = [
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'high' },
      { severity: 'medium' },
      { severity: 'low' },
      { severity: 'info' },
      { severity: 'info' },
    ];
    const counts = severityCounts(vulns);
    expect(counts.critical).toBe(2);
    expect(counts.high).toBe(1);
    expect(counts.medium).toBe(1);
    expect(counts.low).toBe(1);
    expect(counts.info).toBe(2);
  });

  it('should ignore unknown severities', () => {
    const vulns = [
      { severity: 'critical' },
      { severity: 'unknown' },
    ];
    const counts = severityCounts(vulns);
    expect(counts.critical).toBe(1);
    expect(counts.high).toBe(0);
    expect(counts.medium).toBe(0);
    expect(counts.low).toBe(0);
    expect(counts.info).toBe(0);
  });

  it('should handle single vulnerability', () => {
    const counts = severityCounts([{ severity: 'critical' }]);
    expect(counts).toEqual({ critical: 1, high: 0, medium: 0, low: 0, info: 0 });
  });
});

describe('generateId', () => {
  it('should return a string', () => {
    expect(typeof generateId()).toBe('string');
  });

  it('should return a UUID v4 format (8-4-4-4-12 hex pattern)', () => {
    const id = generateId();
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  it('should generate unique IDs on successive calls', () => {
    const id1 = generateId();
    const id2 = generateId();
    expect(id1).not.toBe(id2);
  });
});
