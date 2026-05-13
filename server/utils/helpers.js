const { v4: uuidv4 } = require('uuid');

function generateId() {
  return uuidv4();
}

function calculateRiskScore(vulnerabilities) {
  const weights = { critical: 10, high: 7, medium: 4, low: 2, info: 0.5 };
  let score = 0;
  for (const v of vulnerabilities) {
    score += weights[v.severity] || 0;
  }
  return Math.min(Math.round(score * 10) / 10, 100);
}

function severityCounts(vulnerabilities) {
  return {
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
    info: vulnerabilities.filter(v => v.severity === 'info').length,
  };
}

function sanitizeUrl(url) {
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  try {
    const parsed = new URL(url);
    // Preserve the full URL including query strings (important for scanner targets)
    return parsed.origin + parsed.pathname + parsed.search;
  } catch {
    return null;
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

module.exports = { generateId, calculateRiskScore, severityCounts, sanitizeUrl, sleep };
