const CVSS_METRICS = {
  AV: { label: 'Attack Vector', values: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' }, scores: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 } },
  AC: { label: 'Attack Complexity', values: { L: 'Low', H: 'High' }, scores: { L: 0.77, H: 0.44 } },
  PR: { label: 'Privileges Required', values: { N: 'None', L: 'Low', H: 'High' }, scores: { N: 0.85, L: 0.62, H: 0.27 } },
  UI: { label: 'User Interaction', values: { N: 'None', R: 'Required' }, scores: { N: 0.85, R: 0.62 } },
  S: { label: 'Scope', values: { U: 'Unchanged', C: 'Changed' }, scores: { U: 0, C: 1 } },
  C: { label: 'Confidentiality', values: { H: 'High', L: 'Low', N: 'None' }, scores: { H: 0.56, L: 0.22, N: 0 } },
  I: { label: 'Integrity', values: { H: 'High', L: 'Low', N: 'None' }, scores: { H: 0.56, L: 0.22, N: 0 } },
  A: { label: 'Availability', values: { H: 'High', L: 'Low', N: 'None' }, scores: { H: 0.56, L: 0.22, N: 0 } },
};

const VULN_TYPE_TO_CVSS_DEFAULTS = {
  'sql-injection': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'xss': { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' },
  'lfi': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  'ssrf': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
  'command-injection': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'csrf': { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' },
  'open-redirect': { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'N', I: 'N', A: 'N' },
  'cors': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
  'xxe': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'security-headers': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N' },
  'sensitive-exposure': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
  'authentication': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'network': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
};

const SEVERITY_TO_CVSS = {
  critical: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  high: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'L' },
  medium: { AV: 'N', AC: 'L', PR: 'L', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' },
  low: { AV: 'A', AC: 'L', PR: 'L', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' },
  info: { AV: 'L', AC: 'H', PR: 'H', UI: 'R', S: 'U', C: 'N', I: 'N', A: 'N' },
};

function calculateCVSS31(vector) {
  const av = CVSS_METRICS.AV.scores[vector.AV] || 0.85;
  const ac = CVSS_METRICS.AC.scores[vector.AC] || 0.77;
  const pr = CVSS_METRICS.PR.scores[vector.PR] || 0.85;
  const ui = CVSS_METRICS.UI.scores[vector.UI] || 0.85;
  const s = CVSS_METRICS.S.scores[vector.S] || 0;
  const c = CVSS_METRICS.C.scores[vector.C] || 0;
  const i = CVSS_METRICS.I.scores[vector.I] || 0;
  const a_val = CVSS_METRICS.A.scores[vector.A] || 0;

  const iss = 1 - ((1 - c) * (1 - i) * (1 - a_val));

  let impact;
  if (s === 0) {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  const exploitability = 8.22 * av * ac * pr * ui;

  let baseScore;
  if (impact <= 0) {
    baseScore = 0;
  } else if (s === 0) {
    baseScore = Math.min(impact + exploitability, 10);
  } else {
    baseScore = Math.min(1.08 * (impact + exploitability), 10);
  }

  baseScore = Math.round(baseScore * 10) / 10;

  let severity;
  if (baseScore >= 9.0) severity = 'Critical';
  else if (baseScore >= 7.0) severity = 'High';
  else if (baseScore >= 4.0) severity = 'Medium';
  else if (baseScore >= 0.1) severity = 'Low';
  else severity = 'None';

  const vectorStr = `CVSS:3.1/${Object.entries(vector).map(([k, v]) => `${k}:${v}`).join('/')}`;

  return { score: baseScore, severity, vector: vectorStr };
}

function getCVSSForVulnerability(vulnType, vulnSeverity) {
  let vector = VULN_TYPE_TO_CVSS_DEFAULTS[vulnType] || SEVERITY_TO_CVSS[vulnSeverity] || SEVERITY_TO_CVSS.medium;
  return calculateCVSS31(vector);
}

function getCVSSVectorForSeverity(severity) {
  const vector = SEVERITY_TO_CVSS[severity] || SEVERITY_TO_CVSS.medium;
  return calculateCVSS31(vector);
}

function enrichVulnerabilitiesWithCVSS(vulnerabilities) {
  return vulnerabilities.map(v => {
    const cvss = getCVSSForVulnerability(v.type, v.severity);
    return { ...v, cvssScore: cvss.score, cvssSeverity: cvss.severity, cvssVector: cvss.vector };
  });
}

module.exports = {
  calculateCVSS31,
  getCVSSForVulnerability,
  getCVSSVectorForSeverity,
  enrichVulnerabilitiesWithCVSS,
  CVSS_METRICS,
};
