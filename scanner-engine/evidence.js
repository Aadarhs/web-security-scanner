'use strict';

const CONFIDENCE = {
  CONFIRMED: 'confirmed',
  POTENTIAL: 'potential',
  ADVISORY: 'advisory',
};

const CONFIDENCE_LABELS = {
  confirmed: 'Confirmed',
  potential: 'Potential',
  advisory: 'Advisory',
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function normalizeConfidence(confidence) {
  if (confidence === 'confirmed' || confidence === 'potential' || confidence === 'advisory') {
    return confidence;
  }
  return CONFIDENCE.CONFIRMED;
}

function mkFinding(moduleName, opts) {
  const {
    type,
    severity = 'info',
    title,
    description,
    endpoint,
    parameter = 'N/A',
    payload = 'N/A',
    evidence = '',
    remediation = '',
    owasp_category = 'A05:2021 – Security Misconfiguration',
    cve_id = '',
    confidence = CONFIDENCE.CONFIRMED,
  } = opts || {};

  return {
    type: String(type || 'unknown'),
    severity: SEVERITY_ORDER.includes(severity) ? severity : 'info',
    title,
    description,
    endpoint,
    parameter,
    payload,
    evidence,
    remediation,
    owasp_category,
    cve_id,
    confidence: normalizeConfidence(confidence),
    module: moduleName,
  };
}

module.exports = { mkFinding, CONFIDENCE, CONFIDENCE_LABELS, normalizeConfidence, SEVERITY_ORDER };