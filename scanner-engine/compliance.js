const COMPLIANCE_FRAMEWORKS = {
  'PCI-DSS': {
    name: 'Payment Card Industry Data Security Standard',
    version: '4.0',
    controls: {
      'SQL Injection': { control: '6.5.1', requirement: 'Develop and maintain secure systems and applications', severity: 'critical' },
      'XSS': { control: '6.5.2', requirement: 'Develop and maintain secure systems and applications', severity: 'high' },
      'CSRF': { control: '6.5.5', requirement: 'Develop and maintain secure systems and applications', severity: 'medium' },
      'Authentication Failures': { control: '8.3.1', requirement: 'Identify and authenticate access to system components', severity: 'high' },
      'Security Misconfiguration': { control: '2.2', requirement: 'Apply configuration standards for all system components', severity: 'medium' },
      'Open Redirect': { control: '6.5.3', requirement: 'Address security misconfigurations', severity: 'low' },
      'Insecure Design': { control: '6.5.4', requirement: 'Secure coding practices', severity: 'high' },
      'CORS Misconfiguration': { control: '2.2.1', requirement: 'Configuration standards for network security', severity: 'medium' },
      'Information Exposure': { control: '3.1', requirement: 'Protect stored cardholder data', severity: 'high' },
      'Injection': { control: '6.5.1', requirement: 'Protect against injection attacks', severity: 'critical' },
      'SSRF': { control: '6.5.7', requirement: 'Address server-side request forgery', severity: 'high' },
      'XXE': { control: '6.5.1', requirement: 'Protect against XML external entity attacks', severity: 'high' },
      'LFI': { control: '6.5.1', requirement: 'Prevent local file inclusion', severity: 'medium' },
      'CMDI': { control: '6.5.1', requirement: 'Prevent command injection', severity: 'critical' },
    },
  },
  'HIPAA': {
    name: 'Health Insurance Portability and Accountability Act',
    version: '2024',
    controls: {
      'SQL Injection': { control: '164.312(a)(1)', requirement: 'Access control - prevent unauthorized data access', severity: 'critical' },
      'XSS': { control: '164.312(c)(1)', requirement: 'Integrity controls - protect against improper data modification', severity: 'high' },
      'CSRF': { control: '164.312(a)(1)', requirement: 'Access control - prevent unauthorized actions', severity: 'medium' },
      'Authentication Failures': { control: '164.312(d)', requirement: 'Person or entity authentication', severity: 'high' },
      'Security Misconfiguration': { control: '164.308(a)(1)', requirement: 'Security management process', severity: 'medium' },
      'Information Exposure': { control: '164.314(a)(1)', requirement: 'Protect electronic protected health information', severity: 'high' },
      'Injection': { control: '164.312(c)(1)', requirement: 'Integrity controls', severity: 'critical' },
      'CORS Misconfiguration': { control: '164.312(a)(1)', requirement: 'Access control - limit data exposure', severity: 'medium' },
      'SSRF': { control: '164.312(c)(1)', requirement: 'Integrity controls - prevent data exfiltration', severity: 'high' },
      'LFI': { control: '164.312(a)(1)', requirement: 'Access control - prevent file access', severity: 'medium' },
      'CMDI': { control: '164.312(a)(1)', requirement: 'Access control - prevent remote execution', severity: 'critical' },
      'XXE': { control: '164.312(c)(1)', requirement: 'Integrity controls - protect ePHI', severity: 'high' },
    },
  },
  'SOC2': {
    name: 'Service Organization Control 2',
    version: '2024',
    controls: {
      'SQL Injection': { control: 'CC6.1', requirement: 'Logical and physical access controls', severity: 'critical' },
      'XSS': { control: 'CC6.1', requirement: 'Prevent unauthorized access to data', severity: 'high' },
      'CSRF': { control: 'CC6.2', requirement: 'Access control mechanisms', severity: 'medium' },
      'Authentication Failures': { control: 'CC6.3', requirement: 'Authentication mechanisms', severity: 'high' },
      'Security Misconfiguration': { control: 'CC7.1', requirement: 'System monitoring and security configuration', severity: 'medium' },
      'Injection': { control: 'CC6.1', requirement: 'Prevent unauthorized access to data', severity: 'critical' },
      'CORS Misconfiguration': { control: 'CC6.1', requirement: 'Restrict access based on security policies', severity: 'medium' },
      'SSRF': { control: 'CC6.1', requirement: 'Prevent unauthorized access', severity: 'high' },
      'CMDI': { control: 'CC6.1', requirement: 'Logical and physical access controls', severity: 'critical' },
      'XXE': { control: 'CC6.1', requirement: 'Logical and physical access controls', severity: 'high' },
      'LFI': { control: 'CC6.1', requirement: 'Logical access restriction', severity: 'medium' },
      'Information Exposure': { control: 'CC7.2', requirement: 'Security event monitoring and response', severity: 'high' },
    },
  },
  'GDPR': {
    name: 'General Data Protection Regulation',
    version: '2018',
    controls: {
      'SQL Injection': { control: 'Art. 32', requirement: 'Security of processing - protect personal data', severity: 'critical' },
      'XSS': { control: 'Art. 32', requirement: 'Security of processing', severity: 'high' },
      'CSRF': { control: 'Art. 32', requirement: 'Security of processing - prevent unauthorized actions', severity: 'medium' },
      'Authentication Failures': { control: 'Art. 32(1)(b)', requirement: 'Ability to ensure ongoing confidentiality', severity: 'high' },
      'Security Misconfiguration': { control: 'Art. 32(1)(d)', requirement: 'Process for regular testing of security measures', severity: 'medium' },
      'Information Exposure': { control: 'Art. 5(1)(f)', requirement: 'Integrity and confidentiality principle', severity: 'high' },
      'Injection': { control: 'Art. 32', requirement: 'Security of processing personal data', severity: 'critical' },
      'CORS Misconfiguration': { control: 'Art. 32', requirement: 'Appropriate technical measures', severity: 'medium' },
      'SSRF': { control: 'Art. 32', requirement: 'Protect against data breach via SSRF', severity: 'high' },
      'LFI': { control: 'Art. 32', requirement: 'Protect against unauthorized file access', severity: 'medium' },
      'CMDI': { control: 'Art. 32', requirement: 'Security of processing', severity: 'critical' },
      'XXE': { control: 'Art. 32', requirement: 'Security of processing', severity: 'high' },
    },
  },
  'ISO27001': {
    name: 'ISO/IEC 27001:2022',
    version: '2022',
    controls: {
      'SQL Injection': { control: 'A.8.24', requirement: 'Use of cryptography - protect data at rest', severity: 'critical' },
      'XSS': { control: 'A.8.25', requirement: 'Secure development lifecycle', severity: 'high' },
      'Authentication Failures': { control: 'A.8.5', requirement: 'Secure authentication', severity: 'high' },
      'Security Misconfiguration': { control: 'A.8.9', requirement: 'Configuration management', severity: 'medium' },
      'Injection': { control: 'A.8.25', requirement: 'Secure coding practices', severity: 'critical' },
      'Information Exposure': { control: 'A.8.11', requirement: 'Data masking and access control', severity: 'high' },
      'CORS Misconfiguration': { control: 'A.8.22', requirement: 'Network security controls', severity: 'medium' },
      'CMDI': { control: 'A.8.25', requirement: 'Secure coding - command injection prevention', severity: 'critical' },
      'SSRF': { control: 'A.8.22', requirement: 'Network security - restrict outbound traffic', severity: 'high' },
      'XXE': { control: 'A.8.25', requirement: 'Secure development', severity: 'high' },
      'LFI': { control: 'A.8.25', requirement: 'Input validation in development', severity: 'medium' },
      'CSRF': { control: 'A.8.25', requirement: 'Secure development lifecycle', severity: 'medium' },
    },
  },
};

function getTypeForSeverity(severity) {
  const map = {
    critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info',
  };
  return map[severity] || 'Info';
}

function mapVulnerabilityToCompliance(vuln) {
  const results = [];
  const vulnType = vuln.type || '';

  for (const [framework, config] of Object.entries(COMPLIANCE_FRAMEWORKS)) {
    let bestMatch = null;

    for (const [vulnTypeKey, control] of Object.entries(config.controls)) {
      if (vulnTypeKey === 'Information Exposure' && (vulnType.includes('information') || vulnType.includes('info') || vuln.title?.includes('Information'))) {
        bestMatch = control;
        break;
      }
      if (vulnType.toLowerCase().includes(vulnTypeKey.toLowerCase().replace(/\s+/g, ''))) {
        bestMatch = control;
        break;
      }
      if (vuln.title?.toLowerCase().includes(vulnTypeKey.toLowerCase().replace(/\s+/g, ''))) {
        bestMatch = control;
        break;
      }
    }

    if (bestMatch) {
      results.push({
        framework: `${framework} ${config.version}`,
        frameworkName: config.name,
        control: bestMatch.control,
        requirement: bestMatch.requirement,
        mappedSeverity: bestMatch.severity,
        status: vuln.ignored ? 'accepted_risk' : 'non_compliant',
      });
    } else {
      results.push({
        framework: `${framework} ${config.version}`,
        frameworkName: config.name,
        control: 'General',
        requirement: 'General security controls apply',
        mappedSeverity: vuln.severity,
        status: vuln.ignored ? 'accepted_risk' : 'review_required',
      });
    }
  }

  return results;
}

function generateComplianceReport(vulnerabilities, framework) {
  const frameworkConfig = COMPLIANCE_FRAMEWORKS[framework];
  if (!frameworkConfig) return { error: `Unknown framework: ${framework}` };

  const mappings = vulnerabilities.map(v => ({
    vuln: { title: v.title, severity: v.severity, type: v.type, ignored: !!v.ignored, description: v.description },
    compliance: mapVulnerabilityToCompliance(v).filter(c => c.framework.startsWith(framework)),
  }));

  const nonCompliant = mappings.filter(m => m.compliance.some(c => c.status === 'non_compliant'));
  const acceptedRisk = mappings.filter(m => m.compliance.some(c => c.status === 'accepted_risk'));
  const reviewRequired = mappings.filter(m => m.compliance.some(c => c.status === 'review_required'));

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const m of mappings) {
    const s = m.vuln.severity;
    if (severityCounts[s] !== undefined) severityCounts[s]++;
  }

  return {
    framework: frameworkConfig.name,
    version: frameworkConfig.version,
    totalFindings: vulnerabilities.length,
    nonCompliant: nonCompliant.length,
    acceptedRisk: acceptedRisk.length,
    reviewRequired: reviewRequired.length,
    severityBreakdown: severityCounts,
    mappings,
    summary: generateSummary(frameworkConfig.name, nonCompliant.length, vulnerabilities.length),
  };
}

function generateSummary(framework, nonCompliantCount, totalCount) {
  if (nonCompliantCount === 0) return `Compliant with ${framework} — no non-compliant findings`;
  const pct = Math.round((nonCompliantCount / totalCount) * 100);
  if (pct > 50) return `${pct}% of findings are non-compliant with ${framework} — urgent remediation needed`;
  if (pct > 20) return `${pct}% of findings are non-compliant with ${framework} — remediation recommended`;
  return `Minor compliance gaps found (${nonCompliantCount}/${totalCount}) for ${framework}`;
}

function getFrameworkSummary(vulnerabilities) {
  const summaries = {};
  for (const framework of Object.keys(COMPLIANCE_FRAMEWORKS)) {
    summaries[framework] = generateComplianceReport(vulnerabilities, framework);
  }
  return summaries;
}

module.exports = {
  COMPLIANCE_FRAMEWORKS, mapVulnerabilityToCompliance,
  generateComplianceReport, getFrameworkSummary,
};
