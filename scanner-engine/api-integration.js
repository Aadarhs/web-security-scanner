const axios = require('axios');

const CACHE_DURATION = 3600000;
const cache = {};

function getFromCache(key) {
  const entry = cache[key];
  if (entry && (Date.now() - entry.timestamp) < CACHE_DURATION) {
    return entry.data;
  }
  return null;
}

function setCache(key, data) {
  cache[key] = { data, timestamp: Date.now() };
}

function lookupNVDCVE(cveId) {
  return new Promise(async (resolve) => {
    if (!cveId || cveId === 'N/A' || cveId === 'CWE-200' || cveId === 'CWE-89') {
      return resolve(null);
    }

    const cached = getFromCache(`nvd_${cveId}`);
    if (cached) return resolve(cached);

    try {
      const response = await axios.get(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`, {
        timeout: 10000,
        headers: { 'User-Agent': 'WebSecurityScanner/1.0' },
      });

      if (response.data?.vulnerabilities?.[0]) {
        const vuln = response.data.vulnerabilities[0].cve;
        const result = {
          id: vuln.id,
          description: vuln.descriptions?.find(d => d.lang === 'en')?.value || 'No description',
          cvssScore: vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || null,
          severity: vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || null,
          published: vuln.published,
          lastModified: vuln.lastModified,
          references: (vuln.references || []).slice(0, 3).map(r => r.url),
        };
        setCache(`nvd_${cveId}`, result);
        return resolve(result);
      }
    } catch {
      // NVD API unavailable - silently continue
    }
    return resolve(null);
  });
}

function lookupCWE(cweId) {
  const cweDb = {
    'CWE-22': { name: 'Path Traversal', description: 'Improper Limitation of a Pathname to a Restricted Directory' },
    'CWE-78': { name: 'OS Command Injection', description: 'Improper Neutralization of Special Elements used in an OS Command' },
    'CWE-79': { name: 'Cross-Site Scripting', description: 'Improper Neutralization of Input During Web Page Generation' },
    'CWE-89': { name: 'SQL Injection', description: 'Improper Neutralization of Special Elements used in an SQL Command' },
    'CWE-200': { name: 'Information Exposure', description: 'Exposure of Sensitive Information to an Unauthorized Actor' },
    'CWE-295': { name: 'Improper Certificate Validation', description: 'Improper Validation of Certificate with Host Mismatch' },
    'CWE-306': { name: 'Missing Authentication', description: 'Missing Authentication for Critical Function' },
    'CWE-326': { name: 'Inadequate Encryption Strength', description: 'Inadequate Encryption Strength' },
    'CWE-352': { name: 'CSRF', description: 'Cross-Site Request Forgery' },
    'CWE-400': { name: 'Uncontrolled Resource Consumption', description: 'Uncontrolled Resource Consumption' },
    'CWE-502': { name: 'Deserialization of Untrusted Data', description: 'Deserialization of Untrusted Data' },
    'CWE-530': { name: 'Exposure of Backup Files', description: 'Exposure of Backup Files to an Unauthorized Control Sphere' },
    'CWE-601': { name: 'Open Redirect', description: 'URL Redirection to Untrusted Site' },
    'CWE-611': { name: 'XXE', description: 'Improper Restriction of XML External Entity Reference' },
    'CWE-918': { name: 'SSRF', description: 'Server-Side Request Forgery' },
    'CWE-942': { name: 'CORS Misconfiguration', description: 'Permissive Cross-domain Policy with Untrusted Domains' },
  };

  const cached = getFromCache(`cwe_${cweId}`);
  if (cached) return cached;

  const result = cweDb[cweId] || null;
  if (result) setCache(`cwe_${cweId}`, result);
  return result;
}

function lookupOWASPCategory(category) {
  const owaspDb = {
    'A01:2021 – Broken Access Control': 'Access control enforces policy such that users cannot act outside of their intended permissions.',
    'A03:2021 – Injection': 'Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.',
    'A04:2021 – Insecure Design': 'Insecure design refers to risks related to design and architecture flaws.',
    'A05:2021 – Security Misconfiguration': 'Security misconfiguration is the most commonly seen issue in applications.',
    'A07:2021 – Identification and Authentication Failures': 'Authentication failures allow attackers to compromise user accounts.',
    'A10:2021 – Server-Side Request Forgery (SSRF)': 'SSRF occurs when a web application fetches a remote resource without validating the user-supplied URL.',
  };

  const cached = getFromCache(`owasp_${category}`);
  if (cached) return cached;

  const result = owaspDb[category] || null;
  if (result) setCache(`owasp_${category}`, result);
  return result;
}

async function enhanceVulnerability(vuln) {
  const cveData = await lookupNVDCVE(vuln.cve_id);
  const cweData = lookupCWE(vuln.cve_id);
  const owaspData = lookupOWASPCategory(vuln.owasp_category);

  return {
    ...vuln,
    enhanced: {
      cveDescription: cveData?.description || null,
      cveScore: cveData?.cvssScore || null,
      cveSeverity: cveData?.severity || null,
      cvePublished: cveData?.published || null,
      cweName: cweData?.name || null,
      cweDescription: cweData?.description || null,
      owaspDescription: owaspData || null,
      cveReferences: cveData?.references || [],
    },
  };
}

async function enrichVulnerabilities(vulnerabilities) {
  const enriched = await Promise.all(
    vulnerabilities.map(v => enhanceVulnerability(v).catch(() => v))
  );
  return enriched;
}

function checkSecuritytxt(targetUrl) {
  return new Promise(async (resolve) => {
    try {
      const response = await axios.get(`${targetUrl.replace(/\/$/, '')}/.well-known/security.txt`, {
        timeout: 5000,
        validateStatus: s => s < 500,
      });
      if (response.status === 200) {
        const body = typeof response.data === 'string' ? response.data : '';
        return resolve({
          hasSecurityTxt: true,
          contact: (body.match(/^Contact:\s*(.+)$/m) || [])[1] || 'Unknown',
          expires: (body.match(/^Expires:\s*(.+)$/m) || [])[1] || 'Unknown',
          content: body.substring(0, 500),
        });
      }
    } catch {}
    return resolve({ hasSecurityTxt: false });
  });
}

async function checkSecurityHeadersAPI(targetUrl) {
  const hostname = (() => { try { return new URL(targetUrl).hostname; } catch { return null; } })();
  if (!hostname) return null;

  try {
    const response = await axios.get(`https://securityheaders.com/?q=${hostname}&followRedirects=on`, {
      timeout: 15000,
      headers: { 'User-Agent': 'WebSecurityScanner/1.0' },
    });

    if (response.status === 200) {
      const body = typeof response.data === 'string' ? response.data : '';
      const gradeMatch = body.match(/<span[^>]*class="[^"]*grade[^"]*"[^>]*>([A-F][+-]?)/i);

      return {
        grade: gradeMatch ? gradeMatch[1] : 'N/A',
        url: `https://securityheaders.com/?q=${hostname}&followRedirects=on`,
      };
    }
  } catch {}
  return null;
}

module.exports = { lookupNVDCVE, lookupCWE, lookupOWASPCategory, enhanceVulnerability, enrichVulnerabilities, checkSecuritytxt, checkSecurityHeadersAPI };