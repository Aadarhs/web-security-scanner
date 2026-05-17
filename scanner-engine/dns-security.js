const dns = require('dns').promises;

async function analyzeDNS(targetDomain) {
  const results = {
    domain: targetDomain,
    mx: [], spf: null, dmarc: null, dkim: null,
    dnssec: false, dnsssecDetails: null,
    securityScore: 0, issues: [], recommendations: [],
    error: null,
  };

  if (!targetDomain) { results.error = 'Domain required'; return results; }

  try {
    const mxRecords = await dns.resolveMx(targetDomain);
    results.mx = mxRecords.sort((a, b) => a.priority - b.priority).map(r => ({
      priority: r.priority, exchange: r.exchange,
    }));
    if (results.mx.length === 0) {
      results.issues.push('No MX records found — email delivery may be affected');
    }
  } catch {
    results.issues.push('Could not resolve MX records');
  }

  try {
    const txtRecords = await dns.resolveTxt(targetDomain);
    const allTxt = txtRecords.map(parts => parts.join(''));

    for (const txt of allTxt) {
      if (txt.startsWith('v=spf1')) {
        results.spf = txt;
        if (txt.includes('?all')) results.issues.push('SPF: Neutral policy (?all) — spoofing possible');
        if (txt.includes('~all')) results.issues.push('SPF: SoftFail policy (~all) — may be spoofed');
        if (txt.includes('-all')) {/* good */}
        if (!txt.includes('~all') && !txt.includes('-all') && !txt.includes('?all') && !txt.includes('+all')) {
          results.issues.push('SPF: No explicit deny mechanism — any host can send mail');
        }
        if (txt.includes('+all')) results.issues.push('SPF: Allow all (+all) — completely insecure');
        break;
      }
    }
    if (!results.spf) {
      results.issues.push('No SPF record found — email spoofing is possible');
    }

    for (const txt of allTxt) {
      if (txt.startsWith('v=DMARC1')) {
        results.dmarc = txt;
        if (txt.includes('p=none')) results.issues.push('DMARC: Policy is "none" — monitoring only, no protection');
        if (txt.includes('p=quarantine')) results.recommendations.push('DMARC: Quarantine policy in place');
        if (txt.includes('p=reject')) results.recommendations.push('DMARC: Reject policy — excellent email security');
        const ruaMatch = txt.match(/rua=mailto:([^\s;]+)/);
        if (ruaMatch) results.recommendations.push(`DMARC reports sent to: ${ruaMatch[1]}`);
        break;
      }
    }
    if (!results.dmarc) {
      results.issues.push('No DMARC record found — email spoofing/unrestricted');
    }

    for (const txt of allTxt) {
      if (txt.startsWith('v=DKIM1') || txt.includes('k=rsa')) {
        results.dkim = txt;
        break;
      }
    }
    if (!results.dkim) {
      const selectors = ['google', 'dkim', 'mail', 'default', 'selector1', 's1', 's2', 'k1', 'mx', 'proton'];
      for (const sel of selectors) {
        try {
          const dkimTxt = await dns.resolveTxt(`${sel}._domainkey.${targetDomain}`);
          const dkimStr = dkimTxt.map(p => p.join('')).join('');
          if (dkimStr) {
            results.dkim = dkimStr;
            results.dkimSelector = sel;
            break;
          }
        } catch {}
      }
    }
    if (!results.dkim) {
      results.issues.push('No DKIM record found — email signing not configured');
    }
  } catch {
    if (!results.spf) results.issues.push('Could not query TXT records');
  }

  try {
    await dns.resolve('nl.' + targetDomain, 'RRSIG');
    results.dnssec = true;
  } catch {
    try {
      const soa = await dns.resolveSoa(targetDomain);
      if (soa) {
        try {
          await dns.resolve(targetDomain, 'RRSIG');
          results.dnssec = true;
        } catch {
          results.dnssec = false;
          results.issues.push('DNSSEC not enabled — DNS responses can be spoofed');
        }
      }
    } catch {}
  }

  if (!results.dnssec) {
    results.issues.push('DNSSEC not configured — vulnerable to DNS spoofing/cache poisoning');
  }

  let score = 100;
  if (!results.spf) score -= 20;
  else if (results.spf.includes('?all') || results.spf.includes('+all')) score -= 15;
  else if (results.spf.includes('~all')) score -= 5;

  if (!results.dmarc) score -= 20;
  else if (results.dmarc.includes('p=none')) score -= 10;
  else if (results.dmarc.includes('p=quarantine')) score += 5;
  else if (results.dmarc.includes('p=reject')) score += 10;

  if (!results.dkim) score -= 15;
  if (!results.dnssec) score -= 15;
  if (results.mx.length === 0) score -= 10;

  results.securityScore = Math.max(0, Math.min(100, score));

  if (results.securityScore >= 80) results.recommendations.push('Overall: Good email security posture');
  else if (results.securityScore >= 50) results.recommendations.push('Overall: Moderate — improvement needed');
  else results.recommendations.push('Overall: Poor — urgent remediation required');

  return results;
}

async function scanDNS(targetDomain) {
  const result = { domain: targetDomain, records: {}, error: null };
  if (!targetDomain) { result.error = 'Domain required'; return result; }

  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME'];
  for (const type of types) {
    try {
      const records = await dns.resolve(targetDomain, type);
      result.records[type] = Array.isArray(records)
        ? records.map(r => (typeof r === 'object' ? JSON.stringify(r) : String(r)))
        : [String(records)];
    } catch {
      result.records[type] = [];
    }
  }

  result.dnssec = false;
  try {
    await dns.resolve(targetDomain, 'RRSIG');
    result.dnssec = true;
  } catch {}

  return result;
}

module.exports = { analyzeDNS, scanDNS };
