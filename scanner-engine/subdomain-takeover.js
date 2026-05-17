const TAKEOVER_SIGNATURES = [
  { service: 'AWS S3', pattern: /NoSuchBucket|The specified bucket does not exist/i, cname: /\.s3\.amazonaws\.com|\.s3-website/ },
  { service: 'AWS CloudFront', pattern: /ERROR: The request could not be satisfied|CloudFront.*not find/i, cname: /cloudfront\.net/ },
  { service: 'Azure CDN', pattern: /404.*not find|The resource you are looking for has been removed/i, cname: /\.azureedge\.net|\.trafficmanager\.net/ },
  { service: 'Azure Cloud App', pattern: /Sorry, we can't find that cloud app/i, cname: /\.cloudapp\.net/ },
  { service: 'GitHub Pages', pattern: /There isn't a GitHub Pages site here/i, cname: /\.github\.io/ },
  { service: 'GitLab Pages', pattern: /404.*GitLab|The page you're looking for could not be found/i, cname: /\.gitlab\.io/ },
  { service: 'Heroku', pattern: /no such app|There's nothing here/i, cname: /\.herokuapp\.com|herokudns\.com/ },
  { service: 'Netlify', pattern: /Not Found.*Netlify|Page not found.*Netlify/i, cname: /\.netlify\.app|\.netlify\.com/ },
  { service: 'Shopify', pattern: /Sorry, this shop is currently unavailable/i, cname: /\.myshopify\.com/ },
  { service: 'Tumblr', pattern: /There's nothing here/i, cname: /\.tumblr\.com/ },
  { service: 'Squarespace', pattern: /No site for domain/i, cname: /\.squarespace\.com/ },
  { service: 'WordPress', pattern: /Do you want to register|domain not found.*wordpress/i, cname: /\.wordpress\.com/ },
  { service: 'Zendesk', pattern: /Help Center Closed|This help center is no longer available/i, cname: /\.zendesk\.com/ },
  { service: 'Readme.io', pattern: /Project doesn't exist/i, cname: /\.readme\.io/ },
  { service: 'Strikingly', pattern: /page not found/i, cname: /\.strikinglydns\.com/ },
  { service: 'Unbounce', pattern: /The page you requested was not found/i, cname: /\.unbouncepages\.com/ },
  { service: 'Bitbucket', pattern: /Repository not found/i, cname: /\.bitbucket\.io/ },
  { service: 'Campaign Monitor', pattern: /Trying to access your account/i, cname: /\.createsend\.com/ },
  { service: 'Acquia', pattern: /Site not found/i, cname: /\.acquia\-site\.com/ },
  { service: 'Pantheon', pattern: /404 error.*pantheon|The gods are angry/i, cname: /\.pantheonsite\.io/ },
  { service: 'Fly.io', pattern: /404.*not found/i, cname: /\.fly\.dev/ },
  { service: 'Vercel', pattern: /The deployment could not be found/i, cname: /\.vercel\.app|\.now\.sh/ },
  { service: 'Surge.sh', pattern: /project not found/i, cname: /\.surge\.sh/ },
  { service: 'Cargo Collective', pattern: /404.*Cargo/i, cname: /\.cargocollective\.com/ },
  { service: 'Fastly', pattern: /Fastly error.*not found/i, cname: /\.global\.ssl\.fastly\.net/ },
  { service: 'Kinsta', pattern: /No site configured/i, cname: /\.kinsta\.cloud/ },
  { service: 'Cloudflare Workers', pattern: /Worker not found/i, cname: /\.workers\.dev/ },
  { service: 'Freshdesk', pattern: /This account has been suspended/i, cname: /\.freshdesk\.com/ },
  { service: 'Helpjuice', pattern: /We could not find what you're looking for/i, cname: /\.helpjuice\.com/ },
  { service: 'Intercom', pattern: /We couldn't find what you were looking for/i, cname: /\.custom\.intercom\.help/ },
  { service: 'Smartlook', pattern: /The page you are looking for does not exist/i, cname: /\.smartlook\.com/ },
  { service: 'Tilda', pattern: /Page not found/i, cname: /\.tilda\.ws/ },
  { service: 'Uberflip', pattern: /The page you're looking for doesn't exist/i, cname: /\.uberflip\.com/ },
  { service: 'Mashery', pattern: /Unrecognized domain|Domain not registered/i, cname: /\.mashery\.com/ },
];

async function scanSubdomainTakeover(domain, httpClient) {
  const vulnerabilities = [];
  const dns = require('dns').promises;

  const subdomains = [
    '', 'www', 'api', 'app', 'blog', 'admin', 'mail', 'cdn', 'static',
    'dev', 'test', 'staging', 'docs', 'help', 'support', 'community',
    'shop', 'store', 'm', 'mobile', 'status', 'assets', 'media',
    'img', 'images', 'video', 'download', 'files', 'upload',
    'portal', 'login', 'auth', 'sso', 'id', 'account', 'profile',
    'dashboard', 'analytics', 'monitor', 'metrics', 'git', 'ci',
    'jenkins', 'jira', 'wiki', 'confluence', 'slack', 'chat',
    'forum', 'news', 'events', 'jobs', 'careers', 'partners',
    'beta', 'alpha', 'demo', 'sandbox', 'stage', 'preprod',
    'backup', 'db', 'database', 'mysql', 'redis', 'cache',
    'remote', 'vpn', 'proxy', 'gateway', 'monitor', 'logs',
    'config', 'setup', 'install', 'upgrade', 'patch', 'update',
    'ns1', 'ns2', 'ns3', 'mx1', 'mx2', 'mail2', 'smtp', 'pop3',
    'imap', 'webmail', 'owa', 'exchange', 'calendar', 'drive',
    'cloud', 'storage', 'ftp', 'sftp', 'ssh', 'console',
    'manager', 'management', 'control', 'panel', 'cpanel',
    'whm', 'webdisk', 'phpmyadmin', 'phpadmin', 'administrator',
    'server', 'node1', 'node2', 'cluster', 'lb', 'loadbalancer',
    'tracker', 'report', 'billing', 'invoice', 'payment',
    'checkout', 'cart', 'orders', 'returns', 'feedback',
    'survey', 'polls', 'vote', 'events-api', 'stream',
    'socket', 'notifications', 'alert', 'alerts', 'logs-api',
  ];

  for (const sub of subdomains) {
    const fqdn = sub ? `${sub}.${domain}` : domain;
    try {
      const cnames = await resolveCNAME(fqdn);
      for (const cname of cnames) {
        for (const sig of TAKEOVER_SIGNATURES) {
          if ((sig.cname && sig.cname.test(cname)) || (sig.cname2 && sig.cname2.test(cname))) {
            const confirmResult = await confirmTakeover(fqdn, sig.service, sig.pattern, httpClient);
            if (confirmResult) {
              vulnerabilities.push({
                type: 'subdomain-takeover',
                severity: 'critical',
                title: `Subdomain Takeover - ${fqdn}`,
                description: `${fqdn} (CNAME: ${cname}) points to unclaimed ${sig.service} service and can be taken over.`,
                endpoint: fqdn,
                parameter: 'DNS CNAME',
                payload: `CNAME: ${cname} → ${sig.service}`,
                evidence: `Domain: ${fqdn}\nCNAME: ${cname}\nService: ${sig.service}\nConfirmed: ${confirmResult}`,
                remediation: `Remove the DNS CNAME record pointing to ${sig.service} or claim the ${sig.service} resource. Regularly audit DNS records for dangling references.`,
                owasp_category: 'A05:2021 – Security Misconfiguration',
                cve_id: 'CWE-200',
              });
            } else {
              vulnerabilities.push({
                type: 'subdomain-takeover',
                severity: 'high',
                title: `Potential Subdomain Takeover - ${fqdn}`,
                description: `${fqdn} (CNAME: ${cname}) points to ${sig.service} which may be unclaimed.`,
                endpoint: fqdn,
                parameter: 'DNS CNAME',
                payload: `CNAME: ${cname} → ${sig.service}`,
                evidence: `Domain: ${fqdn}\nCNAME: ${cname}\nService: ${sig.service}`,
                remediation: 'Investigate and either claim the external resource or remove the dangling DNS record.',
                owasp_category: 'A05:2021 – Security Misconfiguration',
                cve_id: 'CWE-200',
              });
            }
            break;
          }
        }
      }
    } catch {}
  }

  return vulnerabilities;
}

async function resolveCNAME(fqdn) {
  const dns = require('dns').promises;
  const results = [];
  let current = fqdn;
  for (let i = 0; i < 5; i++) {
    try {
      const cname = await dns.resolveCname(current);
      if (cname && cname[0]) {
        results.push(cname[0]);
        current = cname[0];
      } else break;
    } catch { break; }
  }
  try {
    const a = await dns.resolve4(current);
    results.push(a[0]);
  } catch {}
  return results;
}

async function confirmTakeover(fqdn, service, pattern, httpClient) {
  try {
    const resp = await httpClient.get(`http://${fqdn}`, {
      timeout: 8000,
      validateStatus: s => s < 600,
    });
    const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
    if (pattern && pattern.test(body)) {
      return `Confirmed: "${pattern.source}" found in HTTP response`;
    }
    if (resp.status === 404 || resp.status === 403) {
      return `HTTP ${resp.status} - potential takeover`;
    }
  } catch (err) {
    if (err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED') {
      return `DNS/NXDOMAIN: ${err.code}`;
    }
  }
  try {
    const resp = await httpClient.get(`https://${fqdn}`, {
      timeout: 8000,
      validateStatus: s => s < 600,
    });
    const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
    if (pattern && pattern.test(body)) {
      return `Confirmed (HTTPS): "${pattern.source}" found`;
    }
  } catch {}
  return null;
}

module.exports = { scanSubdomainTakeover, TAKEOVER_SIGNATURES };
