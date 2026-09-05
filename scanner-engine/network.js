const dns = require('dns');
const net = require('net');
const tls = require('tls');

const COMMON_PORTS = [
  { port: 21, service: 'FTP', severity: 'medium' },
  { port: 22, service: 'SSH', severity: 'low' },
  { port: 23, service: 'Telnet', severity: 'high' },
  { port: 25, service: 'SMTP', severity: 'medium' },
  { port: 53, service: 'DNS', severity: 'info' },
  { port: 80, service: 'HTTP', severity: 'info' },
  { port: 110, service: 'POP3', severity: 'medium' },
  { port: 143, service: 'IMAP', severity: 'medium' },
  { port: 443, service: 'HTTPS', severity: 'info' },
  { port: 445, service: 'SMB', severity: 'high' },
  { port: 1433, service: 'MSSQL', severity: 'medium' },
  { port: 1521, service: 'Oracle DB', severity: 'medium' },
  { port: 3306, service: 'MySQL', severity: 'medium' },
  { port: 3389, service: 'RDP', severity: 'high' },
  { port: 5432, service: 'PostgreSQL', severity: 'medium' },
  { port: 5900, service: 'VNC', severity: 'high' },
  { port: 6379, service: 'Redis', severity: 'medium' },
  { port: 8080, service: 'HTTP-Proxy', severity: 'info' },
  { port: 8443, service: 'HTTPS-Alt', severity: 'info' },
  { port: 27017, service: 'MongoDB', severity: 'medium' },
];

function checkPort(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, host);
  });
}

function getServerBanner(host, port, timeout = 5000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    let banner = '';

    socket.on('connect', () => {
      socket.write('HEAD / HTTP/1.0\r\n\r\n');
    });

    socket.on('data', (data) => {
      banner += data.toString();
      if (banner.length > 2000 || banner.includes('\r\n\r\n')) {
        socket.destroy();
      }
    });

    socket.on('close', () => {
      resolve(banner.substring(0, 2000));
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(banner.substring(0, 2000));
    });

    socket.on('error', () => {
      resolve('');
    });

    socket.connect(port, host);
  });
}

function checkSSL(host, port = 443, timeout = 5000) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host, port,
      rejectUnauthorized: false,
      timeout,
    }, () => {
      const cert = socket.getPeerCertificate();
      const cipher = socket.getCipher();
      const protocol = socket.getProtocol();
      socket.end();

      resolve({
        valid: socket.authorized,
        subject: cert.subject,
        issuer: cert.issuer,
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        daysRemaining: cert.valid_to ? Math.floor((new Date(cert.valid_to) - new Date()) / 86400000) : 0,
        cipher: cipher ? `${cipher.name} (${cipher.version})` : 'Unknown',
        protocol: protocol || 'Unknown',
        sni: cert.subjectaltname || 'N/A',
      });
    });

    socket.on('error', () => {
      resolve(null);
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(null);
    });
  });
}

async function scanNetwork(targetUrl, httpClient) {
  const vulnerabilities = [];
  let host;
  try {
    host = new URL(targetUrl).hostname;
  } catch {
    return [{ type: 'network', severity: 'info', title: 'Invalid URL', description: 'Could not parse hostname from URL', endpoint: targetUrl, parameter: 'N/A', payload: 'N/A', evidence: 'URL parsing failed', remediation: 'N/A', owasp_category: 'N/A', cve_id: 'N/A' }];
  }

  const openPorts = [];
  const CHUNK_SIZE = 5;
  for (let i = 0; i < COMMON_PORTS.length; i += CHUNK_SIZE) {
    const chunk = COMMON_PORTS.slice(i, i + CHUNK_SIZE);
    const results = await Promise.all(chunk.map(p => checkPort(host, p.port)));
    for (let j = 0; j < chunk.length; j++) {
      if (results[j]) {
        openPorts.push(chunk[j]);
      }
    }
  }

  for (const port of openPorts) {
    vulnerabilities.push({
      type: 'network',
      severity: port.severity,
      title: `Open Port Detected - ${port.service} (${port.port})`,
      description: `Port ${port.port} (${port.service}) is open on ${host}. This expands the attack surface.`,
      endpoint: `${host}:${port.port}`,
      parameter: 'N/A (Port Scan)',
      payload: `TCP Connect to ${host}:${port.port}`,
      evidence: `Host: ${host}\nPort: ${port.port}\nService: ${port.service}\nStatus: OPEN\nRisk: ${port.severity.toUpperCase()}`,
      remediation: `Close port ${port.port} if not needed. Restrict access with firewall rules. Ensure ${port.service} is properly secured and updated.`,
      owasp_category: 'A05:2021 – Security Misconfiguration',
      cve_id: 'CWE-200',
    });
  }

  if (host && (targetUrl.startsWith('https://') || port === 443)) {
    const sslInfo = await checkSSL(host, 443);
    if (sslInfo) {
      if (!sslInfo.valid) {
        vulnerabilities.push({
          type: 'network',
          severity: 'high',
          title: 'SSL/TLS Certificate Validation Failed',
          description: `SSL certificate for ${host} is self-signed or invalid. Users cannot verify server identity.`,
          endpoint: `${host}:443`,
          parameter: 'N/A',
          payload: 'TLS Handshake',
          evidence: `Host: ${host}\nProtocol: ${sslInfo.protocol}\nCipher: ${sslInfo.cipher}\nSubject: ${JSON.stringify(sslInfo.subject)}\nIssuer: ${JSON.stringify(sslInfo.issuer)}`,
          remediation: 'Use a valid SSL certificate from a trusted CA. Configure proper TLS settings. Consider using Let\'s Encrypt for free certificates.',
          owasp_category: 'A05:2021 – Security Misconfiguration',
          cve_id: 'CWE-295',
        });
      }

      if (sslInfo.daysRemaining < 30 && sslInfo.daysRemaining >= 0) {
        vulnerabilities.push({
          type: 'network',
          severity: 'high',
          title: 'SSL Certificate Expiring Soon',
          description: `SSL certificate for ${host} expires in ${sslInfo.daysRemaining} days.`,
          endpoint: `${host}:443`,
          parameter: 'N/A',
          payload: 'TLS Certificate Check',
          evidence: `Host: ${host}\nExpires: ${sslInfo.validTo}\nDays remaining: ${sslInfo.daysRemaining}`,
          remediation: 'Renew the SSL certificate before it expires. Set up automated renewal with tools like certbot.',
          owasp_category: 'A05:2021 – Security Misconfiguration',
          cve_id: 'CWE-295',
        });
      }

      if (sslInfo.protocol && !sslInfo.protocol.includes('TLSv1.3') && !sslInfo.protocol.includes('TLSv1.2')) {
        vulnerabilities.push({
          type: 'network',
          severity: 'medium',
          title: 'Outdated TLS Protocol',
          description: `Server uses ${sslInfo.protocol}. Modern TLS 1.2 or 1.3 is recommended.`,
          endpoint: `${host}:443`,
          parameter: 'N/A',
          payload: 'TLS Protocol Check',
          evidence: `Host: ${host}\nProtocol: ${sslInfo.protocol}\nCipher: ${sslInfo.cipher}`,
          remediation: 'Disable TLS 1.0/1.1. Enable only TLS 1.2 and TLS 1.3. Use secure cipher suites.',
          owasp_category: 'A05:2021 – Security Misconfiguration',
          cve_id: 'CWE-326',
        });
      }

      vulnerabilities.push({
        type: 'network',
        severity: 'info',
        title: `SSL/TLS Configuration: ${sslInfo.protocol}`,
        description: `Server uses ${sslInfo.protocol} with ${sslInfo.cipher}. Certificate expires in ${sslInfo.daysRemaining} days.`,
        endpoint: `${host}:443`,
        parameter: 'N/A',
        payload: 'TLS Handshake',
        evidence: `Protocol: ${sslInfo.protocol}\nCipher: ${sslInfo.cipher}\nDays remaining: ${sslInfo.daysRemaining}\nSubject: ${JSON.stringify(sslInfo.subject)}`,
        remediation: 'Maintain current TLS configuration and renew certificate before expiry.',
        owasp_category: 'A05:2021 – Security Misconfiguration',
        cve_id: 'CWE-295',
      });
    }
  }

  return vulnerabilities;
}

module.exports = { scanNetwork, COMMON_PORTS, checkPort, checkSSL };