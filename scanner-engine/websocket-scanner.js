const WebSocket = require('ws');

const WS_ATTACK_PAYLOADS = [
  { payload: '<script>alert(1)</script>', type: 'xss', description: 'XSS via WebSocket' },
  { payload: "' OR '1'='1", type: 'sqli', description: 'SQLi via WebSocket' },
  { payload: '../../etc/passwd', type: 'lfi', description: 'LFI via WebSocket' },
  { payload: '${7*7}', type: 'ssti', description: 'SSTI via WebSocket' },
  { payload: '{{constructor.constructor("alert(1)")()}}', type: 'xss', description: 'JS template XSS' },
  { payload: '<img src=x onerror=alert(1)>', type: 'xss', description: 'Img tag XSS' },
  { payload: '"; ping -c 3 127.0.0.1; "', type: 'cmdi', description: 'Command injection' },
  { payload: '{"__proto__":{"admin":true}}', type: 'pp', description: 'Prototype pollution' },
  { payload: '{"query":"mutation { __typename }","variables":{}}', type: 'graphql', description: 'GraphQL introspection' },
];

const SUSPICIOUS_WS_PATTERNS = [
  { pattern: /admin|config|secret|key|password|token|credential/i, severity: 'high', label: 'Sensitive data in WS messages' },
  { pattern: /eval\(|Function\(|setTimeout\(|setInterval\(/i, severity: 'high', label: 'Code execution in WS messages' },
  { pattern: /root:|nobody:|daemon:/i, severity: 'critical', label: 'System file content in WS' },
  { pattern: /SELECT|INSERT|UPDATE|DELETE|DROP|UNION/i, severity: 'critical', label: 'SQL query in WS response' },
  { pattern: /flag\{|FLAG\{|ctf\{/i, severity: 'critical', label: 'Flag/secret exposure' },
];

async function scanWebSocket(targetUrl, httpClient) {
  const vulnerabilities = [];
  let hostname;
  try { hostname = new URL(targetUrl).hostname; } catch { return vulnerabilities; }

  const wsUrls = [
    `ws://${hostname}`,
    `wss://${hostname}`,
    `ws://${hostname}/ws`,
    `wss://${hostname}/ws`,
    `ws://${hostname}/socket`,
    `wss://${hostname}/socket`,
    `ws://${hostname}/websocket`,
    `wss://${hostname}/websocket`,
    `ws://${hostname}/chat`,
    `wss://${hostname}/chat`,
    `ws://${hostname}/notifications`,
    `wss://${hostname}/notifications`,
    `ws://${hostname}/live`,
    `wss://${hostname}/live`,
  ];

  for (const wsUrl of wsUrls) {
    try {
      await tryWSConnection(wsUrl, vulnerabilities);
    } catch {}
  }

  if (vulnerabilities.length === 0) {
    const socketIo = await detectSocketIO(targetUrl, httpClient);
    if (socketIo) {
      vulnerabilities.push({
        type: 'websocket',
        severity: 'info',
        title: 'Socket.IO Endpoint Detected',
        description: `Socket.IO detected at ${socketIo}. WebSocket connection possible.`,
        endpoint: socketIo,
        parameter: 'N/A',
        payload: 'Socket.IO handshake detection',
        evidence: `Path: ${socketIo}\nFramework: Socket.IO`,
        remediation: 'Ensure WebSocket connections are authenticated. Validate all messages server-side.',
        owasp_category: 'A05:2021 – Security Misconfiguration',
        cve_id: 'CWE-200',
      });
    }
  }

  return vulnerabilities;
}

function tryWSConnection(wsUrl, vulnerabilities) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      ws.terminate();
      resolve();
    }, 4000);

    const ws = new WebSocket(wsUrl, {
      rejectUnauthorized: false,
      handshakeTimeout: 3000,
    });

    ws.on('open', () => {
      clearTimeout(timeout);
      vulnerabilities.push({
        type: 'websocket',
        severity: 'medium',
        title: 'WebSocket Endpoint Exposed',
        description: `WebSocket connection successful at ${wsUrl}. May allow real-time attacks.`,
        endpoint: wsUrl,
        parameter: 'N/A',
        payload: 'WebSocket handshake',
        evidence: `URL: ${wsUrl}\nProtocol: ws${wsUrl.startsWith('wss') ? 's' : ''}\nStatus: Connection established`,
        remediation: 'Authenticate WebSocket connections. Validate all messages. Implement rate limiting on WS endpoints.',
        owasp_category: 'A05:2021 – Security Misconfiguration',
        cve_id: 'CWE-200',
      });

      sendWSPayloads(ws, wsUrl, vulnerabilities).finally(() => {
        ws.close();
        resolve();
      });
    });

    ws.on('error', () => {
      clearTimeout(timeout);
      resolve();
    });

    ws.on('timeout', () => {
      clearTimeout(timeout);
      ws.terminate();
      resolve();
    });
  });
}

async function sendWSPayloads(ws, wsUrl, vulnerabilities) {
  for (const attack of WS_ATTACK_PAYLOADS) {
    try {
      const echoed = await wsEcho(ws, attack.payload, 2000);
      if (echoed && echoed.includes(attack.payload)) {
        vulnerabilities.push({
          type: 'websocket',
          severity: attack.type === 'sqli' || attack.type === 'lfi' ? 'critical' : 'high',
          title: `WebSocket Injection - ${attack.description}`,
          description: `WebSocket at ${wsUrl} echoes attack payload. ${attack.description}.`,
          endpoint: wsUrl,
          parameter: 'WebSocket message',
          payload: attack.payload,
          evidence: `Attack type: ${attack.type}\nSent: ${attack.payload}\nEchoed: ${echoed.substring(0, 200)}`,
          remediation: 'Validate and sanitize all WebSocket messages server-side. Never echo untrusted data.',
          owasp_category: 'A03:2021 – Injection',
          cve_id: 'CWE-79',
        });
        break;
      }
    } catch {}
  }
}

function wsEcho(ws, message, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => resolve(null), timeoutMs);
    const handler = (data) => {
      const str = typeof data === 'string' ? data : data.toString();
      if (str.length > 0) {
        clearTimeout(timeout);
        ws.removeListener('message', handler);
        resolve(str);
      }
    };
    ws.on('message', handler);
    try {
      ws.send(typeof message === 'string' ? message : JSON.stringify(message));
    } catch {
      clearTimeout(timeout);
      ws.removeListener('message', handler);
      reject();
    }
  });
}

async function detectSocketIO(targetUrl, httpClient) {
  const paths = ['/socket.io/socket.io.js', '/socket.io/', '/socket.io/?EIO=4'];
  for (const path of paths) {
    try {
      const resp = await httpClient.get(targetUrl.replace(/\/$/, '') + path, { timeout: 3000, validateStatus: s => s < 500 });
      if (resp.status === 200) return path;
    } catch {}
  }
  const body = typeof (await httpClient.get(targetUrl, { timeout: 3000 }).catch(() => ({ data: '' }))).data === 'string'
    ? (await httpClient.get(targetUrl, { timeout: 3000 }).catch(() => ({ data: '' }))).data : '';
  if (body.includes('socket.io') || body.includes('io.connect')) return 'Socket.IO detected in page source';
  return null;
}

module.exports = { scanWebSocket, WS_ATTACK_PAYLOADS };
