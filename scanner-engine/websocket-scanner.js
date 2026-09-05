'use strict';

const WebSocket = require('ws');
const { mkFinding, CONFIDENCE } = require('./evidence');

const WS_ATTACK_PAYLOADS = [
  { payload: '<script>alert(1)</script>', type: 'xss', description: 'XSS via WebSocket' },
  { payload: "' OR '1'='1", type: 'sqli', description: 'SQLi via WebSocket' },
  { payload: '../../etc/passwd', type: 'lfi', description: 'LFI via WebSocket' },
  { payload: '${7*7}', type: 'ssti', description: 'SSTI via WebSocket' },
  { payload: '<img src=x onerror=alert(1)>', type: 'xss', description: 'Img tag XSS' },
  { payload: '"; ping -c 3 127.0.0.1; "', type: 'cmdi', description: 'Command injection' },
  { payload: '{"__proto__":{"admin":true}}', type: 'pp', description: 'Prototype pollution' },
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
      vulnerabilities.push(mkFinding('websocket', {
        type: 'websocket',
        severity: 'info',
        confidence: CONFIDENCE.CONFIRMED,
        title: 'Socket.IO Endpoint Detected',
        description: `Socket.IO detected at ${socketIo}. WebSocket connections may be possible here.`,
        endpoint: socketIo,
        parameter: 'N/A',
        payload: 'Socket.IO handshake detection',
        evidence: `Path: ${socketIo}\nFramework: Socket.IO`,
        remediation: 'Ensure WebSocket connections are authenticated and all messages are validated server-side.',
        owasp_category: 'A05:2021 – Security Misconfiguration',
        cve_id: 'CWE-200',
      }));
    }
  }

  return vulnerabilities;
}

function tryWSConnection(wsUrl, vulnerabilities) {
  return new Promise((resolve) => {
    let ws = null;
    const timeout = setTimeout(() => {
      if (ws) ws.terminate();
      resolve();
    }, 4000);

    try {
      ws = new WebSocket(wsUrl, {
        rejectUnauthorized: false,
        handshakeTimeout: 3000,
      });
    } catch {
      clearTimeout(timeout);
      return resolve();
    }

    ws.on('open', () => {
      clearTimeout(timeout);
      vulnerabilities.push(mkFinding('websocket', {
        type: 'websocket',
        severity: 'info',
        confidence: CONFIDENCE.CONFIRMED,
        title: 'WebSocket Endpoint Exposed',
        description: `WebSocket connection succeeded at ${wsUrl}. Presence of a WebSocket endpoint is not itself a vulnerability, but its handlers must be reviewed for injection risks.`,
        endpoint: wsUrl,
        parameter: 'N/A',
        payload: 'WebSocket handshake',
        evidence: `URL: ${wsUrl}\nProtocol: ${wsUrl.startsWith('wss') ? 'wss' : 'ws'}\nStatus: Connection established`,
        remediation: 'Authenticate WebSocket connections, validate all messages server-side, and rate-limit WS endpoints.',
        owasp_category: 'A05:2021 – Security Misconfiguration',
        cve_id: 'CWE-200',
      }));

      sendWSPayloads(ws, wsUrl, vulnerabilities).finally(() => {
        try { ws.close(); } catch {}
        resolve();
      });
    });

    ws.on('error', () => {
      clearTimeout(timeout);
      resolve();
    });

    ws.on('timeout', () => {
      clearTimeout(timeout);
      try { ws.terminate(); } catch {}
      resolve();
    });
  });
}

async function sendWSPayloads(ws, wsUrl, vulnerabilities) {
  for (const attack of WS_ATTACK_PAYLOADS) {
    try {
      const echoed = await wsEcho(ws, attack.payload, 2000);
      if (echoed && echoed.includes(attack.payload)) {
        vulnerabilities.push(mkFinding('websocket', {
          type: 'websocket',
          severity: 'low',
          confidence: CONFIDENCE.ADVISORY,
          title: 'WebSocket Echoes Client Messages (Review Server-Side Handling)',
          description: 'The WebSocket endpoint mirrored a test message back to the client. Echoing input is common behavior (chat, echo services) and is NOT proof of injection. The server-side handlers should be reviewed for how mirrored data is interpreted.',
          endpoint: wsUrl,
          parameter: 'WebSocket message',
          payload: attack.payload,
          evidence: `Test type: ${attack.type}\nSent: ${attack.payload.substring(0, 80)}\nEchoed: ${echoed.substring(0, 120)}\nNote: echo != vulnerability; manual review required`,
          remediation: 'Validate and sanitize all WebSocket messages server-side; treat client data as untrusted.',
          owasp_category: 'A03:2021 – Injection',
          cve_id: '',
        }));
        break;
      }
    } catch {}
  }
}

function wsEcho(ws, message, timeoutMs) {
  return new Promise((resolve) => {
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
      resolve(null);
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
  try {
    const resp = await httpClient.get(targetUrl, { timeout: 3000 });
    const body = typeof resp.data === 'string' ? resp.data : '';
    if (body.includes('socket.io') || body.includes('io.connect')) return 'Socket.IO detected in page source';
  } catch {}
  return null;
}

module.exports = { scanWebSocket, WS_ATTACK_PAYLOADS };