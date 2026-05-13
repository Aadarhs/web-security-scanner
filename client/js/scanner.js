let socket = null;
let currentScanId = null;
let foundVulnerabilities = [];

document.addEventListener('DOMContentLoaded', () => {
  initSocket();
  initScannerForm();
  initModuleToggles();
  initClearLogs();
});

function initSocket() {
  try {
    socket = io(window.location.origin, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: Infinity,
    });

    socket.on('connect', () => {
      console.log('[Socket] Connected:', socket.id);
    });

    socket.on('scan:started', (data) => {
      showNotification(`Scan started for ${data.targetUrl}`, 'info');
    });

    socket.on('scan:progress', (data) => {
      updateProgress(data.progress);
    });

    socket.on('scan:log', (data) => {
      addLogEntry(data.message, data.level, data.module);
    });

    socket.on('scan:complete', (data) => {
      onScanComplete(data);
    });

    socket.on('disconnect', () => {
      console.log('[Socket] Disconnected');
    });

    socket.on('connect_error', (err) => {
      console.log('[Socket] Connection error:', err.message);
      addLogEntry('WebSocket disconnected - polling mode active', 'warning', 'System');
    });
  } catch (err) {
    console.log('[Socket] Init error:', err.message);
  }
}

function initScannerForm() {
  const btn = document.getElementById('startScanBtn');
  const input = document.getElementById('targetUrl');

  btn.addEventListener('click', startScan);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') startScan();
  });
}

function initModuleToggles() {
  document.querySelectorAll('.option-tag').forEach(tag => {
    tag.addEventListener('click', () => {
      tag.classList.toggle('active');
    });
  });
}

function initClearLogs() {
  document.getElementById('clearLogs')?.addEventListener('click', () => {
    document.getElementById('scanLog').innerHTML = '<div class="terminal-line info">[System] Log cleared</div>';
  });
}

async function startScan() {
  const url = document.getElementById('targetUrl').value.trim();
  if (!url) {
    showNotification('Please enter a target URL', 'error');
    return;
  }

  const activeModules = [];
  document.querySelectorAll('.option-tag.active').forEach(tag => {
    activeModules.push(tag.dataset.module);
  });
  if (activeModules.length === 0) {
    showNotification('Please select at least one scan module', 'error');
    return;
  }

  document.getElementById('startScanBtn').disabled = true;
  document.getElementById('startScanBtn').innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';

  document.getElementById('scanProgress').style.display = 'block';
  document.getElementById('scanResults').style.display = 'none';
  document.getElementById('progressFill').style.width = '0%';
  document.getElementById('progressText').textContent = '0%';
  document.getElementById('scanTargetDisplay').textContent = url;
  document.getElementById('currentModule').textContent = 'Initializing...';
  document.getElementById('foundCount').textContent = '0';
  document.getElementById('scanStatusBadge').innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running';
  document.getElementById('scanStatusBadge').className = 'badge badge-info';

  const log = document.getElementById('scanLog');
  log.innerHTML = '';
  addLogEntry('Initializing scanner engine...', 'info', 'System');
  addLogEntry(`Target: ${url}`, 'info', 'System');
  addLogEntry(`Modules: ${activeModules.join(', ')}`, 'info', 'System');
  addLogEntry('Establishing connection...', 'info', 'System');

  foundVulnerabilities = [];
  currentScanId = null;

  try {
    if (socket && socket.connected) {
      const room = `scan_${Date.now()}`;
      socket.emit('join:scan', room);
    }
  } catch (e) {}

  try {
    const res = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url,
        socketId: socket?.id || null,
        modules: activeModules,
      }),
      signal: AbortSignal.timeout(15000),
    });

    const data = await res.json();

    if (data.error) {
      addLogEntry(`Error: ${data.error}`, 'error', 'System');
      showNotification(data.error, 'error');
      resetScanButton();
      return;
    }

    currentScanId = data.scanId;
    addLogEntry(`Scan initialized: ${data.scanId?.substring(0, 8)}...`, 'success', 'System');
    addLogEntry('Assessment in progress...', 'info', 'System');
  } catch (err) {
    addLogEntry(`Failed to start scan: ${err.message}`, 'error', 'System');
    showNotification(`Failed to start scan: ${err.message}`, 'error');
    resetScanButton();
  }
}

function updateProgress(progress) {
  const fill = document.getElementById('progressFill');
  const text = document.getElementById('progressText');
  if (fill) fill.style.width = `${progress}%`;
  if (text) text.textContent = `${progress}%`;
}

function addLogEntry(message, level = 'info', module = 'System') {
  const log = document.getElementById('scanLog');
  if (!log) return;

  const line = document.createElement('div');
  line.className = `terminal-line ${level}`;
  const time = new Date().toLocaleTimeString();
  line.textContent = `[${time}] [${module}] ${message}`;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

function onScanComplete(data) {
  resetScanButton();

  document.getElementById('scanStatusBadge').innerHTML = '<i class="fas fa-check-circle"></i> Completed';
  document.getElementById('scanStatusBadge').className = 'badge completed';
  document.getElementById('progressFill').style.width = '100%';
  document.getElementById('progressText').textContent = '100%';

  document.getElementById('scanStatusBadge').className = 'badge';
  document.getElementById('scanStatusBadge').style.background = 'rgba(0, 204, 102, 0.15)';
  document.getElementById('scanStatusBadge').style.color = '#00cc66';

  addLogEntry(`Scan complete! Found ${data.vulnerabilities?.length || 0} vulnerability(s)`, 'success', 'System');
  addLogEntry('Generating report...', 'info', 'System');

  foundVulnerabilities = data.vulnerabilities || [];

  document.getElementById('resultCritical').textContent = data.counts?.critical || 0;
  document.getElementById('resultHigh').textContent = data.counts?.high || 0;
  document.getElementById('resultMedium').textContent = data.counts?.medium || 0;
  document.getElementById('resultLow').textContent = data.counts?.low || 0;
  document.getElementById('resultInfo').textContent = data.counts?.info || 0;

  renderVulnerabilities(foundVulnerabilities);

  document.getElementById('scanResults').style.display = 'block';

  document.getElementById('scanProgress').scrollIntoView({ behavior: 'smooth', block: 'start' });

  showNotification(`Scan complete: ${data.vulnerabilities?.length || 0} vulnerabilities found`, data.vulnerabilities?.length > 0 ? 'error' : 'success');

  if (socket && currentScanId) {
    socket.emit('leave:scan', currentScanId);
  }
}

function resetScanButton() {
  const btn = document.getElementById('startScanBtn');
  btn.disabled = false;
  btn.innerHTML = '<i class="fas fa-bolt"></i> Start Scan';
}
