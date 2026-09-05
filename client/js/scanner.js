let socket = null;
let currentScanId = null;
let foundVulnerabilities = [];
let pollTimer = null;
let socketWarned = false;

document.addEventListener('DOMContentLoaded', () => {
  initSocket();
  initScannerForm();
  initModuleToggles();
  initClearLogs();
  initCancelScan();
});

function initCancelScan() {
  const cancelBtn = document.getElementById('cancelScanBtn');
  if (cancelBtn) {
    cancelBtn.addEventListener('click', async () => {
      if (!currentScanId) return;
      const token = localStorage.getItem('authToken');
      if (!token) {
        showNotification('Please login to cancel scans', 'error');
        return;
      }
      try {
        const res = await fetch(`${API_BASE}/scan/${currentScanId}/cancel`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` },
        });
        const data = await res.json();
        if (data.success) {
          addLogEntry('Scan cancelled by user', 'warning', 'System');
          showNotification('Scan cancelled', 'info');
        }
      } catch (err) {
        showNotification('Failed to cancel scan', 'error');
      }
    });
  }
}

function initSocket() {
  try {
    socket = io(window.location.origin, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 2000,
      reconnectionAttempts: 5,
      timeout: 5000,
    });

    socket.on('connect', () => {
      console.log('[Socket] Connected:', socket.id);
      socketWarned = false;
    });

    socket.on('scan:started', (data) => {
      showNotification(`Scan started for ${data.targetUrl}`, 'info');
    });

    socket.on('scan:progress', (data) => {
      updateProgress(data.progress);
      updateETA(data.eta);
    });

    socket.on('scan:log', (data) => {
      addLogEntry(data.message, data.level, data.module);
      const currentEl = document.getElementById('currentModule');
      if (currentEl && data.module && data.module !== 'engine' && data.module !== 'System') {
        currentEl.textContent = data.module;
      }
    });

    socket.on('scan:complete', (data) => {
      onScanComplete(data);
    });

    socket.on('disconnect', () => {
      console.log('[Socket] Disconnected');
      if (currentScanId && !pollTimer) {
        addLogEntry('Live feed lost - switching to polling status', 'warning', 'System');
        startPolling(currentScanId);
      }
    });

    socket.on('connect_error', (err) => {
      console.log('[Socket] Connection error:', err.message);
      if (!socketWarned) {
        socketWarned = true;
        addLogEntry('WebSocket unavailable - polling mode active', 'warning', 'System');
      }
      if (currentScanId && !pollTimer) {
        startPolling(currentScanId);
      }
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
  const etaEl = document.getElementById('etaDisplay');
  if (etaEl) etaEl.textContent = 'Calculating...';
  document.getElementById('scanTargetDisplay').textContent = url;
  document.getElementById('currentModule').textContent = 'Initializing...';
  document.getElementById('foundCount').textContent = '0';
  document.getElementById('scanStatusBadge').innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running';
  document.getElementById('scanStatusBadge').className = 'badge badge-info';
  const cancelBtn = document.getElementById('cancelScanBtn');
  if (cancelBtn) cancelBtn.style.display = 'inline-block';

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

    if (!(socket && socket.connected)) {
      addLogEntry('Live feed unavailable - polling scan status', 'warning', 'System');
      startPolling(data.scanId);
    }
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

function updateETA(eta) {
  const el = document.getElementById('etaDisplay');
  if (!el) return;
  if (eta === undefined || eta === null) { el.textContent = '--'; return; }
  if (eta <= 0) { el.textContent = 'Finalizing...'; return; }
  const m = Math.floor(eta / 60);
  const s = eta % 60;
  el.textContent = m > 0 ? `${m}m ${s}s` : `${s}s`;
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
  stopPolling();
  resetScanButton();

  const etaEl = document.getElementById('etaDisplay');
  if (etaEl) etaEl.textContent = 'Complete';
  const modEl = document.getElementById('currentModule');
  if (modEl) modEl.textContent = 'Done';
  document.getElementById('scanStatusBadge').innerHTML = '<i class="fas fa-check-circle"></i> Completed';
  document.getElementById('scanStatusBadge').className = 'badge completed';
  document.getElementById('progressFill').style.width = '100%';
  document.getElementById('progressText').textContent = '100%';
  const cancelBtn = document.getElementById('cancelScanBtn');
  if (cancelBtn) cancelBtn.style.display = 'none';

  document.getElementById('scanStatusBadge').className = 'badge';
  document.getElementById('scanStatusBadge').style.background = 'rgba(0, 204, 102, 0.15)';
  document.getElementById('scanStatusBadge').style.color = '#00cc66';

  addLogEntry(`Scan complete! Found ${data.vulnerabilities?.length || 0} vulnerability(s)`, 'success', 'System');
  addLogEntry('Generating report...', 'info', 'System');

  foundVulnerabilities = data.vulnerabilities || [];

  const foundEl = document.getElementById('foundCount');
  if (foundEl) foundEl.textContent = foundVulnerabilities.length;

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

let stepMode = true;
let lastProgressAt = Date.now();

function startPolling(scanId) {
  stopPolling();
  stepMode = true;
  lastProgressAt = Date.now();
  pollTimer = setInterval(async () => {
    try {
      if (stepMode) {
        const stepRes = await fetch(`${API_BASE}/scan/${scanId}/step`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ socketId: socket?.id || null }),
        });
        if (stepRes.status === 404) {
          stepMode = false;
          addLogEntry('Step endpoint unavailable - falling back to status polling', 'warning', 'System');
        } else {
          const d = await stepRes.json();
          if (d.error) return;
          if (typeof d.progress === 'number') updateProgress(d.progress);
          const modEl = document.getElementById('currentModule');
          if (modEl && d.currentModule && d.currentModule !== 'engine') {
            modEl.textContent = d.currentModule;
          }
          if (typeof d.foundCount === 'number') {
            const fc = document.getElementById('foundCount');
            if (fc) fc.textContent = d.foundCount;
          }
        }
      }

      const res = await fetch(`${API_BASE}/scan/${scanId}/status`);
      const d = await res.json();
      if (d.error) return;

      if (typeof d.progress === 'number') {
        updateProgress(d.progress);
        lastProgressAt = Date.now();
      }

      const logEl = document.getElementById('scanLog');
      const offset = logEl ? logEl.children.length : 0;
      (d.logs || []).slice(offset).forEach((l) => {
        addLogEntry(l.message, l.level, l.module || 'engine');
      });

      if (d.status === 'running' || d.status === 'queued' || d.status === 'pending') {
        if (Date.now() - lastProgressAt > 90000) {
          stopPolling();
          addLogEntry('Scan stalled - the server likely timed out. Retry with fewer modules or a faster target.', 'error', 'System');
          resetScanButton();
          showNotification('Scan stalled (server timeout). Try fewer modules.', 'error');
        }
        return;
      }

      stopPolling();
      if (d.status === 'completed') {
        onScanComplete({
          scanId,
          vulnerabilities: d.vulnerabilities || [],
          counts: d.counts || { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        });
      } else {
        resetScanButton();
        showNotification(`Scan ${d.status}`, 'info');
      }
    } catch (e) {
      // Transient network error - keep polling
    }
  }, 2000);
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}
