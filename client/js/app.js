const API_BASE = '/api';
let severityChart = null;
let timelineChart = null;
let typeChart = null;

document.addEventListener('DOMContentLoaded', () => {
  initParticles();
  initNavigation();
  initThemeToggle();
  initNotification();
  initHistory();
  initReports();
  initDashboard();
  initSearch();
  initDownloadButtons();
  initDocsSearch();
  initAIAnalysis();
  initAdmin();
  checkAdminAccess();
});

function initParticles() {
  const canvas = document.getElementById('particle-canvas');
  if (!canvas || !canvas.getContext) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  let particles = [];
  let mouseX = -1000;
  let mouseY = -1000;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  for (let i = 0; i < 80; i++) {
    particles.push({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.5,
      vy: (Math.random() - 0.5) * 0.5,
      size: Math.random() * 2 + 0.5,
      alpha: Math.random() * 0.5 + 0.2,
    });
  }

  document.addEventListener('mousemove', (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
  });

  function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
    ctx.fillStyle = isDark ? 'rgba(0, 240, 255, 0.6)' : 'rgba(0, 102, 255, 0.4)';

    for (const p of particles) {
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0) p.x = canvas.width;
      if (p.x > canvas.width) p.x = 0;
      if (p.y < 0) p.y = canvas.height;
      if (p.y > canvas.height) p.y = 0;

      ctx.globalAlpha = p.alpha * (isDark ? 0.6 : 0.4);
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size + (p === particles[0] ? 1 : 0), 0, Math.PI * 2);
      ctx.fill();

      const dx = mouseX - p.x;
      const dy = mouseY - p.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < 150) {
        ctx.globalAlpha = 0.1 * (isDark ? 1 : 0.7);
        ctx.beginPath();
        ctx.moveTo(p.x, p.y);
        ctx.lineTo(mouseX, mouseY);
        ctx.stroke();
      }
    }

    ctx.globalAlpha = 0.08;
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          ctx.globalAlpha = 0.08 * (1 - dist / 120) * (isDark ? 1 : 0.6);
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }

    requestAnimationFrame(animate);
  }
  animate();
}

function initNavigation() {
  const links = document.querySelectorAll('.nav-link');
  const sections = document.querySelectorAll('.section');

  function showSection(id) {
    sections.forEach(s => s.classList.remove('active'));
    links.forEach(l => l.classList.remove('active'));

    const target = document.getElementById(id);
    if (target) {
      target.classList.add('active');
      document.querySelector(`.nav-link[href="#${id}"]`)?.classList.add('active');
      window.location.hash = id;
    }

    if (id === 'dashboard') initDashboard();
    if (id === 'history') initHistory();
    if (id === 'reports') initReports();
  }

  links.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const id = link.getAttribute('href').substring(1);
      showSection(id);
    });
  });

  const hash = window.location.hash.substring(1) || 'dashboard';
  showSection(hash);

  window.addEventListener('hashchange', () => {
    const id = window.location.hash.substring(1) || 'dashboard';
    showSection(id);
  });
}

function filterCveList(query) {
  const needle = (query || '').toLowerCase().trim();
  document.querySelectorAll('#cveListBody tr').forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(needle) ? '' : 'none';
  });
}

function initThemeToggle() {
  const toggle = document.getElementById('themeToggle');
  const saved = localStorage.getItem('theme');
  if (saved === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
    toggle.innerHTML = '<i class="fas fa-sun"></i>';
  }

  toggle.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    if (current === 'light') {
      document.documentElement.removeAttribute('data-theme');
      localStorage.setItem('theme', 'dark');
      toggle.innerHTML = '<i class="fas fa-moon"></i>';
    } else {
      document.documentElement.setAttribute('data-theme', 'light');
      localStorage.setItem('theme', 'light');
      toggle.innerHTML = '<i class="fas fa-sun"></i>';
    }
    setTimeout(initDashboard, 100);
  });
}

function showNotification(message, type = 'info') {
  const el = document.getElementById('scanNotification');
  el.textContent = message;
  el.className = `notification ${type} show`;
  clearTimeout(el._timeout);
  el._timeout = setTimeout(() => el.classList.remove('show'), 4000);
}

function initNotification() {
  const el = document.getElementById('scanNotification');
  el.addEventListener('click', () => el.classList.remove('show'));
}

async function initDashboard() {
  try {
    const res = await fetch(`${API_BASE}/dashboard/stats`);
    const data = await res.json();

    document.querySelector('#statTotalScans .stat-value').textContent = data.totalScans || 0;
    document.querySelector('#statTotalVulns .stat-value').textContent = data.totalVulnerabilities || 0;
    document.querySelector('#statRiskScore .stat-value').textContent = (data.averageRiskScore || 0) + '%';
    document.getElementById('todayScans').textContent = data.todayScans || 0;
    document.getElementById('lastScanTarget').textContent = data.latestScan?.target_url?.replace(/https?:\/\//, '').substring(0, 25) || '---';
    document.getElementById('lastScanStatus').textContent = data.latestScan?.status || 'No scans yet';
    document.getElementById('lastScanStatus').className = `stat-trend ${data.latestScan?.status === 'completed' ? 'up' : ''}`;

    const critical = data.severityDistribution?.find(s => s.severity === 'critical')?.count || 0;
    document.getElementById('criticalCount').textContent = critical;

    buildSeverityChart(data.severityDistribution || []);
    buildTimelineChart(data.scansByDay || []);
    buildTypeChart(data.severityDistribution || []);
  } catch (err) {
    console.log('[Dashboard]', err.message);
  }
}

function buildSeverityChart(distribution) {
  const ctx = document.getElementById('severityChart')?.getContext('2d');
  if (!ctx) return;
  if (severityChart) severityChart.destroy();

  const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
  const labels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const colors = ['#ff0044', '#ff6600', '#ffcc00', '#4488ff', '#888888'];
  const data = labels.map(l => distribution.find(d => d.severity === l.toLowerCase())?.count || 0);

  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors.map(c => c + 'cc'),
        borderColor: colors,
        borderWidth: 2,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: { color: isDark ? '#8892b0' : '#4a4a6a', padding: 12, font: { size: 11 } }
        }
      }
    }
  });
}

function buildTimelineChart(scansByDay) {
  const ctx = document.getElementById('timelineChart')?.getContext('2d');
  if (!ctx) return;
  if (timelineChart) timelineChart.destroy();

  const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
  const labels = scansByDay.map(s => s.date?.substring(5) || '');
  const data = scansByDay.map(s => s.count || 0);

  timelineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels.length ? labels : ['No Data'],
      datasets: [{
        label: 'Scans',
        data: data.length ? data : [0],
        borderColor: '#00f0ff',
        backgroundColor: 'rgba(0, 240, 255, 0.1)',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointBackgroundColor: '#00f0ff',
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: { ticks: { color: isDark ? '#555577' : '#9999aa', maxTicksLimit: 7 } },
        y: { ticks: { color: isDark ? '#555577' : '#9999aa', stepSize: 1 } },
      }
    }
  });
}

function buildTypeChart(distribution) {
  const ctx = document.getElementById('typeChart')?.getContext('2d');
  if (!ctx) return;
  if (typeChart) typeChart.destroy();

  const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
  const colorMap = { critical: '#ff0044', high: '#ff6600', medium: '#ffcc00', low: '#4488ff', info: '#888888' };
  const labels = distribution.map(d => d.severity.charAt(0).toUpperCase() + d.severity.slice(1));
  const data = distribution.map(d => d.count || 0);
  const colors = distribution.map(d => colorMap[d.severity] || '#888');

  typeChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels.length ? labels : ['No Data'],
      datasets: [{
        label: 'Vulnerabilities',
        data: data.length ? data : [0],
        backgroundColor: colors.map(c => c + '88'),
        borderColor: colors,
        borderWidth: 2,
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: isDark ? '#555577' : '#9999aa' } },
        y: { ticks: { color: isDark ? '#555577' : '#9999aa', stepSize: 1 } },
      }
    }
  });
}

async function initHistory(page = 1) {
  const tbody = document.getElementById('historyBody');
  if (!tbody) return;

  try {
    const statusFilter = document.getElementById('historyStatusFilter')?.value || 'all';
    const searchQuery = document.getElementById('historySearch')?.value || '';
    const res = await fetch(`${API_BASE}/scan/history?page=${page}&limit=15`);
    const data = await res.json();

    tbody.innerHTML = '';

    if (!data.scans || data.scans.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state"><i class="fas fa-radar"></i> No scans performed yet</td></tr>';
      return;
    }

    let filtered = data.scans;
    if (statusFilter !== 'all') {
      filtered = filtered.filter(s => s.status === statusFilter);
    }
    if (searchQuery) {
      filtered = filtered.filter(s => s.target_url.toLowerCase().includes(searchQuery.toLowerCase()));
    }

    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state">No matching scans</div></td></tr>';
      return;
    }

    for (const scan of filtered) {
      const tr = document.createElement('tr');
      const date = new Date(scan.created_at).toLocaleString();
      tr.innerHTML = `
        <td title="${scan.target_url}">${scan.target_url?.substring(0, 40)}${scan.target_url?.length > 40 ? '...' : ''}</td>
        <td><span class="status-badge ${scan.status}"><i class="fas fa-${scan.status === 'completed' ? 'check-circle' : scan.status === 'running' ? 'spinner fa-spin' : 'times-circle'}"></i> ${scan.status}</span></td>
        <td>${scan.total_vulnerabilities || 0}</td>
        <td style="color: ${scan.risk_score > 50 ? '#ff0044' : scan.risk_score > 25 ? '#ff6600' : '#00cc66'}">${scan.risk_score || 0}</td>
        <td>${date}</td>
        <td>
          <button class="btn btn-sm view-scan" data-id="${scan.id}"><i class="fas fa-eye"></i></button>
          <button class="btn btn-sm generate-report" data-id="${scan.id}"><i class="fas fa-file-export"></i></button>
        </td>
      `;
      tbody.appendChild(tr);
    }

    document.querySelectorAll('.view-scan').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        try {
          const res = await fetch(`${API_BASE}/results/${id}`);
          const data = await res.json();
          if (data.scan) {
            document.querySelector('[href="#scanner"]').click();
            showScanResults(data);
          }
        } catch (err) {
          showNotification('Failed to load scan results', 'error');
        }
      });
    });

    document.querySelectorAll('.generate-report').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        try {
          const res = await fetch(`${API_BASE}/reports/generate/${id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ format: 'json' })
          });
          const data = await res.json();
          if (data.reportId) {
            showNotification('Report generated successfully', 'success');
            initReports();
          }
        } catch (err) {
          showNotification('Failed to generate report', 'error');
        }
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-file-export"></i>';
      });
    });

    const pagination = document.getElementById('historyPagination');
    if (pagination) {
      const totalPages = data.pages || 1;
      pagination.innerHTML = '';
      if (totalPages > 1) {
        const prev = document.createElement('button');
        prev.innerHTML = '<i class="fas fa-chevron-left"></i>';
        prev.disabled = page <= 1;
        prev.addEventListener('click', () => initHistory(page - 1));
        pagination.appendChild(prev);

        for (let i = 1; i <= Math.min(totalPages, 5); i++) {
          const btn = document.createElement('button');
          btn.textContent = i;
          btn.className = i === page ? 'active' : '';
          btn.addEventListener('click', () => initHistory(i));
          pagination.appendChild(btn);
        }

        const next = document.createElement('button');
        next.innerHTML = '<i class="fas fa-chevron-right"></i>';
        next.disabled = page >= totalPages;
        next.addEventListener('click', () => initHistory(page + 1));
        pagination.appendChild(next);
      }
    }

  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state">Failed to load history</div></td></tr>';
  }
}

async function initReports() {
  const tbody = document.getElementById('reportsBody');
  if (!tbody) return;

  try {
    const res = await fetch(`${API_BASE}/reports/`);
    const reports = await res.json();

    tbody.innerHTML = '';
    if (!reports || reports.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5"><div class="empty-state"><i class="fas fa-file"></i> No reports generated</div></td></tr>';
      return;
    }

    for (const report of reports) {
      const tr = document.createElement('tr');
      const date = new Date(report.created_at).toLocaleString();
      tr.innerHTML = `
        <td>${report.id?.substring(0, 8)}...</td>
        <td title="${report.target_url}">${report.target_url?.substring(0, 35)}...</td>
        <td><span class="badge badge-info">${report.format?.toUpperCase()}</span></td>
        <td>${date}</td>
        <td>
          <button class="btn btn-sm download-report" data-id="${report.id}"><i class="fas fa-download"></i> Download</button>
        </td>
      `;
      tbody.appendChild(tr);
    }

    document.querySelectorAll('.download-report').forEach(btn => {
      btn.addEventListener('click', () => {
        window.open(`${API_BASE}/reports/${btn.dataset.id}/download`, '_blank');
      });
    });
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="5"><div class="empty-state">Failed to load reports</div></td></tr>';
  }
}

function initSearch() {
  const searchInput = document.getElementById('historySearch');
  if (searchInput) {
    searchInput.addEventListener('input', debounce(() => initHistory(), 300));
  }
  const statusFilter = document.getElementById('historyStatusFilter');
  if (statusFilter) {
    statusFilter.addEventListener('change', () => initHistory());
  }
}

function initDownloadButtons() {
  document.getElementById('downloadJsonBtn')?.addEventListener('click', downloadJSON);
  document.getElementById('downloadPdfBtn')?.addEventListener('click', downloadPDF);
  document.getElementById('viewIgnoredBtn')?.addEventListener('click', () => {
    const ignoredSection = document.getElementById('ignoredSection');
    if (ignoredSection) {
      ignoredSection.style.display = ignoredSection.style.display === 'none' ? '' : 'none';
    }
    loadIgnoredVulnerabilities();
  });
}

function initDocsSearch() {
  const search = document.querySelector('#docs .cyber-input-sm');
  if (!search) return;
  search.addEventListener('input', debounce((e) => {
    const q = e.target.value.toLowerCase();
    document.querySelectorAll('#docs .card').forEach(card => {
      const text = card.textContent.toLowerCase();
      card.style.display = text.includes(q) ? '' : 'none';
    });
  }, 300));
}

function showScanResults(data) {
  const { scan, vulnerabilities } = data;
  const container = document.getElementById('scanResults');
  const progress = document.getElementById('scanProgress');
  if (!container) return;

  container.style.display = 'block';
  progress.style.display = 'none';

  document.getElementById('resultCritical').textContent = vulnerabilities.filter(v => v.severity === 'critical').length;
  document.getElementById('resultHigh').textContent = vulnerabilities.filter(v => v.severity === 'high').length;
  document.getElementById('resultMedium').textContent = vulnerabilities.filter(v => v.severity === 'medium').length;
  document.getElementById('resultLow').textContent = vulnerabilities.filter(v => v.severity === 'low').length;
  document.getElementById('resultInfo').textContent = vulnerabilities.filter(v => v.severity === 'info').length;

  renderVulnerabilities(vulnerabilities);
}

function renderVulnerabilities(vulnerabilities, containerId = 'vulnerabilitiesList') {
  const list = document.getElementById(containerId);
  if (!list) return;

  if (!vulnerabilities || vulnerabilities.length === 0) {
    list.innerHTML = '<div class="empty-state"><i class="fas fa-shield-check" style="color:var(--success);font-size:3rem;margin-bottom:1rem"></i><p>No vulnerabilities detected. The target appears secure.</p></div>';
    return;
  }

  list.innerHTML = '';
  vulnerabilities.forEach((v, idx) => {
    const div = document.createElement('div');
    div.className = `vuln-card severity-${v.severity}${v.ignored ? ' ignored' : ''}`;
    const isFromHistoryView = containerId !== 'vulnerabilitiesList';
    div.innerHTML = `
      <div class="vuln-card-header">
        <span class="vuln-title">${v.ignored ? '<i class="fas fa-eye-slash" style="margin-right:6px;color:var(--text-muted)"></i>' : ''}${v.title}</span>
        <span class="vuln-badge ${v.severity}">${v.severity}</span>
      </div>
      <div class="vuln-meta">
        <span><i class="fas fa-tag"></i> ${v.type}</span>
        <span><i class="fas fa-link"></i> ${v.endpoint || 'N/A'}</span>
        ${v.owasp_category ? `<span><i class="fas fa-book"></i> ${v.owasp_category}</span>` : ''}
        ${v.cve_id ? `<span><i class="fas fa-bug"></i> ${v.cve_id}</span>` : ''}
      </div>
      <div class="vuln-details">
        <p><strong>Description:</strong> ${v.description || 'No description'}</p>
        <p><strong>Payload:</strong> <code>${v.payload || 'N/A'}</code></p>
        ${v.evidence ? `<p><strong>Evidence:</strong><br/><pre>${v.evidence}</pre></p>` : ''}
        <p class="remediation"><i class="fas fa-check-circle"></i> <strong>Remediation:</strong> ${v.remediation || 'No remediation provided'}</p>
        ${v.ignored && v.ignored_reason ? `<p class="ignored-note"><i class="fas fa-ban"></i> <strong>Ignored:</strong> ${v.ignored_reason}</p>` : ''}
        ${v.target_url ? `<p><i class="fas fa-link"></i> <strong>Target:</strong> ${v.target_url}</p>` : ''}
      </div>
      <div class="vuln-actions">
        ${v.ignored
          ? `<button class="btn btn-sm unignore-btn" data-scanid="${v.scan_id}" data-vulnid="${v.id}" title="Restore vulnerability"><i class="fas fa-undo"></i> Restore</button>`
          : `<button class="btn btn-sm ignore-btn" data-scanid="${v.scan_id || (window.currentScanId || '')}" data-vulnid="${v.id}" title="Mark as false positive / ignore"><i class="fas fa-ban"></i> Ignore</button>`
        }
      </div>
    `;
    div.addEventListener('click', (e) => {
      if (e.target.closest('.vuln-actions') || e.target.closest('.ignore-btn') || e.target.closest('.unignore-btn')) return;
      div.classList.toggle('expanded');
    });
    list.appendChild(div);
  });

  // Bind ignore buttons
  document.querySelectorAll(`#${containerId} .ignore-btn`).forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const scanId = btn.dataset.scanid;
      const vulnId = btn.dataset.vulnid;
      const reason = prompt('Reason for ignoring (optional):', 'False positive');
      await ignoreVulnerability(scanId, vulnId, reason || 'False positive');
    });
  });

  // Bind unignore buttons
  document.querySelectorAll(`#${containerId} .unignore-btn`).forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const scanId = btn.dataset.scanid;
      const vulnId = btn.dataset.vulnid;
      await unignoreVulnerability(scanId, vulnId);
    });
  });

  // Only bind search/filter for the primary results list
  if (containerId === 'vulnerabilitiesList') {
    const searchInput = document.getElementById('vulnSearch');
    const severityFilter = document.getElementById('severityFilter');
    if (searchInput) {
      const newInput = searchInput.cloneNode(true);
      searchInput.parentNode.replaceChild(newInput, searchInput);
      newInput.addEventListener('input', debounce(() => filterVulnerabilities(), 200));
    }
    if (severityFilter) {
      const newFilter = severityFilter.cloneNode(true);
      severityFilter.parentNode.replaceChild(newFilter, severityFilter);
      newFilter.addEventListener('change', filterVulnerabilities);
    }
  }
}

async function ignoreVulnerability(scanId, vulnId, reason) {
  if (!scanId || !vulnId) {
    showNotification('Cannot ignore: missing scan or vulnerability ID', 'error');
    return;
  }
  try {
    const headers = { 'Content-Type': 'application/json' };
    const token = localStorage.getItem('authToken');
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const res = await fetch(`${API_BASE}/results/${scanId}/vulnerabilities/${vulnId}/ignore`, {
      method: 'PUT',
      headers,
      body: JSON.stringify({ reason }),
    });
    const data = await res.json();
    if (data.success) {
      showNotification('Vulnerability marked as ignored', 'success');
      // Refresh the current results
      if (window.currentScanId) {
        try {
          const resultsRes = await fetch(`${API_BASE}/results/${window.currentScanId}`);
          const resultsData = await resultsRes.json();
          if (resultsData.vulnerabilities) {
            renderVulnerabilities(resultsData.vulnerabilities);
          }
        } catch {}
      }
    } else {
      showNotification(data.error || 'Failed to ignore vulnerability', 'error');
    }
  } catch (err) {
    showNotification('Failed to ignore vulnerability: ' + err.message, 'error');
  }
}

async function unignoreVulnerability(scanId, vulnId) {
  if (!scanId || !vulnId) return;
  try {
    const headers = { 'Content-Type': 'application/json' };
    const token = localStorage.getItem('authToken');
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const res = await fetch(`${API_BASE}/results/${scanId}/vulnerabilities/${vulnId}/unignore`, {
      method: 'PUT',
      headers,
    });
    const data = await res.json();
    if (data.success) {
      showNotification('Vulnerability restored', 'success');
      if (window.currentScanId) {
        try {
          const resultsRes = await fetch(`${API_BASE}/results/${window.currentScanId}`);
          const resultsData = await resultsRes.json();
          if (resultsData.vulnerabilities) {
            renderVulnerabilities(resultsData.vulnerabilities);
          }
        } catch {}
      }
    } else {
      showNotification(data.error || 'Failed to restore vulnerability', 'error');
    }
  } catch (err) {
    showNotification('Failed to restore vulnerability: ' + err.message, 'error');
  }
}

async function loadIgnoredVulnerabilities() {
  const container = document.getElementById('ignoredResults');
  if (!container) return;

  /* create ignored results section if it doesn't exist */
  const scannerSection = document.getElementById('scanner');
  let ignoredSection = document.getElementById('ignoredSection');
  if (!ignoredSection) {
    ignoredSection = document.createElement('div');
    ignoredSection.id = 'ignoredSection';
    ignoredSection.className = 'card glass';
    ignoredSection.style.marginTop = '1rem';
    ignoredSection.innerHTML = `
      <div class="card-header">
        <h3><i class="fas fa-eye-slash"></i> Ignored Vulnerabilities</h3>
        <button class="btn btn-sm" id="refreshIgnoredBtn" title="Refresh"><i class="fas fa-sync"></i></button>
      </div>
      <div class="card-body">
        <div class="filter-bar">
          <input type="text" id="ignoredSearch" placeholder="Filter ignored..." class="cyber-input-sm" />
        </div>
        <div id="ignoredResults"></div>
      </div>
    `;
    scannerSection.appendChild(ignoredSection);

    document.getElementById('refreshIgnoredBtn')?.addEventListener('click', loadIgnoredVulnerabilities);
  }

  try {
    const res = await fetch(`${API_BASE}/results/ignored?limit=100`);
    const data = await res.json();

    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
      container.innerHTML = '<div class="empty-state"><i class="fas fa-check-circle" style="color:var(--success);font-size:2rem"></i><p>No ignored vulnerabilities</p></div>';
      return;
    }

    renderVulnerabilities(data.vulnerabilities, 'ignoredResults');
  } catch (err) {
    container.innerHTML = '<div class="empty-state">Failed to load ignored vulnerabilities</div>';
  }
}

function filterVulnerabilities() {
  const query = document.getElementById('vulnSearch')?.value.toLowerCase() || '';
  const severity = document.getElementById('severityFilter')?.value || 'all';
  document.querySelectorAll('.vuln-card').forEach(card => {
    const text = card.textContent.toLowerCase();
    const sev = card.className.includes('severity-info') ? 'info' :
                card.className.includes('severity-critical') ? 'critical' :
                card.className.includes('severity-high') ? 'high' :
                card.className.includes('severity-medium') ? 'medium' :
                card.className.includes('severity-low') ? 'low' : '';
    const matchesSearch = !query || text.includes(query);
    const matchesSeverity = severity === 'all' || sev === severity;
    card.style.display = matchesSearch && matchesSeverity ? '' : 'none';
  });
}

async function downloadJSON() {
  const list = document.getElementById('vulnerabilitiesList');
  if (!list || !list.children.length) return;
  const results = [];
  document.querySelectorAll('.vuln-card').forEach(card => {
    results.push({
      title: card.querySelector('.vuln-title')?.textContent || '',
      severity: card.querySelector('.vuln-badge')?.textContent || '',
      type: card.querySelector('.vuln-meta span:first-child')?.textContent?.replace(/^[^a-zA-Z]+/, '') || '',
    });
  });
  const blob = new Blob([JSON.stringify({ vulnerabilities: results, generatedAt: new Date().toISOString() }, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `scan-results-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showNotification('JSON report downloaded', 'success');
}

async function downloadPDF() {
  const id = window.currentScanId;
  if (!id) {
    showNotification('No scan results available. Please run a scan first.', 'error');
    return;
  }
  try {
    showNotification('Generating PDF report...', 'info');
    const res = await fetch(`${API_BASE}/reports/generate/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ format: 'pdf' })
    });
    const data = await res.json();
    if (data.reportId) {
      showNotification('PDF report generated! Opening download...', 'success');
      window.open(`${API_BASE}/reports/${data.reportId}/download`, '_blank');
      initReports();
    } else {
      showNotification(data.error || 'Failed to generate PDF', 'error');
    }
  } catch (err) {
    showNotification('Failed to generate PDF: ' + err.message, 'error');
  }
}

function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

async function fetchWithTimeout(url, options = {}, timeout = 10000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return res;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

function initAIAnalysis() {
  const btn = document.getElementById('aiAnalysisBtn');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    const id = window.currentScanId;
    if (!id) {
      showNotification('No scan results to analyze', 'error');
      return;
    }
    const token = localStorage.getItem('authToken');
    if (!token) {
      showNotification('Please login to use AI analysis', 'error');
      return;
    }
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
    const panel = document.getElementById('aiAnalysisPanel');
    const content = document.getElementById('aiAnalysisContent');
    if (panel) panel.style.display = 'block';
    if (content) content.innerHTML = '<p>Generating AI-powered vulnerability analysis...</p>';

    try {
      const res = await fetch(`${API_BASE}/ai/analyze/${id}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
      });
      const data = await res.json();
      if (data.analysis) {
        renderAIAnalysis(data.analysis);
      } else {
        if (content) content.innerHTML = `<p class="error">${data.error || 'Analysis failed'}</p>`;
      }
    } catch (err) {
      if (content) content.innerHTML = `<p class="error">AI analysis error: ${err.message}</p>`;
    }
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-brain"></i> AI Analysis';
  });
}

function renderAIAnalysis(analysis) {
  const content = document.getElementById('aiAnalysisContent');
  if (!content) return;

  let html = `<div class="ai-risk-badge" style="padding:0.5rem;margin-bottom:0.5rem;border-radius:4px;background:rgba(0,240,255,0.1);border-left:3px solid var(--accent);">
    <p style="margin:0;"><strong>Risk Summary:</strong> ${analysis.riskSummary || 'No risk summary available'}</p>
  </div>`;

  if (analysis.prioritizedActions && analysis.prioritizedActions.length > 0) {
    html += '<h5 style="margin-top:0.5rem;">Prioritized Actions</h5>';
    for (const action of analysis.prioritizedActions) {
      const color = action.severity === 'critical' ? '#ff0044' : action.severity === 'high' ? '#ff6600' : action.severity === 'medium' ? '#ffcc00' : '#4488ff';
      html += `<div style="padding:0.5rem;margin-bottom:0.3rem;border-left:3px solid ${color};background:var(--card-bg);border-radius:4px;">
        <strong style="color:${color}">[${action.severity.toUpperCase()}]</strong> ${action.title}
        <p style="margin:0.2rem 0 0 0;font-size:0.85rem;">${action.action || ''}</p>
        ${action.businessImpact ? `<p style="margin:0.2rem 0 0 0;font-size:0.8rem;color:var(--text-muted);"><em>Impact: ${action.businessImpact}</em></p>` : ''}
      </div>`;
    }
  }

  if (analysis.chainingPossibilities && analysis.chainingPossibilities.length > 0) {
    html += '<h5 style="margin-top:0.5rem;">Attack Chaining Possibilities</h5><ul>';
    for (const chain of analysis.chainingPossibilities) {
      html += `<li style="font-size:0.85rem;">${chain}</li>`;
    }
    html += '</ul>';
  }

  content.innerHTML = html;
}

function checkAdminAccess() {
  const token = localStorage.getItem('authToken');
  if (!token) return;
  fetch(`${API_BASE}/auth/me`, {
    headers: { 'Authorization': `Bearer ${token}` },
  }).then(res => res.json()).then(user => {
    if (user.role === 'admin') {
      document.getElementById('adminNavLink').style.display = '';
    }
  }).catch(() => {});
}

function initAdmin() {
  initAdminModules();
  initAdminEditor();
  initAdminTester();
}

async function initAdminModules() {
  const list = document.getElementById('moduleList');
  if (!list) return;

  const token = localStorage.getItem('authToken');
  if (!token) return;

  try {
    const res = await fetch(`${API_BASE}/admin/modules`, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    const data = await res.json();
    if (!data.modules) return;

    list.innerHTML = '<table class="cyber-table"><thead><tr><th>Module</th><th>Size</th><th>Modified</th></tr></thead><tbody>';
    for (const mod of data.modules) {
      list.innerHTML += `<tr>
        <td>${mod.name}</td>
        <td>${(mod.size / 1024).toFixed(1)} KB</td>
        <td>${new Date(mod.modified).toLocaleDateString()}</td>
      </tr>`;
    }
    list.innerHTML += '</tbody></table>';
  } catch {}
}

async function initAdminEditor() {
  const select = document.getElementById('moduleEditorSelect');
  const saveBtn = document.getElementById('moduleEditorSave');
  const refreshBtn = document.getElementById('moduleEditorRefresh');
  const content = document.getElementById('moduleEditorContent');
  if (!select || !saveBtn) return;

  const token = localStorage.getItem('authToken');
  if (!token) return;

  try {
    const res = await fetch(`${API_BASE}/admin/modules`, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    const data = await res.json();
    if (data.modules) {
      select.innerHTML = data.modules.map(m => `<option value="${m.name}">${m.name}</option>`).join('');
    }
  } catch {}

  select.addEventListener('change', async () => {
    if (!select.value) return;
    try {
      const res = await fetch(`${API_BASE}/admin/modules/${select.value}`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await res.json();
      if (content) content.value = data.content || '';
    } catch {}
  });

  if (select.value) select.dispatchEvent(new Event('change'));

  saveBtn.addEventListener('click', async () => {
    if (!select.value || !content) return;
    try {
      const res = await fetch(`${API_BASE}/admin/modules/${select.value}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ content: content.value }),
      });
      const data = await res.json();
      showNotification(data.message || 'Module saved', data.success ? 'success' : 'error');
    } catch (err) {
      showNotification('Failed to save module: ' + err.message, 'error');
    }
  });

  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      if (select.value) select.dispatchEvent(new Event('change'));
    });
  }
}

async function initAdminTester() {
  const btn = document.getElementById('testPayloadBtn');
  const endpoint = document.getElementById('testEndpoint');
  const payload = document.getElementById('testPayload');
  const results = document.getElementById('testResults');
  if (!btn) return;

  btn.addEventListener('click', async () => {
    if (!endpoint.value) {
      showNotification('Please enter an endpoint URL', 'error');
      return;
    }
    results.innerHTML = '<p>Testing...</p>';
    try {
      const token = localStorage.getItem('authToken');
      const res = await fetch(`${API_BASE}/admin/modules/test/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({
          endpoint: endpoint.value,
          payload: payload.value || 'test',
        }),
      });
      const data = await res.json();
      results.innerHTML = `<div style="font-size:0.85rem;">
        <p><strong>Status:</strong> ${data.status || 'Error'}</p>
        <p><strong>Response Size:</strong> ${data.bodyLength || 0} bytes</p>
        ${data.error ? `<p><strong>Error:</strong> ${data.error}</p>` : ''}
      </div>`;
    } catch (err) {
      results.innerHTML = `<p class="error">${err.message}</p>`;
    }
  });
}

async function loadAdminStats() {
  const token = localStorage.getItem('authToken');
  if (!token) return;

  try {
    const res = await fetch(`${API_BASE}/admin/stats`, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    const data = await res.json();
    document.getElementById('adminTotalScans').textContent = data.totalScans || 0;
    document.getElementById('adminTotalVulns').textContent = data.totalVulns || 0;
    document.getElementById('adminTotalUsers').textContent = data.totalUsers || 0;
    document.getElementById('adminTotalReports').textContent = data.totalReports || 0;
  } catch {}
}

initOSINT();
initCompliance();
initDiff();
initNotifications();

function initOSINT() {
  const techBtn = document.getElementById('techDetectBtn');
  const dnsBtn = document.getElementById('dnsSecurityBtn');
  const breachEmailBtn = document.getElementById('breachEmailBtn');
  const breachPasswordBtn = document.getElementById('breachPasswordBtn');

  if (techBtn) {
    techBtn.addEventListener('click', async () => {
      const url = document.getElementById('techUrl')?.value;
      if (!url) { showNotification('Please enter a URL', 'error'); return; }
      const container = document.getElementById('techResults');
      container.innerHTML = '<p><i class="fas fa-spinner fa-spin"></i> Detecting technologies...</p>';
      try {
        const res = await fetch(`${API_BASE}/tech-detect/detect`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url }),
        });
        const data = await res.json();
        if (data.error) { container.innerHTML = `<p class="error">${data.error}</p>`; return; }
        let html = `<div class="results-summary" style="margin-bottom:0.5rem;">`;
        html += `<span class="summary-item info">Technologies: ${data.technologies.length}</span>`;
        if (data.serverHeader) html += `<span class="summary-item info">Server: ${data.serverHeader}</span>`;
        html += `</div>`;
        if (data.technologies.length === 0) {
          html += `<div class="empty-state"><p>No technologies detected</p></div>`;
        } else {
          const cats = {};
          for (const t of data.technologies) {
            if (!cats[t.category]) cats[t.category] = [];
            cats[t.category].push(t.name);
          }
          html += '<div style="font-size:0.85rem;">';
          for (const [cat, techs] of Object.entries(cats)) {
            html += `<div style="margin-bottom:0.5rem;"><strong style="color:var(--accent)">${cat}:</strong> `;
            html += techs.map(t => `<span class="badge badge-info">${t}</span>`).join(' ');
            html += '</div>';
          }
          html += '</div>';
        }
        if (data.headers) {
          const secHeaders = ['strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','referrer-policy'];
          const present = secHeaders.filter(h => data.headers[h]);
          if (present.length > 0) {
            html += '<div style="margin-top:0.5rem;font-size:0.8rem;">';
            html += '<strong>Security Headers Present:</strong> ';
            html += present.map(h => `<span class="badge badge-success">${h}</span>`).join(' ');
            html += '</div>';
          }
        }
        container.innerHTML = html;
      } catch (err) {
        container.innerHTML = `<p class="error">${err.message}</p>`;
      }
    });
  }

  if (dnsBtn) {
    dnsBtn.addEventListener('click', async () => {
      const domain = document.getElementById('dnsDomain')?.value;
      if (!domain) { showNotification('Please enter a domain', 'error'); return; }
      const container = document.getElementById('dnsSecurityResults');
      container.innerHTML = '<p><i class="fas fa-spinner fa-spin"></i> Analyzing DNS security...</p>';
      try {
        const res = await fetch(`${API_BASE}/dns-security/analyze?domain=${encodeURIComponent(domain)}`);
        const data = await res.json();
        if (data.error) { container.innerHTML = `<p class="error">${data.error}</p>`; return; }
        let html = `<div class="results-summary" style="margin-bottom:0.5rem;">
          <span class="summary-item ${data.securityScore >= 80 ? 'info' : data.securityScore >= 50 ? 'medium' : 'high'}">Security Score: ${data.securityScore}/100</span>
        </div>`;
        html += '<div style="font-size:0.85rem;">';
        html += `<div style="margin-bottom:0.3rem;"><strong>SPF:</strong> ${data.spf ? `<span class="badge badge-success">Configured</span>` : `<span class="badge badge-error">Missing</span>`}</div>`;
        html += `<div style="margin-bottom:0.3rem;"><strong>DKIM:</strong> ${data.dkim ? `<span class="badge badge-success">Configured${data.dkimSelector ? ` (${data.dkimSelector})` : ''}</span>` : `<span class="badge badge-error">Missing</span>`}</div>`;
        html += `<div style="margin-bottom:0.3rem;"><strong>DMARC:</strong> ${data.dmarc ? `<span class="badge badge-success">Configured</span>` : `<span class="badge badge-error">Missing</span>`}</div>`;
        html += `<div style="margin-bottom:0.3rem;"><strong>DNSSEC:</strong> ${data.dnssec ? `<span class="badge badge-success">Enabled</span>` : `<span class="badge badge-error">Not Enabled</span>`}</div>`;
        if (data.mx && data.mx.length > 0) {
          html += `<div style="margin-bottom:0.3rem;"><strong>MX Records:</strong> ${data.mx.map(m => `${m.exchange} (priority ${m.priority})`).join(', ')}</div>`;
        }
        if (data.issues && data.issues.length > 0) {
          html += '<div style="margin-top:0.5rem;"><strong style="color:#ff6600">Issues:</strong><ul>';
          for (const issue of data.issues) html += `<li>${issue}</li>`;
          html += '</ul></div>';
        }
        if (data.recommendations && data.recommendations.length > 0) {
          html += '<div style="margin-top:0.3rem;"><strong style="color:#00cc66">Recommendations:</strong><ul>';
          for (const rec of data.recommendations) html += `<li>${rec}</li>`;
          html += '</ul></div>';
        }
        html += '</div>';
        container.innerHTML = html;
      } catch (err) {
        container.innerHTML = `<p class="error">${err.message}</p>`;
      }
    });
  }

  if (breachEmailBtn) {
    breachEmailBtn.addEventListener('click', async () => {
      const email = document.getElementById('breachEmail')?.value;
      if (!email) { showNotification('Please enter an email', 'error'); return; }
      const container = document.getElementById('breachResults');
      container.innerHTML = '<p><i class="fas fa-spinner fa-spin"></i> Checking email against breach databases...</p>';
      try {
        const res = await fetch(`${API_BASE}/breach-check/check-email`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email }),
        });
        const data = await res.json();
        if (data.error) { container.innerHTML = `<p class="error">${data.error}</p>`; return; }
        let html = `<div class="results-summary" style="margin-bottom:0.5rem;">
          <span class="summary-item ${data.pwned ? 'critical' : 'info'}">${data.pwned ? `⚠ Pwned! Found in ${data.pwnedCount} breaches` : '✅ Not found in any known breaches'}</span>
        </div>`;
        if (data.breaches && data.breaches.length > 0) {
          html += '<div style="font-size:0.85rem;"><strong>Breach Details:</strong></div>';
          for (const b of data.breaches) {
            html += `<div style="padding:0.3rem;margin-bottom:0.2rem;border-left:3px solid #ff4444;background:var(--card-bg);font-size:0.8rem;">
              <strong>${b.name}</strong> (${b.date || 'Unknown'})<br/>
              Domain: ${b.domain || 'N/A'}<br/>
              ${b.dataClasses ? `Data: ${b.dataClasses.join(', ')}` : ''}
            </div>`;
          }
        }
        html += `<div style="margin-top:0.3rem;font-size:0.8rem;color:var(--text-muted);">Password reuse count: ${data.pwnedCount}</div>`;
        container.innerHTML = html;
      } catch (err) {
        container.innerHTML = `<p class="error">${err.message}</p>`;
      }
    });
  }

  if (breachPasswordBtn) {
    breachPasswordBtn.addEventListener('click', async () => {
      const password = document.getElementById('breachPassword')?.value;
      if (!password) { showNotification('Please enter a password', 'error'); return; }
      const container = document.getElementById('breachResults');
      container.innerHTML = '<p><i class="fas fa-spinner fa-spin"></i> Checking password...</p>';
      try {
        const res = await fetch(`${API_BASE}/breach-check/check-password`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password }),
        });
        const data = await res.json();
        if (data.error) { container.innerHTML = `<p class="error">${data.error}</p>`; return; }
        const strengthColor = data.strength === 'strong' ? '#00cc66' : data.strength === 'moderate' ? '#ffcc00' : '#ff4444';
        let html = `<div class="results-summary" style="margin-bottom:0.5rem;">
          <span class="summary-item ${data.pwned ? 'critical' : 'info'}">${data.pwned ? `⚠ Password found in ${data.pwnedCount} breaches!` : '✅ Password not found in breaches'}</span>
          <span class="summary-item" style="border-color:${strengthColor}">Strength: ${data.strength.toUpperCase()}</span>
        </div>`;
        html += '<div style="font-size:0.85rem;">';
        html += `<div>Length: ${data.passwordLength} chars</div>`;
        html += `<div>Uppercase: ${data.hasUpper ? '✅' : '❌'}</div>`;
        html += `<div>Lowercase: ${data.hasLower ? '✅' : '❌'}</div>`;
        html += `<div>Numbers: ${data.hasNumber ? '✅' : '❌'}</div>`;
        html += `<div>Special: ${data.hasSpecial ? '✅' : '❌'}</div>`;
        html += '</div>';
        container.innerHTML = html;
      } catch (err) {
        container.innerHTML = `<p class="error">${err.message}</p>`;
      }
    });
  }
}

function initCompliance() {
  const analyzeBtn = document.getElementById('complianceAnalyzeBtn');
  const refreshBtn = document.getElementById('complianceRefreshBtn');
  const scanSelect = document.getElementById('complianceScanSelect');

  async function loadScans() {
    try {
      const res = await fetch(`${API_BASE}/scan/history?limit=50`);
      const data = await res.json();
      if (data.scans) {
        scanSelect.innerHTML = '<option value="">-- Select a scan --</option>';
        for (const s of data.scans) {
          scanSelect.innerHTML += `<option value="${s.id}">${s.target_url?.substring(0, 40)} (${new Date(s.created_at).toLocaleDateString()})</option>`;
        }
      }
    } catch {}
  }

  if (refreshBtn) refreshBtn.addEventListener('click', loadScans);
  loadScans();

  if (analyzeBtn) {
    analyzeBtn.addEventListener('click', async () => {
      const scanId = scanSelect?.value;
      const framework = document.getElementById('complianceFramework')?.value;
      if (!scanId) { showNotification('Please select a scan', 'error'); return; }
      const container = document.getElementById('complianceResults');
      container.innerHTML = '<p><i class="fas fa-spinner fa-spin"></i> Analyzing compliance...</p>';
      try {
        const res = await fetch(`${API_BASE}/compliance/analyze/${scanId}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ framework: framework || undefined }),
        });
        const data = await res.json();
        if (data.error) { container.innerHTML = `<p class="error">${data.error}</p>`; return; }

        let html = '';
        if (data.frameworks) {
          html = '<div style="font-size:0.85rem;">';
          for (const [fw, report] of Object.entries(data.frameworks)) {
            if (report.error) continue;
            const color = report.nonCompliant > 0 ? '#ff6600' : '#00cc66';
            html += `<div class="card glass" style="margin-bottom:0.5rem;padding:0.5rem;border-left:3px solid ${color};">`;
            html += `<strong>${fw}</strong> — ${report.summary || ''}<br/>`;
            html += `<span class="stat-trend ${report.nonCompliant > 0 ? 'danger' : 'up'}">Non-compliant: ${report.nonCompliant}</span>`;
            html += ` | Accepted Risk: ${report.acceptedRisk}`;
            html += ` | ${report.totalFindings} total findings`;
            html += '</div>';
          }
          html += '</div>';
        } else if (data.mappings) {
          const color = data.nonCompliant > 0 ? '#ff6600' : '#00cc66';
          html = `<div style="font-size:0.85rem;">
            <div style="padding:0.5rem;margin-bottom:0.5rem;border-left:3px solid ${color};background:var(--card-bg);border-radius:4px;">
              <strong>${data.framework}</strong><br/>
              ${data.summary || ''}<br/>
              Non-compliant: ${data.nonCompliant} | Accepted Risk: ${data.acceptedRisk} | Review Required: ${data.reviewRequired}
            </div>`;
          if (data.mappings && data.mappings.length > 0) {
            html += '<table class="cyber-table" style="font-size:0.8rem;"><thead><tr><th>Finding</th><th>Severity</th><th>Control</th><th>Status</th></tr></thead><tbody>';
            for (const m of data.mappings) {
              for (const c of m.compliance) {
                html += `<tr>
                  <td>${m.vuln.title?.substring(0, 30)}</td>
                  <td><span class="badge ${m.vuln.severity}">${m.vuln.severity}</span></td>
                  <td>${c.control}</td>
                  <td><span class="badge ${c.status === 'non_compliant' ? 'badge-error' : 'badge-info'}">${c.status}</span></td>
                </tr>`;
              }
            }
            html += '</tbody></table>';
          }
          html += '</div>';
        } else {
          html = `<p>${data.message || 'No data'}</p>`;
        }
        container.innerHTML = html;
      } catch (err) {
        container.innerHTML = `<p class="error">${err.message}</p>`;
      }
    });
  }
}

function initDiff() {
  const scan1 = document.getElementById('diffScan1');
  const scan2 = document.getElementById('diffScan2');
  const compareBtn = document.getElementById('diffCompareBtn');

  async function loadScans() {
    try {
      const res = await fetch(`${API_BASE}/scan/history?limit=100`);
      const data = await res.json();
      if (data.scans) {
        const opts = data.scans.map(s => `<option value="${s.id}">${s.target_url?.substring(0, 35)} (${new Date(s.created_at).toLocaleDateString()})</option>`).join('');
        if (scan1) scan1.innerHTML = '<option value="">-- Select scan --</option>' + opts;
        if (scan2) scan2.innerHTML = '<option value="">-- Select scan --</option>' + opts;
      }
    } catch {}
  }
  loadScans();

  if (scan1) {
    scan1.addEventListener('change', async () => {
      if (scan1.value) {
        try {
          const res = await fetch(`${API_BASE}/results/${scan1.value}/summary`);
          const data = await res.json();
          if (data.scan) {
            document.getElementById('diffScan1Info').innerHTML = `
              Risk: ${data.scan.risk_score}/100 | Vulns: ${data.scan.total_vulnerabilities} | ${new Date(data.scan.created_at).toLocaleDateString()}
            `;
          }
        } catch {}
      }
    });
  }

  if (scan2) {
    scan2.addEventListener('change', async () => {
      if (scan2.value) {
        try {
          const res = await fetch(`${API_BASE}/results/${scan2.value}/summary`);
          const data = await res.json();
          if (data.scan) {
            document.getElementById('diffScan2Info').innerHTML = `
              Risk: ${data.scan.risk_score}/100 | Vulns: ${data.scan.total_vulnerabilities} | ${new Date(data.scan.created_at).toLocaleDateString()}
            `;
          }
        } catch {}
      }
    });
  }

  if (compareBtn) {
    compareBtn.addEventListener('click', async () => {
      if (!scan1?.value || !scan2?.value) {
        showNotification('Please select two scans to compare', 'error');
        return;
      }
      if (scan1.value === scan2.value) {
        showNotification('Please select two different scans', 'error');
        return;
      }
      const container = document.getElementById('diffResults');
      container.innerHTML = '<p><i class="fas fa-spinner fa-spin"></i> Comparing scans...</p>';
      try {
        const res = await fetch(`${API_BASE}/diff/compare?scanId1=${scan1.value}&scanId2=${scan2.value}`);
        const data = await res.json();
        if (data.error) { container.innerHTML = `<p class="error">${data.error}</p>`; return; }

        const riskColor = data.diff.riskChange > 0 ? '#ff4444' : data.diff.riskChange < 0 ? '#00cc66' : '#888';
        let html = `<div class="results-summary" style="margin-bottom:0.5rem;">
          <span class="summary-item ${data.diff.newCount > 0 ? 'high' : 'info'}">New: ${data.diff.newCount}</span>
          <span class="summary-item ${data.diff.fixedCount > 0 ? 'info' : ''}">Fixed: ${data.diff.fixedCount}</span>
          <span class="summary-item">Unchanged: ${data.diff.unchangedCount}</span>
          <span class="summary-item" style="border-color:${riskColor};color:${riskColor}">Risk Change: ${data.diff.riskChange > 0 ? '+' : ''}${data.diff.riskChange}</span>
        </div>`;

        html += '<div style="font-size:0.85rem;">';
        html += `<div style="margin-bottom:0.3rem;"><strong>Scan 1:</strong> ${data.scan1.targetUrl} — Risk: ${data.scan1.riskScore} (${new Date(data.scan1.date).toLocaleDateString()})</div>`;
        html += `<div style="margin-bottom:0.5rem;"><strong>Scan 2:</strong> ${data.scan2.targetUrl} — Risk: ${data.scan2.riskScore} (${new Date(data.scan2.date).toLocaleDateString()})</div>`;

        if (data.diff.newFindings.length > 0) {
          html += '<h4 style="color:#ff4444;margin-top:0.5rem;">New Findings</h4>';
          for (const v of data.diff.newFindings) {
            html += `<div style="padding:0.3rem;margin-bottom:0.2rem;border-left:3px solid #ff4444;background:var(--card-bg);">
              <strong>[${v.severity.toUpperCase()}]</strong> ${v.title}<br/>
              <span style="color:var(--text-muted);font-size:0.8rem;">${v.type} — ${v.endpoint || ''}</span>
            </div>`;
          }
        }

        if (data.diff.fixedFindings.length > 0) {
          html += '<h4 style="color:#00cc66;margin-top:0.5rem;">Fixed Findings</h4>';
          for (const v of data.diff.fixedFindings) {
            html += `<div style="padding:0.3rem;margin-bottom:0.2rem;border-left:3px solid #00cc66;background:var(--card-bg);">
              <strong>[${v.severity.toUpperCase()}]</strong> ${v.title}<br/>
              <span style="color:var(--text-muted);font-size:0.8rem;">${v.type} — ${v.endpoint || ''}</span>
            </div>`;
          }
        }

        if (data.diff.newCount === 0 && data.diff.fixedCount === 0) {
          html += '<p>No significant changes between these two scans.</p>';
        }

        html += '</div>';
        container.innerHTML = html;
      } catch (err) {
        container.innerHTML = `<p class="error">${err.message}</p>`;
      }
    });
  }
}

function initNotifications() {
  const addBtn = document.getElementById('notifAddBtn');
  const configsContainer = document.getElementById('notifConfigs');

  async function loadConfigs() {
    const token = localStorage.getItem('authToken');
    if (!token) { if (configsContainer) configsContainer.innerHTML = '<p style="color:var(--text-muted);font-size:0.85rem;">Login required</p>'; return; }
    try {
      const res = await fetch(`${API_BASE}/notifications/configs`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await res.json();
      if (!data.configs || data.configs.length === 0) {
        configsContainer.innerHTML = '<p style="color:var(--text-muted);font-size:0.85rem;">No webhooks configured</p>';
        return;
      }
      let html = '<table class="cyber-table" style="font-size:0.8rem;"><thead><tr><th>Type</th><th>Name</th><th>URL</th><th>Actions</th></tr></thead><tbody>';
      for (const c of data.configs) {
        html += `<tr>
          <td><span class="badge badge-info">${c.type}</span></td>
          <td>${c.name}</td>
          <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;">${c.webhook_url}</td>
          <td><button class="btn btn-sm notif-test-btn" data-id="${c.id}" data-type="${c.type}" data-url="${c.webhook_url}"><i class="fas fa-paper-plane"></i></button>
          <button class="btn btn-sm notif-del-btn" data-id="${c.id}"><i class="fas fa-trash"></i></button></td>
        </tr>`;
      }
      html += '</tbody></table>';
      configsContainer.innerHTML = html;

      configsContainer.querySelectorAll('.notif-test-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
          btn.disabled = true;
          btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
          try {
            const res = await fetch(`${API_BASE}/notifications/test`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
              body: JSON.stringify({ type: btn.dataset.type, webhookUrl: btn.dataset.url }),
            });
            const data = await res.json();
            showNotification(data.message || 'Test sent', data.success ? 'success' : 'error');
          } catch (err) {
            showNotification('Test failed: ' + err.message, 'error');
          }
          btn.disabled = false;
          btn.innerHTML = '<i class="fas fa-paper-plane"></i>';
        });
      });

      configsContainer.querySelectorAll('.notif-del-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
          try {
            await fetch(`${API_BASE}/notifications/configs/${btn.dataset.id}`, {
              method: 'DELETE',
              headers: { 'Authorization': `Bearer ${token}` },
            });
            loadConfigs();
            showNotification('Webhook deleted', 'success');
          } catch (err) {
            showNotification('Delete failed', 'error');
          }
        });
      });
    } catch {
      configsContainer.innerHTML = '<p style="color:var(--text-muted);font-size:0.85rem;">Failed to load webhooks</p>';
    }
  }

  if (addBtn) {
    addBtn.addEventListener('click', async () => {
      const token = localStorage.getItem('authToken');
      if (!token) { showNotification('Login required', 'error'); return; }
      const type = document.getElementById('notifType')?.value;
      const name = document.getElementById('notifName')?.value;
      const url = document.getElementById('notifWebhookUrl')?.value;
      if (!name || !url) { showNotification('Name and URL required', 'error'); return; }
      try {
        const res = await fetch(`${API_BASE}/notifications/configs`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
          body: JSON.stringify({ type, name, webhookUrl: url }),
        });
        const data = await res.json();
        if (data.success) {
          showNotification('Webhook added', 'success');
          document.getElementById('notifName').value = '';
          document.getElementById('notifWebhookUrl').value = '';
          loadConfigs();
        } else {
          showNotification(data.error || 'Failed', 'error');
        }
      } catch (err) {
        showNotification('Failed to add webhook', 'error');
      }
    });
  }

  loadConfigs();
}
