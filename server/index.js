require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');

const db = require('./config/db');
const authRoutes = require('./routes/auth');
const scanRoutes = require('./routes/scan');
const resultsRoutes = require('./routes/results');
const reportsRoutes = require('./routes/reports');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
  },
  maxHttpBufferSize: 1e8,
});

app.set('io', io);

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, '..', 'client')));

app.use('/api/auth', authRoutes);
app.use('/api/scan', scanRoutes);
app.use('/api/results', resultsRoutes);
app.use('/api/reports', reportsRoutes);

const aiRoutes = require('./routes/ai');
const adminRoutes = require('./routes/admin');
const pentestRoutes = require('./routes/pentest');
app.use('/api/ai', aiRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/pentest', pentestRoutes);

app.get('/api/dashboard/stats', (req, res) => {
  const getVal = (query, params, key) => {
    try {
      const row = params ? db.prepare(query).get(params) : db.prepare(query).get();
      return row ? (row[key] !== undefined ? row[key] : 0) : 0;
    } catch { return 0; }
  };

  const totalScans = getVal('SELECT COUNT(*) as count FROM scans', null, 'count');
  const totalVulns = getVal('SELECT COALESCE(SUM(total_vulnerabilities), 0) as count FROM scans', null, 'count');
  const avgRisk = getVal("SELECT COALESCE(AVG(risk_score), 0) as avg FROM scans WHERE status = 'completed'", null, 'avg');
  const todayScans = getVal("SELECT COUNT(*) as count FROM scans WHERE date(created_at) = date('now')", null, 'count');

  const latestScan = db.prepare('SELECT target_url, created_at, status FROM scans ORDER BY created_at DESC LIMIT 1').get() || {};

  let severityDist = [];
  let scansByDay = [];
  try { severityDist = db.prepare('SELECT severity, COUNT(*) as count FROM vulnerabilities GROUP BY severity').all(); } catch {}
  try { scansByDay = db.prepare("SELECT date(created_at) as date, COUNT(*) as count FROM scans GROUP BY date(created_at) ORDER BY date DESC LIMIT 30").all() || []; } catch {}

  res.json({
    totalScans,
    totalVulnerabilities: totalVulns,
    averageRiskScore: Math.round(avgRisk * 10) / 10,
    latestScan,
    todayScans,
    severityDistribution: severityDist,
    scansByDay: (scansByDay || []).reverse(),
  });
});

app.get('/api/search', (req, res) => {
  const query = req.query.q;
  if (!query) return res.status(400).json({ error: 'Search query required' });

  const vulnerabilities = db.prepare(`
    SELECT v.*, s.target_url FROM vulnerabilities v
    JOIN scans s ON v.scan_id = s.id
    WHERE v.title LIKE ? OR v.description LIKE ? OR v.type LIKE ? OR v.severity LIKE ?
    ORDER BY v.created_at DESC LIMIT 50
  `).all(`%${query}%`, `%${query}%`, `%${query}%`, `%${query}%`);

  const scans = db.prepare(`
    SELECT * FROM scans WHERE target_url LIKE ? ORDER BY created_at DESC LIMIT 10
  `).all(`%${query}%`);

  res.json({ vulnerabilities, scans });
});

io.on('connection', (socket) => {
  console.log(`[Socket] Client connected: ${socket.id}`);

  socket.on('join:scan', (scanId) => {
    socket.join(scanId);
    console.log(`[Socket] ${socket.id} joined scan: ${scanId}`);
  });

  socket.on('leave:scan', (scanId) => {
    socket.leave(scanId);
  });

  socket.on('disconnect', () => {
    console.log(`[Socket] Client disconnected: ${socket.id}`);
  });
});

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  res.sendFile(path.join(__dirname, '..', 'client', 'index.html'));
});

const PORT = process.env.PORT || 3000;

async function start() {
  await db.init();

  const bcrypt = require('bcryptjs');
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(process.env.ADMIN_EMAIL);
  if (!existing) {
    const hashed = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
    db.prepare('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)').run(process.env.ADMIN_EMAIL, hashed, 'Admin', 'admin');
    console.log(`[Setup] Admin user created: ${process.env.ADMIN_EMAIL}`);
  }
  
  server.listen(PORT, () => {
    console.log(`\x1b[36m`);
    console.log(`  ╔═══════════════════════════════════════════╗`);
    console.log(`  ║     Web Security Scanner v2.0             ║`);
    console.log(`  ║     Running on: http://localhost:${String(PORT).padEnd(5)}║`);
    console.log(`  ║     OWASP Top 10 Scanner Engine            ║`);
    console.log(`  ╚═══════════════════════════════════════════╝`);
    console.log(`\x1b[0m`);
  });
}

start().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
