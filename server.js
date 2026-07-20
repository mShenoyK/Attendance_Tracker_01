'use strict';

const express = require('express');
const cors    = require('cors');
const crypto  = require('node:crypto');
const path    = require('node:path');
const fs      = require('node:fs');

// ── Config ────────────────────────────────────────────────────────────────────
const PORT   = process.env.PORT || 3456;
const USE_PG = !!process.env.DATABASE_URL;

// JWT_SECRET: env var required on Render for stable tokens across restarts
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  const f = path.join(__dirname, '.jwt_secret');
  if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8').trim();
  const s = crypto.randomBytes(32).toString('hex');
  try { fs.writeFileSync(f, s); } catch { /* read-only fs on cloud — set JWT_SECRET env var */ }
  if (!process.env.JWT_SECRET)
    console.warn('[WARN] JWT_SECRET env var not set — tokens will be invalidated on restart. Add it in Render → Environment.');
  return s;
})();

// ── JWT helpers ───────────────────────────────────────────────────────────────
function signToken(payload) {
  const h = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
  const b = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const s = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${b}`).digest('base64url');
  return `${h}.${b}.${s}`;
}

function verifyToken(token) {
  try {
    const [h, b, s] = (token || '').split('.');
    if (!h || !b || !s) return null;
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${b}`).digest('base64url');
    if (s !== expected) return null;
    const payload = JSON.parse(Buffer.from(b, 'base64url').toString());
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch { return null; }
}

function hashPin(pin) {
  return crypto.createHash('sha256').update(pin + JWT_SECRET).digest('hex');
}

// ── Database abstraction ──────────────────────────────────────────────────────
// db.get(sql, params)  → first row or null
// db.all(sql, params)  → array of rows
// db.run(sql, params)  → void
// All methods are async. SQL uses ? placeholders (auto-converted to $n for PG).
let db, _pool, _sq;

if (USE_PG) {
  const { Pool } = require('pg');
  _pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  const pgify = s => { let i = 0; return s.replace(/\?/g, () => `$${++i}`); };
  db = {
    get: async (s, p = []) => { const r = await _pool.query(pgify(s), p); return r.rows[0] ?? null; },
    all: async (s, p = []) => { const r = await _pool.query(pgify(s), p); return r.rows; },
    run: async (s, p = []) => { await _pool.query(pgify(s), p); },
  };
} else {
  const DB_DIR = process.env.DB_DIR || __dirname;
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
  const DB_PATH = path.join(DB_DIR, 'attendance.db');
  let _e;
  try { ({ DatabaseSync: _e } = require('node:sqlite')); }
  catch { _e = require('better-sqlite3'); }
  _sq = new _e(DB_PATH);
  _sq.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;');
  db = {
    get: (s, p = []) => Promise.resolve(_sq.prepare(s).get(...p)),
    all: (s, p = []) => Promise.resolve(_sq.prepare(s).all(...p)),
    run: (s, p = []) => Promise.resolve(_sq.prepare(s).run(...p)),
  };
}

// ── Seed data ─────────────────────────────────────────────────────────────────
const TEAM_MEMBERS = [
  'Aditi Magdum', 'Vaishnavi Limaye', 'Akanksha Jain', 'Bhakti Sheth',
  'Aman Raj',     'Shruti Mehta',     'Sayan Mondal',  'Akanksha Gupta',
];
const VIEWER_NAMES = ['Asutosh Kar', 'Kumaran Palani', 'Jisha Sasidharan'];

async function initDb() {
  if (USE_PG) {
    await _pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id         SERIAL PRIMARY KEY,
        email      TEXT UNIQUE,
        name       TEXT NOT NULL,
        role       TEXT NOT NULL DEFAULT 'member',
        pin_hash   TEXT,
        is_active  INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS attendance (
        id         SERIAL PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users(id),
        date       TEXT NOT NULL,
        status     TEXT NOT NULL CHECK(status IN ('WFO','WFH','Leave','DC Holiday')),
        updated_at TEXT,
        UNIQUE(user_id, date)
      );
      CREATE TABLE IF NOT EXISTS dc_holidays (
        id          SERIAL PRIMARY KEY,
        date        TEXT UNIQUE NOT NULL,
        description TEXT,
        created_by  INTEGER REFERENCES users(id),
        created_at  TIMESTAMPTZ DEFAULT NOW()
      );
    `);
  } else {
    _sq.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id         INTEGER PRIMARY KEY,
        email      TEXT UNIQUE,
        name       TEXT NOT NULL,
        role       TEXT NOT NULL DEFAULT 'member',
        pin_hash   TEXT,
        is_active  INTEGER NOT NULL DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS attendance (
        id         INTEGER PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users(id),
        date       TEXT NOT NULL,
        status     TEXT NOT NULL CHECK(status IN ('WFO','WFH','Leave','DC Holiday')),
        updated_at TEXT,
        UNIQUE(user_id, date)
      );
      CREATE TABLE IF NOT EXISTS dc_holidays (
        id          INTEGER PRIMARY KEY,
        date        TEXT UNIQUE NOT NULL,
        description TEXT,
        created_by  INTEGER REFERENCES users(id),
        created_at  TEXT DEFAULT CURRENT_TIMESTAMP
      );
    `);
  }

  // Seed admin
  await db.run(
    "INSERT INTO users (name, role) SELECT ?,? WHERE NOT EXISTS (SELECT 1 FROM users WHERE name = ?)",
    ['Mohith Shenoyk', 'admin', 'Mohith Shenoyk']
  );

  // Seed team members
  for (const name of TEAM_MEMBERS) {
    await db.run(
      'INSERT INTO users (name) SELECT ? WHERE NOT EXISTS (SELECT 1 FROM users WHERE name = ?)',
      [name, name]
    );
  }

  // Seed viewers
  for (const name of VIEWER_NAMES) {
    await db.run(
      "INSERT INTO users (name, role) SELECT ?,? WHERE NOT EXISTS (SELECT 1 FROM users WHERE name = ?)",
      [name, 'viewer', name]
    );
  }

  // Authentication is now name/PIN-based — clear any stored emails
  await db.run("UPDATE users SET email = NULL WHERE email IS NOT NULL");
}

// ── Express ───────────────────────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth middleware ───────────────────────────────────────────────────────────
function auth(req, res, next) {
  const payload = verifyToken((req.headers.authorization || '').replace('Bearer ', ''));
  if (!payload) return res.status(401).json({ error: 'Unauthorized' });
  req.user = payload;
  next();
}
function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── SSE (real-time broadcast) ─────────────────────────────────────────────────
const sseClients = new Set();
app.get('/api/events', (req, res) => {
  const token   = req.query.token || (req.headers.authorization || '').replace('Bearer ', '');
  const payload = verifyToken(token);
  if (!payload) return res.status(401).end();
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.status(200).write('data: {"type":"connected"}\n\n');
  const beat = setInterval(() => { try { res.write(':ping\n\n'); } catch { clearInterval(beat); sseClients.delete(res); } }, 25000);
  sseClients.add(res);
  req.on('close', () => { clearInterval(beat); sseClients.delete(res); });
});
function broadcast(type, data) {
  const msg = `data: ${JSON.stringify({ type, ...data })}\n\n`;
  for (const c of sseClients) try { c.write(msg); } catch {}
}

// ── Auth routes ───────────────────────────────────────────────────────────────

// Public: list all active users for the login selection screen
app.get('/api/auth/users', async (req, res) => {
  try {
    const rows = await db.all(`
      SELECT id, name, role, pin_hash IS NOT NULL as has_pin
      FROM users WHERE is_active = 1
      ORDER BY CASE role WHEN 'admin' THEN 0 WHEN 'member' THEN 1 ELSE 2 END, name
    `);
    res.json(rows.map(u => ({ id: u.id, name: u.name, role: u.role, has_pin: !!u.has_pin })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/set-pin', async (req, res) => {
  try {
    const { user_id, pin, confirm_pin } = req.body;
    if (!pin || pin.length !== 6 || !/^\d{6}$/.test(pin))
      return res.status(400).json({ error: 'PIN must be exactly 6 digits' });
    if (pin !== confirm_pin)
      return res.status(400).json({ error: 'PINs do not match' });
    const user = await db.get('SELECT id, name, role, pin_hash FROM users WHERE id = ? AND is_active = 1', [user_id]);
    if (!user)         return res.status(404).json({ error: 'User not found' });
    if (user.pin_hash) return res.status(400).json({ error: 'PIN already set. Use login instead.' });
    await db.run('UPDATE users SET pin_hash = ? WHERE id = ?', [hashPin(pin), user.id]);
    const token = signToken({ id: user.id, name: user.name, role: user.role });
    res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { user_id, pin } = req.body;
    if (!user_id) return res.status(400).json({ error: 'User ID required' });
    const user = await db.get('SELECT id, name, role, pin_hash, is_active FROM users WHERE id = ?', [user_id]);
    if (!user)           return res.status(401).json({ error: 'User not found.' });
    if (!user.is_active) return res.status(401).json({ error: 'Account deactivated. Contact admin.' });
    if (!user.pin_hash)  return res.status(401).json({ error: 'PIN not set yet. Please set your PIN first.' });
    if (user.pin_hash !== hashPin(pin)) return res.status(401).json({ error: 'Invalid PIN' });
    const token = signToken({ id: user.id, name: user.name, role: user.role });
    res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/change-pin', auth, async (req, res) => {
  try {
    const { old_pin, new_pin, confirm_pin } = req.body;
    const user = await db.get('SELECT pin_hash FROM users WHERE id = ?', [req.user.id]);
    if (user.pin_hash !== hashPin(old_pin)) return res.status(401).json({ error: 'Current PIN incorrect' });
    if (!new_pin || new_pin.length !== 6 || !/^\d{6}$/.test(new_pin))
      return res.status(400).json({ error: 'New PIN must be exactly 6 digits' });
    if (new_pin !== confirm_pin) return res.status(400).json({ error: 'PINs do not match' });
    await db.run('UPDATE users SET pin_hash = ? WHERE id = ?', [hashPin(new_pin), req.user.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Team ──────────────────────────────────────────────────────────────────────
app.get('/api/team', auth, async (req, res) => {
  try {
    const members = (req.user.role === 'admin' || req.user.role === 'viewer')
      ? await db.all("SELECT id, name, email, role, is_active FROM users WHERE role = 'member' ORDER BY name")
      : await db.all("SELECT id, name, email, role, is_active FROM users WHERE role = 'member' AND id = ?", [req.user.id]);
    res.json(members);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Attendance ────────────────────────────────────────────────────────────────
app.get('/api/attendance/:year/:month', auth, async (req, res) => {
  try {
    const prefix = `${req.params.year}-${req.params.month.padStart(2, '0')}-`;
    const rows = (req.user.role === 'admin' || req.user.role === 'viewer')
      ? await db.all(`
          SELECT a.id, a.user_id, u.name, a.date, a.status, a.updated_at
          FROM attendance a JOIN users u ON a.user_id = u.id
          WHERE a.date LIKE ? ORDER BY u.name, a.date`, [prefix + '%'])
      : await db.all(`
          SELECT a.id, a.user_id, u.name, a.date, a.status, a.updated_at
          FROM attendance a JOIN users u ON a.user_id = u.id
          WHERE a.user_id = ? AND a.date LIKE ? ORDER BY a.date`, [req.user.id, prefix + '%']);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/attendance', auth, async (req, res) => {
  try {
    if (req.user.role === 'viewer')
      return res.status(403).json({ error: 'View-only access: cannot modify attendance' });
    const { date, status, user_id } = req.body;
    if (!['WFO','WFH','Leave','DC Holiday'].includes(status))
      return res.status(400).json({ error: 'Invalid status' });
    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date))
      return res.status(400).json({ error: 'Invalid date' });
    if (req.user.role !== 'admin' && user_id && Number(user_id) !== req.user.id)
      return res.status(403).json({ error: "Cannot update another member's attendance" });
    const targetId = (req.user.role === 'admin' && user_id) ? Number(user_id) : req.user.id;
    const now = new Date().toISOString();
    await db.run(`
      INSERT INTO attendance (user_id, date, status, updated_at) VALUES (?,?,?,?)
      ON CONFLICT(user_id, date) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at`,
      [targetId, date, status, now]);
    const record = await db.get(`
      SELECT a.id, a.user_id, u.name, a.date, a.status, a.updated_at
      FROM attendance a JOIN users u ON a.user_id = u.id
      WHERE a.user_id=? AND a.date=?`, [targetId, date]);
    broadcast('attendance_update', { record });
    res.json(record);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/attendance/:userId/:date', auth, async (req, res) => {
  try {
    if (req.user.role === 'viewer')
      return res.status(403).json({ error: 'View-only access: cannot modify attendance' });
    const targetId = Number(req.params.userId);
    if (req.user.role !== 'admin' && targetId !== req.user.id)
      return res.status(403).json({ error: 'Forbidden' });
    await db.run('DELETE FROM attendance WHERE user_id=? AND date=?', [targetId, req.params.date]);
    broadcast('attendance_delete', { user_id: targetId, date: req.params.date });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── DC Holidays ───────────────────────────────────────────────────────────────
app.get('/api/holidays', auth, async (req, res) => {
  try { res.json(await db.all('SELECT * FROM dc_holidays ORDER BY date')); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/holidays', auth, adminOnly, async (req, res) => {
  try {
    const { date, description } = req.body;
    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date))
      return res.status(400).json({ error: 'Valid date required' });
    await db.run(
      'INSERT INTO dc_holidays (date, description, created_by) VALUES (?,?,?) ON CONFLICT (date) DO UPDATE SET description=excluded.description, created_by=excluded.created_by',
      [date, description || '', req.user.id]);
    const members = await db.all("SELECT id FROM users WHERE role='member' AND is_active=1");
    const now = new Date().toISOString();
    for (const m of members) {
      await db.run(`
        INSERT INTO attendance (user_id,date,status,updated_at) VALUES (?,?,'DC Holiday',?)
        ON CONFLICT(user_id,date) DO UPDATE SET status='DC Holiday', updated_at=excluded.updated_at`,
        [m.id, date, now]);
    }
    broadcast('holiday_added', { date, description });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/holidays/:date', auth, adminOnly, async (req, res) => {
  try {
    await db.run('DELETE FROM dc_holidays WHERE date=?', [req.params.date]);
    broadcast('holiday_removed', { date: req.params.date });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Reports ───────────────────────────────────────────────────────────────────
app.get('/api/reports/month/:year/:month', auth, adminOnly, async (req, res) => {
  try {
    const { year, month } = req.params;
    const prefix  = `${year}-${month.padStart(2, '0')}-`;
    const members = await db.all("SELECT id, name FROM users WHERE role='member' AND is_active=1 ORDER BY name");
    const rows    = await db.all("SELECT user_id, date, status FROM attendance WHERE date LIKE ? ORDER BY date", [prefix + '%']);
    const byMember = {};
    for (const m of members) byMember[m.id] = { name: m.name, entries: {}, effectiveWfo: 0 };
    for (const r of rows) {
      if (!byMember[r.user_id]) continue;
      byMember[r.user_id].entries[r.date] = r.status;
      if (['WFO','Leave','DC Holiday'].includes(r.status)) byMember[r.user_id].effectiveWfo++;
    }
    res.json({ year, month, members: byMember });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/reports/year/:year', auth, adminOnly, async (req, res) => {
  try {
    const { year }  = req.params;
    const members   = await db.all("SELECT id, name FROM users WHERE role='member' AND is_active=1 ORDER BY name");
    const result    = {};
    for (const m of members) {
      result[m.id] = { name: m.name, months: {} };
      for (let mo = 1; mo <= 12; mo++) {
        const prefix = `${year}-${String(mo).padStart(2, '0')}-`;
        const rows   = await db.all("SELECT status FROM attendance WHERE user_id=? AND date LIKE ?", [m.id, prefix + '%']);
        const eff    = rows.filter(r => ['WFO','Leave','DC Holiday'].includes(r.status)).length;
        result[m.id].months[mo] = { effectiveWfo: eff, met: eff >= 10 };
      }
    }
    res.json({ year, members: result });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/reports/individual/:userId/:year', auth, async (req, res) => {
  try {
    const uid = Number(req.params.userId);
    if (req.user.role !== 'admin' && uid !== req.user.id)
      return res.status(403).json({ error: 'Forbidden' });
    const user = await db.get('SELECT id, name FROM users WHERE id=?', [uid]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const rows = await db.all(
      "SELECT date, status FROM attendance WHERE user_id=? AND date LIKE ? ORDER BY date",
      [uid, `${req.params.year}-%`]);
    const months = {};
    for (let mo = 1; mo <= 12; mo++)
      months[mo] = { entries: {}, wfo: 0, wfh: 0, leave: 0, holiday: 0, effectiveWfo: 0, met: false };
    for (const r of rows) {
      const mo = parseInt(r.date.split('-')[1]);
      months[mo].entries[r.date] = r.status;
      if      (r.status === 'WFO')        months[mo].wfo++;
      else if (r.status === 'WFH')        months[mo].wfh++;
      else if (r.status === 'Leave')      months[mo].leave++;
      else if (r.status === 'DC Holiday') months[mo].holiday++;
      if (['WFO','Leave','DC Holiday'].includes(r.status)) months[mo].effectiveWfo++;
      months[mo].met = months[mo].effectiveWfo >= 10;
    }
    res.json({ user, year: req.params.year, months });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin: user management ────────────────────────────────────────────────────
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try { res.json(await db.all('SELECT id, email, name, role, is_active FROM users ORDER BY role DESC, name')); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const { name, email } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    if (email && !email.toLowerCase().endsWith('@infosys.com'))
      return res.status(400).json({ error: 'Must use @infosys.com email' });
    await db.run('INSERT INTO users (name, email) VALUES (?,?)', [name.trim(), email?.toLowerCase() || null]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    const { is_active } = req.body;
    if (is_active !== undefined)
      await db.run('UPDATE users SET is_active=? WHERE id=?', [is_active ? 1 : 0, req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/users/:id/reset-pin', auth, adminOnly, async (req, res) => {
  try {
    await db.run('UPDATE users SET pin_hash=NULL WHERE id=?', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Start ─────────────────────────────────────────────────────────────────────
initDb()
  .then(() => app.listen(PORT, () => {
    console.log(`\n  Attendance Tracker  →  http://localhost:${PORT}`);
    console.log(`  Admin               →  ${ADMIN_EMAIL}`);
    console.log(`  Database            →  ${USE_PG ? 'PostgreSQL (Render)' : 'SQLite (local)'}\n`);
  }))
  .catch(err => { console.error('\n  DB init failed:', err.message); process.exit(1); });
