'use strict';

const express    = require('express');
const cors       = require('cors');
const crypto     = require('node:crypto');
const path       = require('node:path');
const fs         = require('node:fs');

// Use built-in node:sqlite on Node 22+ (local), fall back to better-sqlite3 on cloud
let _db_engine;
try {
  ({ DatabaseSync: _db_engine } = require('node:sqlite'));
} catch {
  _db_engine = require('better-sqlite3');
}

// ── Config ───────────────────────────────────────────────────────────────────
const PORT        = process.env.PORT || 3456;
// DB_DIR: /data on Render (persistent disk) or fallback to project dir locally
const DB_DIR      = process.env.DB_DIR || __dirname;
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true }); // create /data if disk not yet mounted
const DB_PATH     = path.join(DB_DIR, 'attendance.db');
const ADMIN_EMAIL = 'mohith_shenoyk01@infosys.com';

// JWT_SECRET: prefer env var (set in Render dashboard); fall back to file for local dev
const SECRET_FILE = path.join(DB_DIR, '.jwt_secret');
const JWT_SECRET  = process.env.JWT_SECRET
  || (fs.existsSync(SECRET_FILE)
    ? fs.readFileSync(SECRET_FILE, 'utf8').trim()
    : (() => { const s = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(SECRET_FILE, s); return s; })());

// ── JWT helpers ───────────────────────────────────────────────────────────────
function signToken(payload, hours = 8) {
  const exp  = Math.floor(Date.now() / 1000) + hours * 3600;
  const data = { ...payload, exp };
  const h    = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
  const b    = Buffer.from(JSON.stringify(data)).toString('base64url');
  const s    = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${b}`).digest('base64url');
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

// ── Database ──────────────────────────────────────────────────────────────────
const db = new _db_engine(DB_PATH);
db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT UNIQUE,
    name       TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'member',
    pin_hash   TEXT,
    is_active  INTEGER NOT NULL DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS attendance (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    date       TEXT NOT NULL,
    status     TEXT NOT NULL CHECK(status IN ('WFO','WFH','Leave','DC Holiday')),
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, date)
  );

  CREATE TABLE IF NOT EXISTS dc_holidays (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    date        TEXT UNIQUE NOT NULL,
    description TEXT,
    created_by  INTEGER REFERENCES users(id),
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

// Seed admin
if (!db.prepare('SELECT id FROM users WHERE email = ?').get(ADMIN_EMAIL)) {
  db.prepare("INSERT INTO users (email, name, role) VALUES (?, 'Mohith Shenoyk', 'admin')").run(ADMIN_EMAIL);
}

// Seed team members (name only; email linked on first login)
const TEAM_MEMBERS = [
  'Aditi Magdum', 'Vaishnavi Limaye', 'Akanksha Jain', 'Bhakti Sheth',
  'Aman Raj',     'Shruti Mehta',     'Sayan Mondal',  'Akanksha Gupta'
];
for (const name of TEAM_MEMBERS) {
  if (!db.prepare('SELECT id FROM users WHERE name = ?').get(name)) {
    db.prepare('INSERT INTO users (name) VALUES (?)').run(name);
  }
}

// Seed view-only accounts (email pre-set; they set a PIN on first login)
const VIEWERS = [
  { email: 'asutosh_kar@infosys.com',      name: 'Asutosh Kar'      },
  { email: 'kumaran_palani@infosys.com',   name: 'Kumaran Palani'   },
  { email: 'jisha_sasidharan@infosys.com', name: 'Jisha Sasidharan' },
];
for (const v of VIEWERS) {
  if (!db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(v.email)) {
    db.prepare("INSERT INTO users (email, name, role) VALUES (?, ?, 'viewer')").run(v.email, v.name);
  }
}

// ── Auth middleware ───────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token   = (req.headers.authorization || '').replace('Bearer ', '');
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Unauthorized' });
  req.user = payload;
  next();
}

function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── SSE (real-time broadcast) ─────────────────────────────────────────────────
const sseClients = new Set();

app.get('/api/events', (req, res) => {
  // EventSource cannot send headers; accept token via query param for SSE only
  const token   = req.query.token || (req.headers.authorization || '').replace('Bearer ', '');
  const payload = verifyToken(token);
  if (!payload) return res.status(401).end();
  req.user = payload;

  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',    'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.status(200);
  res.write('data: {"type":"connected"}\n\n');

  const beat = setInterval(() => { try { res.write(':ping\n\n'); } catch { clearInterval(beat); sseClients.delete(res); } }, 25000);
  sseClients.add(res);
  req.on('close', () => { clearInterval(beat); sseClients.delete(res); });
});

function broadcast(type, data) {
  const msg = `data: ${JSON.stringify({ type, ...data })}\n\n`;
  for (const c of sseClients) try { c.write(msg); } catch {}
}

// ── Auth routes ───────────────────────────────────────────────────────────────

// Step 1: Check email → tells client what flow to show
app.post('/api/auth/check-email', (req, res) => {
  const { email } = req.body;
  if (!email || !email.toLowerCase().endsWith('@infosys.com')) {
    return res.status(400).json({ error: 'Please use your Infosys email (@infosys.com)' });
  }
  const user = db.prepare('SELECT id, name, role, pin_hash FROM users WHERE email = ? COLLATE NOCASE').get(email);
  if (!user) {
    const unregistered = db.prepare("SELECT id, name FROM users WHERE email IS NULL AND role = 'member' ORDER BY name").all();
    return res.json({ status: 'unregistered', unregistered });
  }
  return res.json({ status: user.pin_hash ? 'registered' : 'needs-pin', name: user.name, role: user.role });
});

// New team member: link email to a pre-seeded name slot
app.post('/api/auth/register', (req, res) => {
  const { email, user_id, pin, confirm_pin } = req.body;
  if (!email?.toLowerCase().endsWith('@infosys.com'))
    return res.status(400).json({ error: 'Must use @infosys.com email' });
  if (!pin || pin.length !== 6 || !/^\d{6}$/.test(pin))
    return res.status(400).json({ error: 'PIN must be exactly 6 digits' });
  if (pin !== confirm_pin)
    return res.status(400).json({ error: 'PINs do not match' });
  if (db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(email))
    return res.status(400).json({ error: 'Email already registered' });

  const slot = db.prepare('SELECT id, name, role FROM users WHERE id = ? AND email IS NULL').get(user_id);
  if (!slot) return res.status(404).json({ error: 'Team member slot not found or already claimed' });

  db.prepare('UPDATE users SET email = ?, pin_hash = ? WHERE id = ?').run(email.toLowerCase(), hashPin(pin), slot.id);
  const token = signToken({ id: slot.id, email: email.toLowerCase(), name: slot.name, role: slot.role });
  res.json({ token, user: { id: slot.id, email: email.toLowerCase(), name: slot.name, role: slot.role } });
});

// First login (user exists but no PIN): set PIN
app.post('/api/auth/set-pin', (req, res) => {
  const { email, pin, confirm_pin } = req.body;
  if (!email?.toLowerCase().endsWith('@infosys.com'))
    return res.status(400).json({ error: 'Must use @infosys.com email' });
  if (!pin || pin.length !== 6 || !/^\d{6}$/.test(pin))
    return res.status(400).json({ error: 'PIN must be exactly 6 digits' });
  if (pin !== confirm_pin)
    return res.status(400).json({ error: 'PINs do not match' });

  const user = db.prepare('SELECT id, name, role, pin_hash FROM users WHERE email = ? COLLATE NOCASE').get(email);
  if (!user)          return res.status(404).json({ error: 'User not found' });
  if (user.pin_hash)  return res.status(400).json({ error: 'PIN already set. Use login instead.' });

  db.prepare('UPDATE users SET pin_hash = ? WHERE id = ?').run(hashPin(pin), user.id);
  const token = signToken({ id: user.id, email: email.toLowerCase(), name: user.name, role: user.role });
  res.json({ token, user: { id: user.id, email: email.toLowerCase(), name: user.name, role: user.role } });
});

// Subsequent logins
app.post('/api/auth/login', (req, res) => {
  const { email, pin } = req.body;
  if (!email?.toLowerCase().endsWith('@infosys.com'))
    return res.status(400).json({ error: 'Must use @infosys.com email' });

  const user = db.prepare('SELECT id, name, role, pin_hash, is_active FROM users WHERE email = ? COLLATE NOCASE').get(email);
  if (!user)            return res.status(401).json({ error: 'Not registered. Contact your admin.' });
  if (!user.is_active)  return res.status(401).json({ error: 'Account deactivated. Contact admin.' });
  if (!user.pin_hash)   return res.status(401).json({ error: 'PIN not set. Please use "Set PIN" flow.' });
  if (user.pin_hash !== hashPin(pin)) return res.status(401).json({ error: 'Invalid PIN' });

  const token = signToken({ id: user.id, email: email.toLowerCase(), name: user.name, role: user.role });
  res.json({ token, user: { id: user.id, email: email.toLowerCase(), name: user.name, role: user.role } });
});

// Change PIN
app.post('/api/auth/change-pin', auth, (req, res) => {
  const { old_pin, new_pin, confirm_pin } = req.body;
  const user = db.prepare('SELECT pin_hash FROM users WHERE id = ?').get(req.user.id);
  if (user.pin_hash !== hashPin(old_pin)) return res.status(401).json({ error: 'Current PIN incorrect' });
  if (!new_pin || new_pin.length !== 6 || !/^\d{6}$/.test(new_pin))
    return res.status(400).json({ error: 'New PIN must be exactly 6 digits' });
  if (new_pin !== confirm_pin) return res.status(400).json({ error: 'PINs do not match' });
  db.prepare('UPDATE users SET pin_hash = ? WHERE id = ?').run(hashPin(new_pin), req.user.id);
  res.json({ success: true });
});

// ── Team route ────────────────────────────────────────────────────────────────
app.get('/api/team', auth, (req, res) => {
  // Members see only their own entry in the list (used for calendar row selection);
  // admin and viewer see the full team so the calendar renders all rows.
  const members = (req.user.role === 'admin' || req.user.role === 'viewer')
    ? db.prepare("SELECT id, name, email, role, is_active FROM users WHERE role = 'member' ORDER BY name").all()
    : db.prepare("SELECT id, name, email, role, is_active FROM users WHERE role = 'member' AND id = ?").all(req.user.id);
  res.json(members);
});

// ── Attendance routes ─────────────────────────────────────────────────────────
app.get('/api/attendance/:year/:month', auth, (req, res) => {
  const prefix = `${req.params.year}-${req.params.month.padStart(2, '0')}-`;
  let rows;
  if (req.user.role === 'admin' || req.user.role === 'viewer') {
    rows = db.prepare(`
      SELECT a.id, a.user_id, u.name, a.date, a.status, a.updated_at
      FROM attendance a JOIN users u ON a.user_id = u.id
      WHERE a.date LIKE ? ORDER BY u.name, a.date
    `).all(prefix + '%');
  } else {
    rows = db.prepare(`
      SELECT a.id, a.user_id, u.name, a.date, a.status, a.updated_at
      FROM attendance a JOIN users u ON a.user_id = u.id
      WHERE a.user_id = ? AND a.date LIKE ? ORDER BY a.date
    `).all(req.user.id, prefix + '%');
  }
  res.json(rows);
});

app.post('/api/attendance', auth, (req, res) => {
  if (req.user.role === 'viewer')
    return res.status(403).json({ error: 'View-only access: cannot modify attendance' });

  const { date, status, user_id } = req.body;
  const valid = ['WFO', 'WFH', 'Leave', 'DC Holiday'];
  if (!valid.includes(status))              return res.status(400).json({ error: 'Invalid status' });
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Invalid date' });

  // Members can only update their own record; if user_id is given and differs, reject
  if (req.user.role !== 'admin' && user_id && Number(user_id) !== req.user.id)
    return res.status(403).json({ error: 'Cannot update another member\'s attendance' });
  const targetId = (req.user.role === 'admin' && user_id) ? Number(user_id) : req.user.id;

  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO attendance (user_id, date, status, updated_at) VALUES (?,?,?,?)
    ON CONFLICT(user_id, date) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at
  `).run(targetId, date, status, now);

  const record = db.prepare(`
    SELECT a.id, a.user_id, u.name, a.date, a.status, a.updated_at
    FROM attendance a JOIN users u ON a.user_id = u.id
    WHERE a.user_id=? AND a.date=?
  `).get(targetId, date);

  broadcast('attendance_update', { record });
  res.json(record);
});

app.delete('/api/attendance/:userId/:date', auth, (req, res) => {
  if (req.user.role === 'viewer')
    return res.status(403).json({ error: 'View-only access: cannot modify attendance' });
  const targetId = Number(req.params.userId);
  if (req.user.role !== 'admin' && targetId !== req.user.id)
    return res.status(403).json({ error: 'Forbidden' });
  db.prepare('DELETE FROM attendance WHERE user_id=? AND date=?').run(targetId, req.params.date);
  broadcast('attendance_delete', { user_id: targetId, date: req.params.date });
  res.json({ success: true });
});

// ── DC Holidays routes ────────────────────────────────────────────────────────
app.get('/api/holidays', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM dc_holidays ORDER BY date').all());
});

app.post('/api/holidays', auth, adminOnly, (req, res) => {
  const { date, description } = req.body;
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Valid date required' });

  db.prepare('INSERT OR REPLACE INTO dc_holidays (date, description, created_by) VALUES (?,?,?)')
    .run(date, description || '', req.user.id);

  // Auto-mark all active members
  const members = db.prepare("SELECT id FROM users WHERE role='member' AND is_active=1").all();
  const now = new Date().toISOString();
  for (const m of members) {
    db.prepare(`
      INSERT INTO attendance (user_id,date,status,updated_at) VALUES (?,?,'DC Holiday',?)
      ON CONFLICT(user_id,date) DO UPDATE SET status='DC Holiday', updated_at=excluded.updated_at
    `).run(m.id, date, now);
  }

  broadcast('holiday_added', { date, description });
  res.json({ success: true });
});

app.delete('/api/holidays/:date', auth, adminOnly, (req, res) => {
  db.prepare('DELETE FROM dc_holidays WHERE date=?').run(req.params.date);
  broadcast('holiday_removed', { date: req.params.date });
  res.json({ success: true });
});

// ── Report routes ─────────────────────────────────────────────────────────────
app.get('/api/reports/month/:year/:month', auth, adminOnly, (req, res) => {
  const { year, month } = req.params;
  const prefix  = `${year}-${month.padStart(2, '0')}-`;
  const members = db.prepare("SELECT id, name FROM users WHERE role='member' AND is_active=1 ORDER BY name").all();
  const rows    = db.prepare("SELECT user_id, date, status FROM attendance WHERE date LIKE ? ORDER BY date").all(prefix + '%');

  const byMember = {};
  for (const m of members) byMember[m.id] = { name: m.name, entries: {}, effectiveWfo: 0 };
  for (const r of rows) {
    if (!byMember[r.user_id]) continue;
    byMember[r.user_id].entries[r.date] = r.status;
    if (['WFO', 'Leave', 'DC Holiday'].includes(r.status)) byMember[r.user_id].effectiveWfo++;
  }
  res.json({ year, month, members: byMember });
});

app.get('/api/reports/year/:year', auth, adminOnly, (req, res) => {
  const { year } = req.params;
  const members  = db.prepare("SELECT id, name FROM users WHERE role='member' AND is_active=1 ORDER BY name").all();
  const result   = {};
  for (const m of members) {
    result[m.id] = { name: m.name, months: {} };
    for (let mo = 1; mo <= 12; mo++) {
      const prefix = `${year}-${String(mo).padStart(2, '0')}-`;
      const rows   = db.prepare("SELECT status FROM attendance WHERE user_id=? AND date LIKE ?").all(m.id, prefix + '%');
      const eff    = rows.filter(r => ['WFO','Leave','DC Holiday'].includes(r.status)).length;
      result[m.id].months[mo] = { effectiveWfo: eff, met: eff >= 10 };
    }
  }
  res.json({ year, members: result });
});

app.get('/api/reports/individual/:userId/:year', auth, (req, res) => {
  const uid = Number(req.params.userId);
  if (req.user.role !== 'admin' && uid !== req.user.id) return res.status(403).json({ error: 'Forbidden' });

  const user = db.prepare('SELECT id, name FROM users WHERE id=?').get(uid);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { year } = req.params;
  const rows = db.prepare("SELECT date, status FROM attendance WHERE user_id=? AND date LIKE ? ORDER BY date").all(uid, `${year}-%`);

  const months = {};
  for (let mo = 1; mo <= 12; mo++) months[mo] = { entries: {}, wfo: 0, wfh: 0, leave: 0, holiday: 0, effectiveWfo: 0, met: false };
  for (const r of rows) {
    const mo = parseInt(r.date.split('-')[1]);
    months[mo].entries[r.date] = r.status;
    if (r.status === 'WFO')        months[mo].wfo++;
    else if (r.status === 'WFH')   months[mo].wfh++;
    else if (r.status === 'Leave') months[mo].leave++;
    else if (r.status === 'DC Holiday') months[mo].holiday++;
    if (['WFO','Leave','DC Holiday'].includes(r.status)) months[mo].effectiveWfo++;
    months[mo].met = months[mo].effectiveWfo >= 10;
  }
  res.json({ user, year, months });
});

// ── Admin: user management ────────────────────────────────────────────────────
app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  res.json(db.prepare('SELECT id, email, name, role, is_active FROM users ORDER BY role DESC, name').all());
});

app.post('/api/admin/users', auth, adminOnly, (req, res) => {
  const { name, email } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  if (email && !email.toLowerCase().endsWith('@infosys.com'))
    return res.status(400).json({ error: 'Must use @infosys.com email' });
  db.prepare('INSERT INTO users (name, email) VALUES (?,?)').run(name.trim(), email?.toLowerCase() || null);
  res.json({ success: true });
});

app.put('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  const { is_active } = req.body;
  if (is_active !== undefined) {
    db.prepare('UPDATE users SET is_active=? WHERE id=?').run(is_active ? 1 : 0, req.params.id);
  }
  res.json({ success: true });
});

// Admin: reset a user's PIN (they'll need to set-pin again)
app.post('/api/admin/users/:id/reset-pin', auth, adminOnly, (req, res) => {
  db.prepare('UPDATE users SET pin_hash=NULL WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  Attendance Tracker  →  http://localhost:${PORT}`);
  console.log(`  Admin email         →  ${ADMIN_EMAIL}`);
  console.log(`  Database            →  ${DB_PATH}\n`);
});
