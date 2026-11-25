/* Nirakar Attendance - server */
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const ExcelJS = require('exceljs');
const PDFDocument = require('pdfkit');

// ---------- Config ----------
const PORT = process.env.PORT || 3000;
const TZ = 'Asia/Kathmandu';
const FULL_DAY_HOURS = Number(process.env.FULL_DAY_HOURS || 6); // below this = "Half Day"
const DATA = path.join(__dirname, 'data');
const PHOTOS = path.join(DATA, 'photos');
const BACKUPS = path.join(DATA, 'backups');
[DATA, PHOTOS, BACKUPS].forEach(d => fs.mkdirSync(d, { recursive: true }));

const secretFile = path.join(DATA, '.secret');
let SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  if (!fs.existsSync(secretFile)) fs.writeFileSync(secretFile, crypto.randomBytes(48).toString('hex'));
  SECRET = fs.readFileSync(secretFile, 'utf8');
}

// ---------- Database ----------
const db = new Database(path.join(DATA, 'attendance.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS employees (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  designation TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  date TEXT NOT NULL,                -- YYYY-MM-DD (Nepal time)
  check_in_time TEXT NOT NULL,       -- ISO UTC
  check_in_photo TEXT NOT NULL,
  check_out_time TEXT,
  check_out_photo TEXT,
  UNIQUE (employee_id, date)         -- one check-in per employee per day
);
CREATE INDEX IF NOT EXISTS idx_att_date ON attendance(date);
`);

if (!db.prepare('SELECT COUNT(*) c FROM admins').get().c) {
  const phone = normPhone(process.env.ADMIN_PHONE || '9800000000');
  const pass = process.env.ADMIN_PASSWORD || 'admin123';
  db.prepare('INSERT INTO admins (name, phone, password_hash) VALUES (?,?,?)')
    .run(process.env.ADMIN_NAME || 'Administrator', phone, bcrypt.hashSync(pass, 10));
  console.log(`\n>> First-run admin created. Mobile: ${phone}  Password: ${pass}`);
  console.log('>> Log in and change the password immediately.\n');
}

// ---------- Helpers ----------
function normPhone(p) { return String(p || '').replace(/[^\d]/g, ''); }
function validPhone(p) { return /^\d{7,15}$/.test(p); }
function nowInfo() {
  const d = new Date();
  const date = new Intl.DateTimeFormat('en-CA', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
  return { iso: d.toISOString(), date };
}
function validMonth(m) { return /^\d{4}-(0[1-9]|1[0-2])$/.test(m || ''); }
function currentMonth() { return nowInfo().date.slice(0, 7); }

function savePhoto(dataUrl) {
  const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String(dataUrl || ''));
  if (!m) return null;
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length < 2000 || buf.length > 4 * 1024 * 1024) return null;
  const ext = m[1] === 'jpeg' ? 'jpg' : m[1];
  const name = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.${ext}`;
  fs.writeFileSync(path.join(PHOTOS, name), buf);
  return name;
}

function decorate(r, today) {
  let hours = null, status;
  if (r.check_out_time) {
    hours = Math.round((new Date(r.check_out_time) - new Date(r.check_in_time)) / 3600000 * 100) / 100;
    status = hours >= FULL_DAY_HOURS ? 'Present' : 'Half Day';
  } else {
    status = r.date === today ? 'Checked In' : 'Missing Check-out';
  }
  return { ...r, hours, status };
}

// ---------- Login throttling ----------
const fails = new Map();
const LOCK_MS = 15 * 60000;
const isLocked = k => { const f = fails.get(k); return f && f.count >= 5 && Date.now() - f.t < LOCK_MS; };
const addFail = k => {
  const f = fails.get(k);
  if (!f || Date.now() - f.t > LOCK_MS) fails.set(k, { count: 1, t: Date.now() });
  else { f.count++; f.t = Date.now(); }
};

// ---------- App ----------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '6mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function auth(role) {
  return (req, res, next) => {
    try {
      const h = req.headers.authorization || '';
      const p = jwt.verify(h.startsWith('Bearer ') ? h.slice(7) : '', SECRET);
      if (p.role !== role) throw new Error('role');
      const tbl = role === 'admin' ? 'admins' : 'employees';
      const u = db.prepare(`SELECT * FROM ${tbl} WHERE id=?`).get(p.id);
      if (!u || !u.active) throw new Error('inactive');
      req.user = u;
      next();
    } catch (e) {
      res.status(401).json({ error: 'Please log in again' });
    }
  };
}

function loginHandler(table, role) {
  return (req, res) => {
    const phone = normPhone(req.body.phone);
    const pw = String(req.body.password || '');
    const key = `${role}:${phone}:${req.ip}`;
    if (isLocked(key)) return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
    const u = db.prepare(`SELECT * FROM ${table} WHERE phone=?`).get(phone);
    if (!u || !u.active || !bcrypt.compareSync(pw, u.password_hash)) {
      addFail(key);
      return res.status(401).json({ error: 'Invalid mobile number or password' });
    }
    fails.delete(key);
    const token = jwt.sign({ id: u.id, role }, SECRET, { expiresIn: '12h' });
    res.json({ token, user: { name: u.name, phone: u.phone, designation: u.designation || 'Administrator' } });
  };
}
app.post('/api/admin/login', loginHandler('admins', 'admin'));
app.post('/api/employee/login', loginHandler('employees', 'employee'));

// ---------- Employee API (own data only) ----------
const emp = auth('employee');

app.get('/api/me', emp, (req, res) => {
  const { name, phone, designation } = req.user;
  res.json({ name, phone, designation });
});

app.get('/api/me/today', emp, (req, res) => {
  const { date } = nowInfo();
  const r = db.prepare('SELECT * FROM attendance WHERE employee_id=? AND date=?').get(req.user.id, date);
  res.json({ date, record: r ? decorate(r, date) : null });
});

app.post('/api/me/checkin', emp, (req, res) => {
  const photo = savePhoto(req.body.photo);
  if (!photo) return res.status(400).json({ error: 'A photo is required to check in.' });
  const { iso, date } = nowInfo();
  const exists = db.prepare('SELECT id FROM attendance WHERE employee_id=? AND date=?').get(req.user.id, date);
  if (exists) {
    fs.unlink(path.join(PHOTOS, photo), () => {});
    return res.status(409).json({ error: 'You have already checked in today.' });
  }
  db.prepare('INSERT INTO attendance (employee_id,date,check_in_time,check_in_photo) VALUES (?,?,?,?)')
    .run(req.user.id, date, iso, photo);
  res.json({ ok: true });
});

app.post('/api/me/checkout', emp, (req, res) => {
  const photo = savePhoto(req.body.photo);
  if (!photo) return res.status(400).json({ error: 'A photo is required to check out.' });
  const { iso, date } = nowInfo();
  const r = db.prepare('SELECT * FROM attendance WHERE employee_id=? AND date=?').get(req.user.id, date);
  const bad = msg => { fs.unlink(path.join(PHOTOS, photo), () => {}); return res.status(400).json({ error: msg }); };
  if (!r) return bad('You must check in before you can check out.');
  if (r.check_out_time) return bad('You have already checked out today.');
  db.prepare('UPDATE attendance SET check_out_time=?, check_out_photo=? WHERE id=?').run(iso, photo, r.id);
  res.json({ ok: true });
});

app.get('/api/me/history', emp, (req, res) => {
  const month = validMonth(req.query.month) ? req.query.month : currentMonth();
  const today = nowInfo().date;
  const rows = db.prepare('SELECT * FROM attendance WHERE employee_id=? AND date LIKE ? ORDER BY date DESC')
    .all(req.user.id, month + '-%').map(r => decorate(r, today));
  res.json({ month, records: rows, totalHours: Math.round(rows.reduce((s, r) => s + (r.hours || 0), 0) * 100) / 100 });
});

// ---------- Photos (admin: any, employee: own only) ----------
app.get('/api/photo/:file', (req, res) => {
  try {
    const h = req.headers.authorization || '';
    const p = jwt.verify(h.startsWith('Bearer ') ? h.slice(7) : '', SECRET);
    const file = path.basename(req.params.file);
    if (p.role === 'employee') {
      const own = db.prepare('SELECT id FROM attendance WHERE employee_id=? AND (check_in_photo=? OR check_out_photo=?)').get(p.id, file, file);
      if (!own) return res.status(403).end();
    } else if (p.role !== 'admin') return res.status(403).end();
    const full = path.join(PHOTOS, file);
    if (!fs.existsSync(full)) return res.status(404).end();
    res.set('Cache-Control', 'private, max-age=3600');
    res.sendFile(full);
  } catch (e) { res.status(401).end(); }
});

// ---------- Admin API ----------
const adm = auth('admin');

app.get('/api/admin/employees', adm, (req, res) => {
  res.json(db.prepare('SELECT id,name,phone,designation,active,created_at FROM employees ORDER BY name').all());
});

app.post('/api/admin/employees', adm, (req, res) => {
  const name = String(req.body.name || '').trim();
  const phone = normPhone(req.body.phone);
  const designation = String(req.body.designation || '').trim();
  const password = String(req.body.password || '');
  if (!name) return res.status(400).json({ error: 'Name is required' });
  if (!validPhone(phone)) return res.status(400).json({ error: 'Enter a valid mobile number' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (!designation) return res.status(400).json({ error: 'Designation is required' });
  try {
    const r = db.prepare('INSERT INTO employees (name,phone,password_hash,designation) VALUES (?,?,?,?)')
      .run(name, phone, bcrypt.hashSync(password, 10), designation);
    res.json({ id: r.lastInsertRowid });
  } catch (e) { res.status(409).json({ error: 'This mobile number is already registered' }); }
});

app.put('/api/admin/employees/:id', adm, (req, res) => {
  const id = Number(req.params.id);
  const e = db.prepare('SELECT * FROM employees WHERE id=?').get(id);
  if (!e) return res.status(404).json({ error: 'Employee not found' });
  const name = String(req.body.name ?? e.name).trim();
  const phone = normPhone(req.body.phone ?? e.phone);
  const designation = String(req.body.designation ?? e.designation).trim();
  const active = req.body.active === undefined ? e.active : (req.body.active ? 1 : 0);
  if (!name || !designation) return res.status(400).json({ error: 'Name and designation are required' });
  if (!validPhone(phone)) return res.status(400).json({ error: 'Enter a valid mobile number' });
  let hash = e.password_hash;
  if (req.body.password) {
    if (String(req.body.password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    hash = bcrypt.hashSync(String(req.body.password), 10);
  }
  try {
    db.prepare('UPDATE employees SET name=?,phone=?,designation=?,active=?,password_hash=? WHERE id=?')
      .run(name, phone, designation, active, hash, id);
    res.json({ ok: true });
  } catch (err) { res.status(409).json({ error: 'This mobile number is already registered' }); }
});

app.get('/api/admin/attendance', adm, (req, res) => {
  const today = nowInfo().date;
  const where = [], args = [];
  if (req.query.date && /^\d{4}-\d{2}-\d{2}$/.test(req.query.date)) { where.push('a.date=?'); args.push(req.query.date); }
  else { const m = validMonth(req.query.month) ? req.query.month : currentMonth(); where.push('a.date LIKE ?'); args.push(m + '-%'); }
  if (req.query.employee_id) { where.push('a.employee_id=?'); args.push(Number(req.query.employee_id)); }
  const rows = db.prepare(`SELECT a.*, e.name, e.phone, e.designation FROM attendance a JOIN employees e ON e.id=a.employee_id
    WHERE ${where.join(' AND ')} ORDER BY a.date DESC, e.name`).all(...args).map(r => decorate(r, today));
  res.json(rows);
});

function buildReport(month) {
  const today = nowInfo().date;
  const records = db.prepare(`SELECT a.*, e.name, e.phone, e.designation FROM attendance a JOIN employees e ON e.id=a.employee_id
    WHERE a.date LIKE ? ORDER BY e.name, a.date`).all(month + '-%').map(r => decorate(r, today));
  const employees = db.prepare('SELECT id,name,phone,designation FROM employees ORDER BY name').all();
  const summary = employees.map(e => {
    const rs = records.filter(r => r.employee_id === e.id);
    return {
      name: e.name, phone: e.phone, designation: e.designation,
      present: rs.filter(r => r.status === 'Present').length,
      half: rs.filter(r => r.status === 'Half Day').length,
      missing: rs.filter(r => r.status === 'Missing Check-out').length,
      days: rs.length,
      hours: Math.round(rs.reduce((s, r) => s + (r.hours || 0), 0) * 100) / 100
    };
  });
  return { month, summary, records };
}
const fmtT = iso => iso ? new Date(iso).toLocaleTimeString('en-GB', { timeZone: TZ, hour: '2-digit', minute: '2-digit' }) : '-';

app.get('/api/admin/report', adm, (req, res) => {
  res.json(buildReport(validMonth(req.query.month) ? req.query.month : currentMonth()));
});

app.get('/api/admin/report.xlsx', adm, async (req, res) => {
  const month = validMonth(req.query.month) ? req.query.month : currentMonth();
  const rep = buildReport(month);
  const wb = new ExcelJS.Workbook();
  const s1 = wb.addWorksheet('Summary');
  s1.columns = [
    { header: 'Name', key: 'name', width: 26 }, { header: 'Mobile', key: 'phone', width: 16 },
    { header: 'Designation', key: 'designation', width: 22 }, { header: 'Days Attended', key: 'days', width: 15 },
    { header: 'Present', key: 'present', width: 10 }, { header: 'Half Day', key: 'half', width: 10 },
    { header: 'Missing Check-out', key: 'missing', width: 18 }, { header: 'Total Hours', key: 'hours', width: 12 }
  ];
  rep.summary.forEach(r => s1.addRow(r));
  const s2 = wb.addWorksheet('Daily Records');
  s2.columns = [
    { header: 'Date', key: 'date', width: 13 }, { header: 'Name', key: 'name', width: 26 },
    { header: 'Designation', key: 'designation', width: 22 }, { header: 'Check-in', key: 'in', width: 11 },
    { header: 'Check-out', key: 'out', width: 11 }, { header: 'Hours', key: 'hours', width: 9 },
    { header: 'Status', key: 'status', width: 18 }
  ];
  rep.records.forEach(r => s2.addRow({ date: r.date, name: r.name, designation: r.designation, in: fmtT(r.check_in_time), out: fmtT(r.check_out_time), hours: r.hours ?? '', status: r.status }));
  [s1, s2].forEach(ws => { ws.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } }; ws.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF16996B' } }; });
  res.set({ 'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'Content-Disposition': `attachment; filename="nirakar-attendance-${month}.xlsx"` });
  await wb.xlsx.write(res);
  res.end();
});

app.get('/api/admin/report.pdf', adm, (req, res) => {
  const month = validMonth(req.query.month) ? req.query.month : currentMonth();
  const rep = buildReport(month);
  res.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': `attachment; filename="nirakar-attendance-${month}.pdf"` });
  const doc = new PDFDocument({ size: 'A4', layout: 'landscape', margin: 36 });
  doc.pipe(res);
  const logo = path.join(__dirname, 'public', 'logo.png');
  if (fs.existsSync(logo)) doc.image(logo, 36, 30, { height: 50 });
  doc.fontSize(18).fillColor('#16996B').text('Nirakar Attendance - Monthly Report', 100, 36);
  doc.fontSize(11).fillColor('#333').text(`Month: ${month}`, 100, 60);
  doc.y = 95;

  function table(headers, rows, widths) {
    const x0 = 36; let y = doc.y;
    const drawRow = (cells, bold) => {
      if (y > 520) { doc.addPage(); y = 40; }
      let x = x0;
      if (bold) doc.rect(x0, y - 3, widths.reduce((a, b) => a + b, 0), 18).fill('#16996B');
      doc.fillColor(bold ? '#fff' : '#222').font(bold ? 'Helvetica-Bold' : 'Helvetica').fontSize(9);
      cells.forEach((c, i) => { doc.text(String(c ?? ''), x + 3, y, { width: widths[i] - 6, height: 12, ellipsis: true, lineBreak: false }); x += widths[i]; });
      y += 18;
    };
    drawRow(headers, true);
    rows.forEach(r => drawRow(r, false));
    doc.y = y + 10;
  }
  doc.fillColor('#6B3D1A').fontSize(13).text('Summary', 36, doc.y); doc.y += 6;
  table(['Name', 'Designation', 'Days', 'Present', 'Half Day', 'Missing Out', 'Total Hours'],
    rep.summary.map(s => [s.name, s.designation, s.days, s.present, s.half, s.missing, s.hours]), [200, 160, 60, 60, 60, 80, 80]);
  doc.addPage();
  doc.fillColor('#6B3D1A').fontSize(13).text('Daily Records', 36, 36); doc.y = 60;
  table(['Date', 'Name', 'Designation', 'Check-in', 'Check-out', 'Hours', 'Status'],
    rep.records.map(r => [r.date, r.name, r.designation, fmtT(r.check_in_time), fmtT(r.check_out_time), r.hours ?? '-', r.status]),
    [80, 190, 140, 70, 70, 60, 100]);
  doc.end();
});

app.post('/api/admin/password', adm, (req, res) => {
  const { current, next } = req.body;
  if (!bcrypt.compareSync(String(current || ''), req.user.password_hash)) return res.status(400).json({ error: 'Current password is incorrect' });
  if (String(next || '').length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
  db.prepare('UPDATE admins SET password_hash=? WHERE id=?').run(bcrypt.hashSync(String(next), 10), req.user.id);
  res.json({ ok: true });
});

// ---------- Automatic backups ----------
let backingUp = false;
async function runBackup() {
  if (backingUp) return null;
  backingUp = true;
  try {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const file = `attendance-${stamp}.db`;
    await db.backup(path.join(BACKUPS, file));
    const all = fs.readdirSync(BACKUPS).filter(f => f.endsWith('.db')).sort();
    all.slice(0, Math.max(0, all.length - 30)).forEach(f => fs.unlinkSync(path.join(BACKUPS, f))); // keep newest 30
    console.log('Backup created:', file);
    return file;
  } catch (e) { console.error('Backup failed:', e.message); return null; }
  finally { backingUp = false; }
}
runBackup();
setInterval(runBackup, 24 * 60 * 60 * 1000);

app.get('/api/admin/backups', adm, (req, res) => {
  const list = fs.readdirSync(BACKUPS).filter(f => f.endsWith('.db')).sort().reverse()
    .map(f => ({ file: f, size: fs.statSync(path.join(BACKUPS, f)).size }));
  res.json(list);
});
app.post('/api/admin/backups', adm, async (req, res) => {
  const f = await runBackup();
  f ? res.json({ file: f }) : res.status(500).json({ error: 'Backup failed' });
});
app.get('/api/admin/backups/:file', adm, (req, res) => {
  const f = path.basename(req.params.file);
  const full = path.join(BACKUPS, f);
  if (!f.endsWith('.db') || !fs.existsSync(full)) return res.status(404).end();
  res.download(full);
});

app.listen(PORT, () => console.log(`Nirakar Attendance running on http://localhost:${PORT}`));
