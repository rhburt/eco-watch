const express = require('express');
const path    = require('path');
const crypto  = require('crypto');
const app     = express();

app.use(express.json());
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ── In-memory data ────────────────────────────────────────────────────────────

const users = {
  admin:     { username: 'admin',     password: 'ecowatch2026', role: 'admin',       name: 'Dr. Priya Nair',    avatar: '🛡️', bio: 'Platform administrator and environmental data scientist.' },
  ranger:    { username: 'ranger',    password: 'fieldwork!1',  role: 'field_agent', name: 'Marcus Delgado',    avatar: '🌿', bio: 'Lead field investigator. 9 years tracking industrial polluters.' },
  volunteer: { username: 'volunteer', password: 'saveearth',    role: 'volunteer',   name: 'Sasha Kowalski',    avatar: '🌱', bio: 'Citizen scientist and weekend cleanup crew organizer.' },
};

let reportSeq = 6;
const reports = [
  { id: 1, title: 'Oil slick detected — Sector 7 coastline',        location: 'Clearwater Bay',   severity: 'critical', status: 'active',        reporter: 'ranger',    date: '2026-02-28', description: 'Large surface oil slick observed from drone survey. Marine wildlife affected.' },
  { id: 2, title: 'Illegal chemical drums dumped near river bend',   location: 'Green Valley',     severity: 'high',     status: 'investigating', reporter: 'volunteer', date: '2026-03-01', description: 'Approx. 40 unlabelled drums discovered by trail volunteers.' },
  { id: 3, title: 'Factory effluent discharge confirmed',            location: 'Industrial Zone B', severity: 'high',    status: 'resolved',      reporter: 'ranger',    date: '2026-02-25', description: 'NovoChem facility cited and fined $320k. Discharge halted.' },
  { id: 4, title: 'Microplastics in North Fields groundwater',       location: 'North Fields',     severity: 'medium',   status: 'monitoring',    reporter: 'admin',     date: '2026-03-02', description: 'Sampling shows 4.2x elevated microplastic concentration vs baseline.' },
  { id: 5, title: 'PM2.5 spike — third consecutive alert day',      location: 'Downtown Core',    severity: 'medium',   status: 'active',        reporter: 'volunteer', date: '2026-03-03', description: 'Particulate matter above safe thresholds since March 1st.' },
];

const sessions = new Map(); // token → username

// ── Merge functions ───────────────────────────────────────────────────────────

function vulnerableMerge(target, source) {
  for (const key in source) {                         // ← for…in walks __proto__
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      vulnerableMerge(target[key], source[key]);      // ← recurses into __proto__!
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

function safeMerge(target, source) {
  const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);
  for (const key of Object.keys(source)) {           // Object.keys = own keys only
    if (BLOCKED.has(key)) continue;                  // ← block dangerous keys
    if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
      if (!target[key] || typeof target[key] !== 'object') target[key] = {};
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// ── Role permission tables ────────────────────────────────────────────────────
//
// IMPORTANT: Keys absent from a role's table (e.g. canManageUsers for volunteer)
// will NOT be set as own properties on the perms object — so if Object.prototype
// has been polluted with that key, the lookup will find it via the prototype chain.
// This is exactly how the exploit works.

const ROLE_PERMISSIONS = {
  volunteer:   { canView: true, canCreate: false },
  field_agent: { canView: true, canCreate: true  },
  admin:       { canView: true, canCreate: true, canManageUsers: true, canDeleteReports: true },
};

function getPermissions(role) {
  const perms = {};   // ← fresh object: inherits from Object.prototype
  const rp = ROLE_PERMISSIONS[role] || {};
  for (const k of Object.keys(rp)) perms[k] = rp[k];
  return perms;
}

// Serialize all known permission keys — property access walks prototype chain,
// so polluted values surface here automatically.
function serializePerms(perms) {
  return {
    canView:           !!perms.canView,
    canCreate:         !!perms.canCreate,
    canManageUsers:    !!perms.canManageUsers,
    canDeleteReports:  !!perms.canDeleteReports,
  };
}

// ── Auth middleware ───────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (!token || !sessions.has(token)) return res.status(401).json({ error: 'Unauthorized' });
  req.username = sessions.get(token);
  req.user     = users[req.username];
  req.perms    = getPermissions(req.user.role);
  next();
}

// ── Auth routes ───────────────────────────────────────────────────────────────

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = users[username];
  if (!user || user.password !== password)
    return res.status(401).json({ error: 'Invalid username or password' });
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, username);
  const { password: _, ...safe } = user;
  res.json({ token, user: safe, permissions: serializePerms(getPermissions(user.role)) });
});

app.post('/api/logout', requireAuth, (req, res) => {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  sessions.delete(token);
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const { password: _, ...safe } = req.user;
  res.json({ user: safe, permissions: serializePerms(req.perms) });
});

// ── Report routes ─────────────────────────────────────────────────────────────

app.get('/api/reports', requireAuth, (req, res) => {
  if (!req.perms.canView) return res.status(403).json({ error: 'Forbidden' });
  res.json({ reports: [...reports].reverse() });
});

app.post('/api/reports', requireAuth, (req, res) => {
  if (!req.perms.canCreate)
    return res.status(403).json({ error: 'Forbidden — field agents and above can submit reports' });
  const { title, location, severity, description } = req.body;
  if (!title || !location) return res.status(400).json({ error: 'title and location are required' });
  const report = {
    id: reportSeq++, title, location,
    severity: severity || 'medium', status: 'active',
    reporter: req.username,
    date: new Date().toISOString().split('T')[0],
    description: description || '',
  };
  reports.push(report);
  res.json({ report });
});

app.delete('/api/reports/:id', requireAuth, (req, res) => {
  if (!req.perms.canDeleteReports)
    return res.status(403).json({ error: 'Forbidden — admin only' });
  const idx = reports.findIndex(r => r.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Report not found' });
  const [deleted] = reports.splice(idx, 1);
  res.json({ deleted });
});

// ── Profile update routes (the vulnerable demo) ───────────────────────────────

app.post('/api/profile/update', requireAuth, (req, res) => {
  let parsed;
  try {
    parsed = typeof req.body.data === 'string' ? JSON.parse(req.body.data) : req.body.data;
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed))
      return res.status(400).json({ error: 'Payload must be a JSON object' });
  } catch (e) {
    return res.status(400).json({ error: 'Invalid JSON: ' + e.message });
  }

  const protoBefore = Object.keys(Object.prototype);

  // ← VULNERABLE: recurses into __proto__, polluting Object.prototype
  vulnerableMerge(req.user, parsed);

  const protoAfter  = Object.keys(Object.prototype);
  const polluted    = protoAfter.filter(k => !protoBefore.includes(k));
  const permsAfter  = serializePerms(getPermissions(req.user.role));
  const { password: _, ...safe } = req.user;

  res.json({
    user: safe,
    permissions: permsAfter,
    attack: {
      pollutedKeys: polluted,
      prototypeState: (() => { const s = {}; for (const k of protoAfter) s[k] = Object.prototype[k]; return s; })(),
      privilegeEscalation: polluted.some(k => ['canManageUsers','canDeleteReports','canCreate'].includes(k)),
    },
  });
});

app.post('/api/profile/update-safe', requireAuth, (req, res) => {
  let parsed;
  try {
    parsed = typeof req.body.data === 'string' ? JSON.parse(req.body.data) : req.body.data;
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed))
      return res.status(400).json({ error: 'Payload must be a JSON object' });
  } catch (e) {
    return res.status(400).json({ error: 'Invalid JSON: ' + e.message });
  }

  safeMerge(req.user, parsed);

  const { password: _, ...safe } = req.user;
  res.json({
    user: safe,
    permissions: serializePerms(getPermissions(req.user.role)),
    attack: {
      pollutedKeys: [],
      prototypeState: {},
      privilegeEscalation: false,
    },
  });
});

// ── Admin routes ──────────────────────────────────────────────────────────────

app.get('/api/admin/users', requireAuth, (req, res) => {
  if (!req.perms.canManageUsers)
    return res.status(403).json({ error: 'Forbidden — admin only', prototypeClean: Object.keys(Object.prototype).length === 0 });
  const safe = Object.values(users).map(({ password: _, ...u }) => ({ ...u, permissions: serializePerms(getPermissions(u.role)) }));
  res.json({
    users: safe,
    prototypeWarning: Object.keys(Object.prototype).length > 0
      ? '⚠️  Object.prototype is currently polluted — permissions may be unreliable!'
      : null,
  });
});

app.post('/api/admin/assign-role', requireAuth, (req, res) => {
  if (!req.perms.canManageUsers) return res.status(403).json({ error: 'Forbidden — admin only' });
  const { username, role } = req.body || {};
  if (!users[username]) return res.status(404).json({ error: 'User not found' });
  if (!ROLE_PERMISSIONS[role]) return res.status(400).json({ error: 'Invalid role. Use: volunteer, field_agent, admin' });
  users[username].role = role;
  const { password: _, ...safe } = users[username];
  res.json({ user: safe, message: `${username} is now a ${role}` });
});

// ── Lab utility routes ────────────────────────────────────────────────────────

app.get('/api/prototype-state', (_req, res) => {
  const keys = Object.keys(Object.prototype);
  const state = {};
  for (const k of keys) state[k] = Object.prototype[k];
  res.json({ polluted: keys.length > 0, keys, state });
});

app.post('/api/prototype-reset', (_req, res) => {
  const keys = Object.keys(Object.prototype);
  for (const k of keys) delete Object.prototype[k];
  res.json({ cleared: keys, message: 'Object.prototype has been cleaned' });
});

// ── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`EcoWatch running → http://localhost:${PORT}`));
