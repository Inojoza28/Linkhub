// server.js — versão segura com Admin + Postgres
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const dotenv = require('dotenv');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { Pool } = require('pg');

dotenv.config();

const app = express();

// ===== Configurações =====
const EVENT_PASSWORD = process.env.EVENT_PASSWORD;
const COOKIE_SECRET = process.env.COOKIE_SECRET;
const PORT = process.env.PORT || 3000;
const PUBLIC_ORIGIN = (process.env.PUBLIC_ORIGIN || '').trim() || null;
const IS_PROD = process.env.NODE_ENV === 'production';
const ADMIN_KEY = process.env.ADMIN_KEY;

// ===== Postgres =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: IS_PROD ? { rejectUnauthorized: false } : false
});

// Cria tabela se não existir
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS participants (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      linkedin_url TEXT NOT NULL UNIQUE,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_participants_created_at
      ON participants(created_at DESC, id DESC);
  `);
})();

// ===== Cache de participantes =====
let lastParticipants = [];
let lastFetchTime = 0;

// ===== Segurança de cabeçalhos =====
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// ===== CORS =====
if (PUBLIC_ORIGIN) {
  app.use(cors({ origin: PUBLIC_ORIGIN, credentials: true }));
} else {
  app.use(cors({ origin: true, credentials: true }));
}

// ===== Rate limit =====
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(['/auth', '/api/register', '/api/participants'], authLimiter);

// ===== Body parsers =====
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ===== Cookies assinados =====
app.use(cookieParser(COOKIE_SECRET));

// ===== Utilitários =====
function isValidName(name) {
  if (typeof name !== 'string') return false;
  const s = name.trim();
  if (s.length < 2 || s.length > 50) return false;
  return /^[A-Za-zÀ-ÖØ-öø-ÿ0-9'’´`^~.,()-\s]+$/.test(s);
}

function normalizeLinkedIn(input) {
  if (!input) return null;
  let s = String(input).trim();
  if (!s) return null;

  s = s.replace(/^@/, '');
  const hasProtocol = /^https?:\/\//i.test(s);
  const hasLinkedIn = /(^|\/|\.)linkedin\.com/i.test(s);

  if (!hasProtocol) {
    if (hasLinkedIn) {
      s = 'https://' + s.replace(/^www\./i, '');
    } else {
      s = `https://www.linkedin.com/in/${s}`;
    }
  }

  try {
    const url = new URL(s.replace(/^http:\/\//i, 'https://'));
    url.hash = '';
    url.search = '';
    url.hostname = 'www.linkedin.com';
    let normalized = url.toString().replace(/\/$/, '');
    if (!/(^|\/|\.)linkedin\.com/i.test(normalized)) return null;
    return normalized;
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const token = req.signedCookies?.event_session;
  if (token === '1') return next();
  if (req.accepts('html')) return res.redirect('/');
  return res.status(401).json({ error: 'unauthorized' });
}

function setEventCookie(res) {
  res.cookie('event_session', '1', {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PROD,
    signed: true
  });
}

// ===== Static files =====
app.use(express.static(path.join(__dirname, 'public')));

// ===== Rotas =====
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Autenticação
app.post('/auth', (req, res) => {
  const { password } = req.body || {};
  if (typeof password === 'string' && password === EVENT_PASSWORD) {
    setEventCookie(res);
    return res.json({ ok: true });
  }
  return res.status(401).json({ ok: false, error: 'invalid_password' });
});

// Painel protegido
app.get('/panel', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'panel.html'));
});

// Lista de participantes (protegido + cache)
app.get('/api/participants', requireAuth, async (req, res) => {
  try {
    const now = Date.now();
    if (now - lastFetchTime < 2000 && lastParticipants.length > 0) {
      return res.json({ participants: lastParticipants });
    }

    const { rows } = await pool.query(`
      SELECT id, name, linkedin_url, created_at
      FROM participants
      ORDER BY created_at DESC, id DESC
    `);

    lastParticipants = rows;
    lastFetchTime = now;

    res.json({ participants: rows });
  } catch (err) {
    console.error('[DB ERROR]', err);
    res.status(500).json({ error: 'db_error' });
  }
});

// Cadastro
app.post('/api/register', requireAuth, async (req, res) => {
  const rawName = (req.body?.name ?? '').toString();
  const rawLinkedIn = (req.body?.linkedin ?? '').toString();
  const name = rawName.trim();
  const linkedin = normalizeLinkedIn(rawLinkedIn);

  if (!isValidName(name)) {
    return res.status(400).json({ ok: false, error: 'invalid_name' });
  }
  if (!linkedin) {
    return res.status(400).json({ ok: false, error: 'invalid_linkedin' });
  }

  try {
    const { rows: existing } = await pool.query(
      'SELECT id, name, linkedin_url, created_at FROM participants WHERE linkedin_url = $1',
      [linkedin]
    );

    if (existing.length > 0) {
      return res.json({ ok: true, status: 'exists', participant: existing[0] });
    }

    const { rows } = await pool.query(
      'INSERT INTO participants (name, linkedin_url) VALUES ($1, $2) RETURNING id, name, linkedin_url, created_at',
      [name, linkedin]
    );

    lastParticipants = [];
    lastFetchTime = 0;

    return res.json({ ok: true, status: 'created', participant: rows[0] });
  } catch (e) {
    if (String(e.message).includes('duplicate key')) {
      return res.json({ ok: true, status: 'exists' });
    }
    console.error('[DB ERROR]', e);
    return res.status(500).json({ ok: false, error: 'db_error' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('event_session', {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PROD,
    signed: true
  });
  res.redirect('/');
});

// ===== Admin =====
app.get('/admin', async (req, res) => {
  const key = req.query.key || '';
  if (key !== ADMIN_KEY) {
    return res.status(403).send('<h2>Acesso negado</h2><p>Chave inválida.</p>');
  }

  try {
    const { rows } = await pool.query(
      'SELECT * FROM participants ORDER BY created_at DESC, id DESC'
    );

    let html = `
      <h1>Painel Admin</h1>
      <p>Total: ${rows.length} participantes</p>
      <table border="1" cellpadding="6" cellspacing="0">
        <tr><th>ID</th><th>Nome</th><th>LinkedIn</th><th>Ações</th></tr>
    `;

    rows.forEach(p => {
      html += `
        <tr>
          <td>${p.id}</td>
          <td>${p.name}</td>
          <td><a href="${p.linkedin_url}" target="_blank">${p.linkedin_url}</a></td>
          <td>
            <form method="POST" action="/admin/delete?key=${ADMIN_KEY}" style="display:inline">
              <input type="hidden" name="id" value="${p.id}" />
              <button type="submit">Remover</button>
            </form>
          </td>
        </tr>
      `;
    });

    html += `</table>`;
    res.send(html);
  } catch (err) {
    console.error('[DB ADMIN ERROR]', err);
    res.status(500).send('<p>Erro ao carregar admin.</p>');
  }
});

app.post('/admin/delete', express.urlencoded({ extended: true }), async (req, res) => {
  const key = req.query.key || '';
  if (key !== ADMIN_KEY) {
    return res.status(403).send('<h2>Acesso negado</h2><p>Chave inválida.</p>');
  }

  const id = parseInt(req.body.id, 10);
  if (!id) return res.status(400).send('<p>ID inválido</p>');

  try {
    await pool.query('DELETE FROM participants WHERE id = $1', [id]);
    res.redirect(`/admin?key=${ADMIN_KEY}`);
  } catch (e) {
    console.error('[DB DELETE ERROR]', e);
    res.status(500).send('<p>Erro ao remover participante.</p>');
  }
});

// ===== Start =====
app.listen(PORT, () => {
  console.log(`✅ Servidor rodando em http://localhost:${PORT}`);
});
