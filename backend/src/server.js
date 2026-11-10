import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import argon2 from 'argon2';
import axios from 'axios';
import cors from 'cors';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import pg from 'pg';

const { Pool } = pg;
const app = express();
const port = Number(process.env.PORT || 8000);
const uploadDir = path.resolve(process.env.UPLOAD_DIR || './uploads');
const maxUploadMb = Number(process.env.MAX_UPLOAD_MB || 100);
const jwtSecret = process.env.JWT_SECRET || 'local-jwt-secret-change-me-before-use-123456';
const sharedToken = process.env.ANALYZER_SHARED_TOKEN || 'local-analyzer-token-change-me';
const analyzerUrl = process.env.ANALYZER_URL || 'http://localhost:8001';
if (process.env.NODE_ENV === 'production' && (jwtSecret.length < 32 || jwtSecret.startsWith('local-') || sharedToken.startsWith('local-'))) {
  throw new Error('Production requires non-default JWT and analyzer secrets of at least 32 characters');
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL || 'postgresql://pqc_app:local-dev-only-change-me@localhost:5432/pqc_assistant' });

await fs.mkdir(uploadDir, { recursive: true });
app.use(helmet());
app.use(cors({ origin: (process.env.CORS_ORIGIN || 'http://localhost:5173').split(','), credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use('/api/auth', rateLimit({ windowMs: 60_000, limit: 20, standardHeaders: true, legacyHeaders: false }));

function auth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    req.user = jwt.verify(token, jwtSecret, { issuer: 'pqc-assessment-gateway' });
    if (!['security_analyst', 'admin'].includes(req.user.role)) return res.status(403).json({ error: 'Insufficient role' });
    next();
  }
  catch { return res.status(401).json({ error: 'Invalid or expired token' }); }
}

async function ownsProject(projectId, userId) {
  const { rowCount } = await pool.query('SELECT 1 FROM projects WHERE id=$1 AND user_id=$2', [projectId, userId]);
  return rowCount > 0;
}

app.get('/healthz', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ status: 'ok', service: 'gateway', database: 'ok' }); }
  catch { res.status(503).json({ status: 'unavailable', service: 'gateway' }); }
});

app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { email, password, full_name: fullName } = req.body || {};
    if (typeof email !== 'string' || !/^\S+@\S+\.\S+$/.test(email) || typeof password !== 'string' || password.length < 12 || password.length > 256) {
      return res.status(400).json({ error: 'Provide a valid email and a password between 12 and 256 characters' });
    }
    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
    const { rows } = await pool.query('INSERT INTO users(email,password_hash,full_name) VALUES($1,$2,$3) RETURNING id,email,full_name,role', [email.toLowerCase(), passwordHash, typeof fullName === 'string' ? fullName.slice(0, 150) : null]);
    res.status(201).json({ user: rows[0] });
  } catch (error) { if (error.code === '23505') return res.status(409).json({ error: 'Email already registered' }); next(error); }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    const { rows } = await pool.query('SELECT id,email,password_hash,full_name,role FROM users WHERE email=$1', [String(email || '').toLowerCase()]);
    if (!rows[0] || !(await argon2.verify(rows[0].password_hash, String(password || '')))) return res.status(401).json({ error: 'Invalid email or password' });
    const user = { id: rows[0].id, email: rows[0].email, full_name: rows[0].full_name, role: rows[0].role };
    const token = jwt.sign(user, jwtSecret, { expiresIn: '8h', issuer: 'pqc-assessment-gateway' });
    res.json({ token, user });
  } catch (error) { next(error); }
});

app.get('/api/projects', auth, async (req, res, next) => {
  try { const { rows } = await pool.query('SELECT id,name,description,created_at FROM projects WHERE user_id=$1 ORDER BY created_at DESC', [req.user.id]); res.json({ projects: rows }); }
  catch (error) { next(error); }
});

app.post('/api/projects', auth, async (req, res, next) => {
  try {
    const name = String(req.body?.name || '').trim();
    if (!name || name.length > 255) return res.status(400).json({ error: 'Project name is required (maximum 255 characters)' });
    const description = typeof req.body.description === 'string' ? req.body.description.slice(0, 4000) : null;
    const { rows } = await pool.query("INSERT INTO projects(user_id,name,description) VALUES($1,$2,$3) RETURNING id,name,description,created_at", [req.user.id, name, description]);
    res.status(201).json({ project: rows[0] });
  } catch (error) { next(error); }
});

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadDir),
    filename: (_req, _file, cb) => cb(null, `${crypto.randomUUID()}.zip`),
  }),
  limits: { fileSize: maxUploadMb * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    if (file.originalname.toLowerCase().endsWith('.zip')) return cb(null, true);
    const error = new Error('Only ZIP archives are accepted');
    error.status = 400;
    cb(error);
  },
});

app.post('/api/repositories/upload/:projectId', auth, upload.single('repository'), async (req, res, next) => {
  if (!req.file) return res.status(400).json({ error: 'A ZIP file is required in form field `repository`' });
  try {
    if (!(await ownsProject(req.params.projectId, req.user.id))) { await fs.rm(req.file.path, { force: true }); return res.status(404).json({ error: 'Project not found' }); }
    const handle = await fs.open(req.file.path, 'r');
    const signature = Buffer.alloc(4);
    await handle.read(signature, 0, 4, 0);
    await handle.close();
    if (signature.toString('hex') !== '504b0304' && signature.toString('hex') !== '504b0506' && signature.toString('hex') !== '504b0708') {
      await fs.rm(req.file.path, { force: true });
      return res.status(400).json({ error: 'File content is not a ZIP archive' });
    }
    const digest = crypto.createHash('sha256').update(await fs.readFile(req.file.path)).digest('hex');
    const { rows } = await pool.query('INSERT INTO repositories(project_id,stored_name,original_name,sha256,size_bytes) VALUES($1,$2,$3,$4,$5) RETURNING id,original_name,sha256,size_bytes,created_at', [req.params.projectId, path.basename(req.file.filename), req.file.originalname.slice(0, 255), digest, req.file.size]);
    res.status(201).json({ repository: rows[0] });
  } catch (error) { await fs.rm(req.file.path, { force: true }).catch(() => {}); next(error); }
});

app.post('/api/assessments', auth, async (req, res, next) => {
  const { project_id: projectId, repository_id: repositoryId, scan_label: scanLabel = 'Assessment' } = req.body || {};
  try {
    if (!(await ownsProject(projectId, req.user.id))) return res.status(404).json({ error: 'Project not found' });
    const repo = await pool.query('SELECT id FROM repositories WHERE id=$1 AND project_id=$2', [repositoryId, projectId]);
    if (!repo.rowCount) return res.status(404).json({ error: 'Repository not found for this project' });
    const { rows } = await pool.query('INSERT INTO assessments(project_id,repository_id,scan_label) VALUES($1,$2,$3) RETURNING id,status,stage,created_at', [projectId, repositoryId, String(scanLabel).slice(0, 100)]);
    try {
      await axios.post(`${analyzerUrl}/api/analyzer/scan`, { assessment_id: rows[0].id }, { headers: { Authorization: `Bearer ${sharedToken}` }, timeout: 10_000 });
    } catch (error) {
      await pool.query("UPDATE assessments SET status='FAILED',stage='FAILED',error_message='Analyzer queue unavailable',completed_at=NOW() WHERE id=$1", [rows[0].id]);
      return res.status(503).json({ error: 'Analyzer is unavailable; assessment was recorded as failed', assessment_id: rows[0].id });
    }
    res.status(202).json({ assessment: rows[0] });
  } catch (error) { next(error); }
});

app.get('/api/assessments/:id/status', auth, async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT a.id,a.scan_label,a.status,a.stage,a.error_message,a.files_scanned,a.findings_count,a.created_at,a.started_at,a.completed_at FROM assessments a JOIN projects p ON p.id=a.project_id WHERE a.id=$1 AND p.user_id=$2', [req.params.id, req.user.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Assessment not found' });
    res.json({ assessment: rows[0] });
  } catch (error) { next(error); }
});

app.get('/api/assessments/:id/findings', auth, async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT a.result_json FROM assessments a JOIN projects p ON p.id=a.project_id WHERE a.id=$1 AND p.user_id=$2 AND a.status=\'COMPLETED\'', [req.params.id, req.user.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Completed assessment not found' });
    const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 50));
    const offset = Math.max(0, Number.parseInt(req.query.offset, 10) || 0);
    const findings = rows[0].result_json.findings || [];
    res.json({ assessment_id: req.params.id, total: findings.length, limit, offset, findings: findings.slice(offset, offset + limit) });
  } catch (error) { next(error); }
});

app.get('/api/assessments/:id/results', auth, async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT a.result_json FROM assessments a JOIN projects p ON p.id=a.project_id WHERE a.id=$1 AND p.user_id=$2 AND a.status=\'COMPLETED\'', [req.params.id, req.user.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Completed assessment not found' });
    res.json({ assessment_id: req.params.id, ...rows[0].result_json });
  } catch (error) { next(error); }
});

app.get('/api/cbom/:assessmentId/export', auth, async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT a.result_json FROM assessments a JOIN projects p ON p.id=a.project_id WHERE a.id=$1 AND p.user_id=$2 AND a.status=\'COMPLETED\'', [req.params.assessmentId, req.user.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Completed assessment not found' });
    const bom = rows[0].result_json.cbom;
    if (req.query.format === 'csv') {
      const csv = ['bom-ref,type,name,algorithm,operation', ...(bom.components || []).map(c => [c['bom-ref'], c.type, c.name, c.cryptoProperties?.algorithmProperties?.primitive, c.cryptoProperties?.assetType].map(v => `"${String(v ?? '').replaceAll('"', '""')}"`).join(','))].join('\n');
      res.setHeader('Content-Disposition', `attachment; filename="cbom-${req.params.assessmentId}.csv"`);
      return res.type('text/csv').send(csv);
    }
    res.setHeader('Content-Disposition', `attachment; filename="cbom-${req.params.assessmentId}.json"`);
    return res.type('application/json').send(JSON.stringify(bom, null, 2));
  } catch (error) { next(error); }
});

for (const section of ['risk', 'cars', 'recommendations']) {
  app.get(`/api/${section}/:assessmentId`, auth, async (req, res, next) => {
    try {
      const { rows } = await pool.query('SELECT a.result_json FROM assessments a JOIN projects p ON p.id=a.project_id WHERE a.id=$1 AND p.user_id=$2 AND a.status=\'COMPLETED\'', [req.params.assessmentId, req.user.id]);
      if (!rows[0]) return res.status(404).json({ error: 'Completed assessment not found' });
      res.json({ assessment_id: req.params.assessmentId, [section]: rows[0].result_json[section] });
    } catch (error) { next(error); }
  });
}

app.post('/api/validation/compare', auth, async (req, res, next) => {
  try {
    const { baseline_id: baselineId, migrated_id: migratedId } = req.body || {};
    const { rows } = await pool.query('SELECT a.id,a.result_json FROM assessments a JOIN projects p ON p.id=a.project_id WHERE a.id=ANY($1::uuid[]) AND p.user_id=$2 AND a.status=\'COMPLETED\'', [[baselineId, migratedId], req.user.id]);
    if (!baselineId || !migratedId || rows.length !== 2) return res.status(404).json({ error: 'Both completed assessments must belong to the current user' });
    const byId = Object.fromEntries(rows.map(row => [row.id, row.result_json]));
    const group = findings => {
      const grouped = new Map();
      for (const finding of findings || []) {
        const key = `${finding.algorithm}|${finding.operation}|${finding.file_path}`;
        grouped.set(key, [...(grouped.get(key) || []), { algorithm: finding.algorithm, operation: finding.operation, file_path: finding.file_path }]);
      }
      return grouped;
    };
    const before = group(byId[baselineId].findings);
    const after = group(byId[migratedId].findings);
    const resolved = [], remaining = [], newlyIntroduced = [];
    for (const [key, items] of before) {
      const later = after.get(key) || [];
      remaining.push(...items.slice(0, later.length));
      resolved.push(...items.slice(later.length));
    }
    for (const [key, items] of after) newlyIntroduced.push(...items.slice((before.get(key) || []).length));
    res.json({ baseline_id: baselineId, migrated_id: migratedId, resolved, remaining, newly_introduced: newlyIntroduced });
  } catch (error) { next(error); }
});

app.get('/api/reports/:assessmentId/pdf', auth, async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT a.id FROM assessments a JOIN projects p ON p.id=a.project_id WHERE a.id=$1 AND p.user_id=$2 AND a.status=\'COMPLETED\'', [req.params.assessmentId, req.user.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Completed assessment not found' });
    const pdf = await axios.get(`${analyzerUrl}/api/reports/${req.params.assessmentId}/pdf`, { headers: { Authorization: `Bearer ${sharedToken}` }, responseType: 'arraybuffer', timeout: 30_000 });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="assessment-${req.params.assessmentId}.pdf"`);
    res.send(Buffer.from(pdf.data));
  } catch (error) { next(error); }
});

app.get('/api/reports/:assessmentId/download', auth, async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT a.id,a.scan_label,a.status,a.result_json,a.created_at FROM assessments a JOIN projects p ON p.id=a.project_id WHERE a.id=$1 AND p.user_id=$2 AND a.status=\'COMPLETED\'', [req.params.assessmentId, req.user.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Completed assessment not found' });
    res.setHeader('Content-Disposition', `attachment; filename="assessment-${rows[0].id}.json"`);
    res.type('application/json').send(JSON.stringify({ ...rows[0], ...rows[0].result_json }, null, 2));
  } catch (error) { next(error); }
});

app.use((error, _req, res, _next) => {
  const status = error instanceof multer.MulterError || error.status === 400 ? 400 : 500;
  res.status(status).json({ error: status === 500 ? 'Internal server error' : error.message });
});

app.listen(port, '0.0.0.0', () => console.log(`Gateway listening on ${port}`));
