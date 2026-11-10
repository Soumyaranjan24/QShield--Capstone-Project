import { useEffect, useMemo, useState } from 'react';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';
const APP_NAME = import.meta.env.VITE_APP_NAME || 'QShield';

async function request(path, options = {}) {
  const token = localStorage.getItem('pqc_token');
  const headers = { ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers };
  const response = await fetch(`${API}${path}`, { ...options, headers });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || body.detail || `Request failed (${response.status})`);
  }
  return response;
}

function download(path, name) {
  request(path).then(r => r.blob()).then(blob => {
    const url = URL.createObjectURL(blob);
    const anchor = Object.assign(document.createElement('a'), { href: url, download: name });
    anchor.click(); URL.revokeObjectURL(url);
  }).catch(error => window.alert(error.message));
}

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('pqc_token'));
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mode, setMode] = useState('login');
  const [projects, setProjects] = useState([]);
  const [projectName, setProjectName] = useState('');
  const [description, setDescription] = useState('');
  const [selected, setSelected] = useState('');
  const [repo, setRepo] = useState(null);
  const [archive, setArchive] = useState(null);
  const [assessmentId, setAssessmentId] = useState('');
  const [status, setStatus] = useState(null);
  const [result, setResult] = useState(null);
  const [baselineId, setBaselineId] = useState('');
  const [migratedId, setMigratedId] = useState('');
  const [comparison, setComparison] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const chartData = useMemo(() => Object.entries(result?.cars?.dimensions || {}).map(([name, item]) => ({ name: name.replaceAll('_', ' '), score: item.score })), [result]);

  async function loadProjects() {
    const response = await request('/projects');
    const body = await response.json();
    setProjects(body.projects);
  }

  useEffect(() => { if (token) loadProjects().catch(err => setError(err.message)); }, [token]);

  useEffect(() => {
    if (!assessmentId || ['COMPLETED', 'FAILED'].includes(status?.status)) return;
    const timer = setInterval(async () => {
      try {
        const response = await request(`/assessments/${assessmentId}/status`);
        const body = await response.json(); setStatus(body.assessment);
        if (body.assessment.status === 'COMPLETED') {
          const resultResponse = await request(`/assessments/${assessmentId}/results`);
          setResult(await resultResponse.json());
        }
      } catch (err) { setError(err.message); }
    }, 2000);
    return () => clearInterval(timer);
  }, [assessmentId, status?.status]);

  async function authenticate(event) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      if (mode === 'register') await request('/auth/register', { method: 'POST', body: JSON.stringify({ email, password }) });
      const response = await request('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) });
      const body = await response.json(); localStorage.setItem('pqc_token', body.token); setToken(body.token);
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }

  async function createProject(event) {
    event.preventDefault(); setError('');
    try {
      await request('/projects', { method: 'POST', body: JSON.stringify({ name: projectName, description }) });
      setProjectName(''); setDescription(''); await loadProjects();
    } catch (err) { setError(err.message); }
  }

  async function startAssessment(event) {
    event.preventDefault(); if (!selected || !archive) return;
    setBusy(true); setError(''); setResult(null); setAssessmentId(''); setRepo(null); setComparison(null); setBaselineId(''); setMigratedId(''); setStatus({ status: 'UPLOADING', stage: 'UPLOAD' });
    try {
      const form = new FormData(); form.append('repository', archive);
      const uploaded = await request(`/repositories/upload/${selected}`, { method: 'POST', body: form });
      const repository = (await uploaded.json()).repository;
      setRepo(repository);
      const started = await request('/assessments', { method: 'POST', body: JSON.stringify({ project_id: selected, repository_id: repository.id, scan_label: archive.name }) });
      const assessment = (await started.json()).assessment; setAssessmentId(assessment.id); setStatus(assessment);
    } catch (err) { setError(err.message); setStatus({ status: 'FAILED' }); }
    finally { setBusy(false); }
  }

  async function compareAssessments(event) {
    event.preventDefault(); setError(''); setComparison(null);
    try {
      const response = await request('/validation/compare', { method: 'POST', body: JSON.stringify({ baseline_id: baselineId, migrated_id: migratedId || assessmentId }) });
      setComparison(await response.json());
    } catch (err) { setError(err.message); }
  }

  function signOut() { localStorage.removeItem('pqc_token'); setToken(null); setProjects([]); setAssessmentId(''); setResult(null); setStatus(null); }

  if (!token) return <main className="auth-shell"><section className="auth-card"><div className="eyebrow">CAPSTONE · CRYPTO AGILITY</div><h1>Quantum-safe<br /><span>assessment</span></h1><p className="muted">Inventory cryptographic use and plan a standards-based migration.</p><form onSubmit={authenticate} className="stack"><label>Email<input type="email" value={email} onChange={e => setEmail(e.target.value)} required autoComplete="email" /></label><label>Password<input type="password" value={password} onChange={e => setPassword(e.target.value)} required minLength="12" autoComplete={mode === 'login' ? 'current-password' : 'new-password'} /></label><button disabled={busy}>{busy ? 'Working…' : mode === 'login' ? 'Sign in' : 'Create account'}</button></form><button className="text-button" onClick={() => setMode(mode === 'login' ? 'register' : 'login')}>{mode === 'login' ? 'Create an account' : 'Back to sign in'}</button>{error && <p className="error">{error}</p>}</section></main>;

  return <main className="app-shell">
    <header className="topbar"><div className="brand-mark">Q</div><div className="brand-title">{APP_NAME.toUpperCase()} <span>ASSESSMENT WORKSPACE</span></div><button className="quiet-button" onClick={signOut}>Sign out</button></header>
    <section className="hero"><div><div className="eyebrow">CRYPTOGRAPHIC INVENTORY · MIGRATION READINESS</div><h1>Know what needs<br /><span>to change.</span></h1><p>Scan a repository, review evidence, and build a practical path toward post-quantum cryptography.</p></div><div className="hero-orbit"><div className="orbit-ring ring-one"/><div className="orbit-ring ring-two"/><div className="orbit-core">PQC</div></div></section>
    {error && <div className="notice error">{error}<button className="dismiss" onClick={() => setError('')}>×</button></div>}
    <div className="workspace-grid">
      <section className="panel"><div className="panel-heading"><div><div className="eyebrow">01 · PROJECT</div><h2>Start an assessment</h2></div><span className="step-number">01</span></div>
        <form onSubmit={createProject} className="stack"><label>New project<input value={projectName} onChange={e => setProjectName(e.target.value)} placeholder="Payment platform" required /></label><label>Description <span className="optional">optional</span><textarea value={description} onChange={e => setDescription(e.target.value)} placeholder="What are you assessing?" rows="2" /></label><button className="secondary-button">Create project</button></form>
        <div className="divider"/><form onSubmit={startAssessment} className="stack"><label>Project<select value={selected} onChange={e => setSelected(e.target.value)} required><option value="">Choose a project</option>{projects.map(project => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label><label>Repository archive<input type="file" accept=".zip,application/zip" onChange={e => setArchive(e.target.files?.[0] || null)} required /></label><p className="hint">ZIP only · maximum size is set by the server · repository code is never executed.</p><button disabled={busy || !selected || !archive}>{busy ? 'Submitting…' : 'Upload and scan'}</button></form>
        {status && <div className="status-card"><span className={`status-dot ${status.status?.toLowerCase()}`}/><div><strong>{status.status}</strong><span>{status.stage || status.error_message || 'Assessment queued'}</span></div>{assessmentId && <code title={assessmentId}>{assessmentId}</code>}</div>}
      </section>
      <section className="panel results-panel"><div className="panel-heading"><div><div className="eyebrow">02 · RESULTS</div><h2>Assessment report</h2></div>{result && <div className="download-row"><button className="quiet-button" onClick={() => download(`/reports/${assessmentId}/download`, `assessment-${assessmentId}.json`)}>JSON</button><button className="quiet-button" onClick={() => download(`/reports/${assessmentId}/pdf`, `assessment-${assessmentId}.pdf`)}>PDF</button><button className="quiet-button" onClick={() => download(`/cbom/${assessmentId}/export?format=cyclonedx_json`, `cbom-${assessmentId}.json`)}>CBOM</button></div>}</div>
        {!result ? <div className="empty-state"><div className="empty-icon">⌁</div><h3>Your results appear here</h3><p>Upload a small repository archive to see cryptographic findings, risk factors, and migration guidance.</p></div> : <div className="results-content">
          <div className="metrics"><div><span>FILES SCANNED</span><strong>{result.files_scanned}</strong></div><div><span>FINDINGS</span><strong>{result.findings?.length || 0}</strong></div><div><span>RISK</span><strong>{result.risk?.score}<small>/100</small></strong><em>{result.risk?.category}</em></div><div><span>CARS</span><strong>{result.cars?.score}<small>/100</small></strong><em>Provisional</em></div></div>
          <div className="risk-factors">{Object.entries(result.risk?.factors || {}).map(([name, score]) => <span key={name}>{name.replaceAll('_', ' ')} <b>{score}</b></span>)}</div>
          <div className="chart-wrap"><div className="subheading">Crypto-agility dimensions</div><ResponsiveContainer width="100%" height={190}><BarChart data={chartData} layout="vertical" margin={{ left: 8, right: 22 }}><CartesianGrid stroke="#233248" horizontal={false} /><XAxis type="number" domain={[0, 100]} stroke="#78869b" tick={{ fontSize: 11 }} /><YAxis type="category" dataKey="name" width={145} stroke="#a6b2c4" tick={{ fontSize: 11 }} /><Tooltip contentStyle={{ background: '#101c2c', border: '1px solid #263850', borderRadius: 8 }} /><Bar dataKey="score" fill="#64d5bd" radius={[0, 5, 5, 0]} /></BarChart></ResponsiveContainer></div>
          <div className="subheading">Cryptographic findings</div>{result.findings?.length ? <div className="finding-list">{result.findings.map((finding, index) => <article className="finding" key={`${finding.file_path}-${finding.line_start}-${index}`}><div className="finding-top"><strong>{finding.algorithm}</strong><span>{finding.operation}</span><b>{Math.round(finding.confidence * 100)}% confidence</b></div><code>{finding.file_path}:{finding.line_start}</code><pre>{finding.evidence}</pre>{finding.cwe_ids?.length > 0 && <div className="tags">{finding.cwe_ids.map(cwe => <span key={cwe}>{cwe}</span>)}</div>}</article>)}</div> : <p className="hint">No supported cryptographic API patterns were detected in the scanned Python files.</p>}
          <div className="subheading">Migration recommendations</div>{result.recommendations?.map((recommendation, index) => <div className="recommendation" key={index}><strong>{recommendation.source_algorithm} · {recommendation.operation}</strong><p>{recommendation.recommendation}</p><span>{recommendation.basis}</span></div>)}
          <div className="subheading">Migration complexity decision support</div><div className="recommendation"><strong>{result.ml?.prediction || 'Manual review required'}</strong><p>{result.ml?.reason}</p><span>Model: {result.ml?.model_version || 'not trained'} · Target: {result.ml?.target} · Confidence: {result.ml?.confidence ?? 'n/a'}</span></div>
          <div className="subheading">Benchmark sample</div>{result.benchmarks?.signature_timings?.length ? <div className="benchmark-list">{result.benchmarks.signature_timings.slice(0, 8).map((benchmark, index) => <div className="benchmark-row" key={`${benchmark.source_file}-${benchmark.algorithm}-${benchmark.operation}-${index}`}><strong>{benchmark.algorithm}</strong><span>{benchmark.operation}</span><b>{benchmark.ms_per_op} ms/op</b><small>{benchmark.metadata?.arch || 'platform metadata in report'}</small></div>)}</div> : <p className="hint">No matching signature benchmark rows.</p>}
          <div className="subheading">Migration roadmap</div>{result.migration_roadmap?.length ? result.migration_roadmap.map((task, index) => <div className="recommendation" key={index}><strong>{task.algorithm} · {task.operation}</strong><p>{task.file_path}</p><span>{task.steps.join(' → ')}</span></div>) : <p className="hint">No migration tasks generated because no cryptographic findings were detected.</p>}
          <div className="subheading">Before / after validation</div><form className="compare-form" onSubmit={compareAssessments}><label>Baseline assessment ID<input value={baselineId} onChange={e => setBaselineId(e.target.value)} placeholder="Paste baseline UUID" required /></label><label>Migrated assessment ID<input value={migratedId} onChange={e => setMigratedId(e.target.value)} placeholder={assessmentId || 'Paste migrated UUID'} /></label><button className="secondary-button">Compare assessments</button></form>{comparison && <p className="hint">Resolved: {comparison.resolved.length} · Remaining: {comparison.remaining.length} · New: {comparison.newly_introduced.length}</p>}
          <p className="limitation">Vulnerability correlation: {result.vulnerability_correlation?.status} — {result.vulnerability_correlation?.reason}</p>
          <p className="limitation">{result.benchmark_scope} Risk and CARS values use provisional defaults and require review.</p>
        </div>}
      </section>
    </div>
    <footer>Evidence first · recommendations are suggestions · source archives are never modified or executed</footer>
  </main>;
}
