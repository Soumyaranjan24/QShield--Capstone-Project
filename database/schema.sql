CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(150),
  role VARCHAR(50) NOT NULL DEFAULT 'security_analyst',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS projects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  repository_type VARCHAR(50) NOT NULL DEFAULT 'zip_upload',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS repositories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  stored_name VARCHAR(255) NOT NULL,
  original_name VARCHAR(255) NOT NULL,
  sha256 CHAR(64) NOT NULL,
  size_bytes BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS assessments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  scan_label VARCHAR(100) NOT NULL,
  status VARCHAR(30) NOT NULL DEFAULT 'QUEUED',
  stage VARCHAR(40) NOT NULL DEFAULT 'QUEUED',
  error_message TEXT,
  files_scanned INTEGER NOT NULL DEFAULT 0,
  findings_count INTEGER NOT NULL DEFAULT 0,
  overall_risk_score NUMERIC(5,2),
  cars_score NUMERIC(5,2),
  result_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS cryptographic_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  file_path VARCHAR(1000) NOT NULL,
  line_start INTEGER,
  line_end INTEGER,
  detected_algorithm VARCHAR(100) NOT NULL,
  operation_type VARCHAR(100) NOT NULL,
  purpose VARCHAR(100),
  library_name VARCHAR(150),
  key_size_bits INTEGER,
  detection_method VARCHAR(100) NOT NULL,
  confidence NUMERIC(4,3) NOT NULL,
  evidence JSONB NOT NULL,
  cwe_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  quantum_threat_type VARCHAR(50),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cwe_records (
  cwe_id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  abstraction TEXT,
  status TEXT,
  description TEXT,
  extended_description TEXT,
  potential_mitigations TEXT,
  source_version TEXT NOT NULL DEFAULT 'CWE View 1000 CSV'
);

CREATE TABLE IF NOT EXISTS kev_records (
  cve_id TEXT PRIMARY KEY,
  vendor_project TEXT,
  product TEXT,
  vulnerability_name TEXT,
  date_added DATE,
  required_action TEXT,
  cwes JSONB NOT NULL DEFAULT '[]'::jsonb,
  source_version TEXT NOT NULL DEFAULT 'CISA KEV local snapshot'
);

CREATE TABLE IF NOT EXISTS cvefixes_crypto_examples (
  id BIGSERIAL PRIMARY KEY,
  source_key CHAR(64) NOT NULL UNIQUE,
  cve_id TEXT NOT NULL,
  cwe_id TEXT NOT NULL,
  commit_hash TEXT,
  repository_url TEXT,
  filename TEXT,
  programming_language TEXT,
  patch_json JSONB NOT NULL,
  source_version TEXT NOT NULL DEFAULT 'CVEfixes v1.0.0'
);

CREATE TABLE IF NOT EXISTS benchmark_results (
  id BIGSERIAL PRIMARY KEY,
  algorithm TEXT NOT NULL,
  operation TEXT NOT NULL,
  ms_per_op DOUBLE PRECISION,
  ops_per_sec DOUBLE PRECISION,
  iterations BIGINT,
  public_key_bytes INTEGER,
  secret_key_bytes INTEGER,
  signature_bytes INTEGER,
  platform_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  source_file TEXT NOT NULL,
  source_version TEXT NOT NULL DEFAULT 'pqc-sig-bench-c snapshot',
  UNIQUE(source_file, algorithm, operation)
);

CREATE INDEX IF NOT EXISTS idx_projects_user ON projects(user_id);
CREATE INDEX IF NOT EXISTS idx_assessments_project ON assessments(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_assessment ON cryptographic_findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_kev_vendor_product ON kev_records(vendor_project, product);
CREATE INDEX IF NOT EXISTS idx_cvefixes_cwe ON cvefixes_crypto_examples(cwe_id);
CREATE INDEX IF NOT EXISTS idx_benchmark_algorithm ON benchmark_results(algorithm, operation);
