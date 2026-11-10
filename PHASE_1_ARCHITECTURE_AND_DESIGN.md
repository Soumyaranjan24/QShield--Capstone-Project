# PHASE 1: SYSTEM ARCHITECTURE, DATABASE DESIGN & SPECIFICATION BLUEPRINT

**Project Title:** AI-Driven Quantum-Safe Cryptography Assessment and Migration Assistant  
**Author / Role:** Lead System Architect, Cybersecurity Researcher, and Full-Stack Engineer  
**Stage:** Phase 1 Design & Architectural Review (Approval Gate)

---

## A. Project Understanding & Academic Defense Context

### 1. The Core Problem: The Post-Quantum Threat Model
Modern digital infrastructure relies heavily on asymmetric public-key cryptography (e.g., **RSA**, **ECC**, **ECDSA**, **ECDH**, and **Diffie-Hellman**) to establish trust, exchange symmetric session keys, and generate non-repudiable digital signatures. 

- **Shor's Algorithm (1994):** When executed on a Cryptanalytically Relevant Quantum Computer (CRQC), Shor's algorithm solves the integer factorization problem and the discrete logarithm problem in polynomial time $\mathcal{O}((\log N)^3)$. Consequently, **all classical public-key cryptography will be completely broken** once sufficiently large fault-tolerant quantum computers exist.
- **Grover's Algorithm (1996):** In contrast, Grover's algorithm provides a quadratic speedup for unstructured search, reducing the brute-force security of symmetric ciphers and hash functions from $N$ to $\sqrt{N}$ (e.g., AES-128 becomes equivalent to 64-bit security; AES-256 remains at an effective 128-bit quantum security level). Therefore, **symmetric algorithms like AES-256 do NOT need immediate structural replacement, but key lengths must be evaluated.**
- **The "Harvest Now, Decrypt Later" (HNDL) Threat:** Adversaries and nation-states are actively capturing encrypted data in transit today. Once a CRQC becomes viable, recorded sensitive data (intellectual property, national secrets, medical records, financial keys) will be decrypted retroactively.

### 2. Platform Purpose & Scope
This platform is **not** a generic vulnerability scanner or simple linting tool. It is an end-to-end **post-quantum cryptography assessment, crypto-agility audit, and migration validation platform** designed to:
1. Parse multi-language source repositories without executing code.
2. Extract cryptographic implementations and configurations via AST analysis, regex pattern matching, and dependency inspection.
3. Generate a standardized **Cryptographic Bill of Materials (CBOM)** aligned with CycloneDX standards.
4. Distinguish clearly between **conventional software weaknesses (CWE/CVE)** and **quantum-computational vulnerabilities**.
5. Calculate a transparent, explainable **Crypto-Agility Readiness Score (CARS)** across 5 operational dimensions.
6. Formulate precise, NIST-compliant migration recommendations (**FIPS 203 ML-KEM**, **FIPS 204 ML-DSA**, **FIPS 205 SLH-DSA**) based on actual cryptographic usage context.
7. Benchmark performance trade-offs (key sizes, latency, memory) using validated empirical benchmark datasets.
8. Validate code refactoring and migration changes via before-and-after regression diffing.

---

## B. Detailed System Architecture

The system is structured as a **Microservices / Decoupled Service-Oriented Architecture (SOA)** consisting of:
1. **React Frontend (Presentation Tier):** Vite + React + Tailwind CSS + Recharts + Framer Motion. Provides dashboards, interactive CBOM exploration, CARS breakdowns, benchmark comparison charts, and report generation.
2. **Node.js / Express API Gateway & Orchestrator (Application Management Tier):** Manages user authentication (Argon2id + JWT), RBAC, project management, file uploads, scan job dispatching, and report downloads.
3. **Python / FastAPI Analysis Engine (Deep Analysis & Data Science Tier):** Dedicated computation engine running AST parsers (Python AST, structured parsers for Java, C/C++, JS), regex pattern extractors, dependency parsers, quantum risk scoring, CARS calculation, and dataset integration.
4. **PostgreSQL Database (Data Persistence Tier):** Normalized relational database with JSONB support for rich evidence data, storing all users, projects, scans, CBOM records, CWE/CVE mappings, KEV catalogs, benchmarks, and validation logs.
5. **Worker / Task Queue Manager (Asynchronous Processing):** Uses background task processing (via FastAPI BackgroundTasks / BullMQ / Celery worker model) to isolate file extraction and repository scanning from real-time HTTP threads.

```mermaid
flowchart TD
    subgraph ClientTier ["Client Tier (Browser)"]
        UI["React.js Frontend (Vite + Tailwind CSS + Recharts)"]
    end

    subgraph GatewayTier ["Orchestration Tier (Node.js / Express)"]
        GW["Express API Gateway"]
        AuthM["Auth & RBAC (Argon2id + JWT)"]
        ProjM["Project & Repo File Manager"]
        JobOrch["Scan Orchestrator & Poller"]
        RepGen["Report Controller (PDF / JSON / CSV)"]
    end

    subgraph AnalysisTier ["Analysis Tier (Python / FastAPI)"]
        FastAPI["FastAPI Discovery & Risk Engine"]
        SafeExtract["Safe Archive Extractor & Sanitizer"]
        
        subgraph DiscoveryEngines ["Cryptographic Discovery Subsystem"]
            ASTParser["AST Analyzer (Python, Java, JS, C/C++)"]
            RegexEngine["Pattern & API Detector"]
            DepParser["Dependency & Lockfile Inspector"]
            ConfigParser["TLS & Config Analyzer"]
        end

        subgraph IntelligenceEngines ["Evaluation & Intelligence Subsystem"]
            CBOMGen["CBOM Generator (CycloneDX spec)"]
            CWEMapper["MITRE CWE-1000 Mapper"]
            VulnMatcher["CVE / CISA KEV Correlator"]
            QuantumEngine["Quantum Risk Calculator (Shor vs Grover)"]
            CARSEngine["CARS Readiness Calculator (5 Dimensions)"]
            PQCEngine["NIST PQC Recommender (FIPS 203, 204, 205)"]
            BenchEngine["PQC Benchmark Engine (Kaggle PQC Dataset)"]
            DiffEngine["Migration Validation & Diffing"]
        end
    end

    subgraph DataTier ["Persistence Tier (PostgreSQL 15+)"]
        DB[("PostgreSQL Database")]
        T_Users["users / audit_logs"]
        T_Projects["projects / repositories / scan_jobs"]
        T_Findings["cryptographic_findings / cbom_components"]
        T_Ref["cwe_records / cve_records / kev_records"]
        T_Metrics["risk_assessments / cars_assessments"]
        T_PQC["pqc_algorithms / benchmark_results"]
    end

    UI -->|"HTTPS / REST / JWT"| GW
    GW --> AuthM
    GW --> ProjM
    GW --> JobOrch
    GW --> RepGen

    ProjM -->|"Save Archive / Unpack to Temp Sandbox"| SafeExtract
    JobOrch -->|"Dispatch Scan (POST /api/analyzer/scan)"| FastAPI
    
    FastAPI --> SafeExtract
    SafeExtract --> ASTParser
    SafeExtract --> RegexEngine
    SafeExtract --> DepParser
    SafeExtract --> ConfigParser

    ASTParser & RegexEngine & DepParser & ConfigParser --> CBOMGen
    CBOMGen --> CWEMapper
    CWEMapper --> VulnMatcher
    VulnMatcher --> QuantumEngine
    QuantumEngine --> CARSEngine
    CARSEngine --> PQCEngine
    PQCEngine --> BenchEngine
    BenchEngine --> DiffEngine

    FastAPI -->|"Persist Findings & Evidence"| DB
    GW -->|"Query Results, Aggregates & Users"| DB
```

### Why This Architecture? (Viva Defense Explanation)
- **Separation of Concerns:** Node.js excels at asynchronous I/O, event-driven gateway routing, and auth workflows. Python is the premier standard for AST code parsing, data science, matrix mathematics (Pandas/NumPy), and ML modeling. Coupling them via clear REST contracts keeps both services lightweight, independently testable, and robust.
- **Fail-Safe Execution:** Source code analysis can be CPU-intensive. By running the Python engine as an isolated microservice, an analysis crash or timeout on a corrupted file never crashes the web gateway or disconnects active users.

---

## C. Complete Folder Structure

```
d:\Projects\QCM\
├── .gitignore
├── docker-compose.yml
├── README.md
├── prompt.txt                            # Master Project Specification
├── PHASE_1_ARCHITECTURE_AND_DESIGN.md     # Phase 1 Architectural Blueprint
│
├── backend/                               # Node.js / Express Gateway
│   ├── package.json
│   ├── .env.example
│   ├── server.js                         # Server entry point
│   ├── src/
│   │   ├── config/                       # DB, JWT, environment configurations
│   │   │   ├── db.js
│   │   │   └── security.js
│   │   ├── controllers/                  # Request controllers
│   │   │   ├── authController.js
│   │   │   ├── projectController.js
│   │   │   ├── assessmentController.js
│   │   │   ├── reportController.js
│   │   │   └── validationController.js
│   │   ├── middleware/                   # Express middlewares
│   │   │   ├── authMiddleware.js
│   │   │   ├── uploadMiddleware.js       # Safe archive upload validator
│   │   │   ├── rateLimiter.js
│   │   │   └── errorHandler.js
│   │   ├── routes/                       # Express route definitions
│   │   │   ├── authRoutes.js
│   │   │   ├── projectRoutes.js
│   │   │   ├── assessmentRoutes.js
│   │   │   ├── reportRoutes.js
│   │   │   └── validationRoutes.js
│   │   ├── services/                     # Business logic & Python bridge
│   │   │   ├── pythonAnalyzerClient.js   # HTTP client communicating with Python service
│   │   │   └── pdfReportGenerator.js     # PDF report generation
│   │   └── utils/
│   │       ├── logger.js
│   │       └── sanitize.js
│   └── tests/                            # Gateway integration & unit tests
│       ├── auth.test.js
│       └── projects.test.js
│
├── analyzer/                              # Python / FastAPI Analysis Engine
│   ├── pyproject.toml / requirements.txt
│   ├── Dockerfile
│   ├── main.py                           # FastAPI application entrypoint
│   ├── app/
│   │   ├── api/                          # FastAPI route endpoints
│   │   │   ├── scan_routes.py
│   │   │   ├── cbom_routes.py
│   │   │   ├── risk_routes.py
│   │   │   ├── cars_routes.py
│   │   │   ├── pqc_routes.py
│   │   │   └── benchmark_routes.py
│   │   ├── core/                         # Config, database session, security utils
│   │   │   ├── config.py
│   │   │   ├── database.py
│   │   │   └── safe_unpack.py            # ZIP-slip, symlink, & bomb defense
│   │   ├── models/                       # SQLAlchemy ORM models
│   │   │   ├── base.py
│   │   │   ├── findings.py
│   │   │   ├── cbom.py
│   │   │   ├── cwe_cve.py
│   │   │   └── metrics.py
│   │   ├── schemas/                      # Pydantic validation schemas
│   │   │   ├── scan_schema.py
│   │   │   ├── finding_schema.py
│   │   │   └── cbom_schema.py
│   │   ├── services/                     # Core analysis logic
│   │   │   ├── discovery/                # Module 3: Discovery Engine
│   │   │   │   ├── ast_python.py         # Python AST visitor
│   │   │   │   ├── ast_java.py           # Java syntax parser
│   │   │   │   ├── ast_javascript.py     # JS/TS syntax parser
│   │   │   │   ├── regex_patterns.py     # Multi-language pattern matching
│   │   │   │   ├── dependency_parser.py  # Manifest/Lockfile parser
│   │   │   │   └── config_parser.py      # TLS, certs, and config detector
│   │   │   ├── cbom/                     # Module 4: CBOM Generator
│   │   │   │   ├── cbom_builder.py
│   │   │   │   └── cyclonedx_exporter.py # CycloneDX 1.6 / CBOM JSON format
│   │   │   ├── intelligence/             # Modules 5 & 6: CWE, CVE & KEV
│   │   │   │   ├── cwe_mapper.py
│   │   │   │   └── kev_correlator.py
│   │   │   ├── risk/                     # Modules 7, 8, 9: Quantum Risk & CARS
│   │   │   │   ├── quantum_risk.py       # Shor vs. Grover exposure model
│   │   │   │   ├── risk_prioritizer.py   # Configurable weighted risk formula
│   │   │   │   └── cars_calculator.py    # 5-dimensional CARS evaluator
│   │   │   ├── pqc/                      # Module 10: Recommendation Engine
│   │   │   │   ├── nist_standards.py     # FIPS 203, 204, 205 knowledge base
│   │   │   │   └── recommender.py        # Purpose-aware algorithm mapping
│   │   │   ├── benchmark/                # Module 11: Benchmark Engine
│   │   │   │   ├── dataset_loader.py     # Kaggle PQC loader & validator
│   │   │   │   └── comparator.py         # Key sizes, cycle count, memory metrics
│   │   │   ├── ml/                       # Module 12: AI/ML Classifier
│   │   │   │   ├── feature_extractor.py
│   │   │   │   ├── train.py
│   │   │   │   └── classifier.py         # Pattern & complexity estimation
│   │   │   └── validation/               # Module 14: Migration Validation
│   │   │       └── diff_engine.py        # Before-and-after cryptographic diff
│   │   └── utils/
│   │       ├── secret_redactor.py        # Strips credentials, API keys, private keys
│   │       └── logger.py
│   └── tests/
│       ├── test_ast_python.py
│       ├── test_cbom.py
│       ├── test_quantum_risk.py
│       └── test_cars.py
│
├── frontend/                              # React + Vite Dashboard
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   ├── index.html
│   ├── src/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   ├── api/                          # Axios API clients
│   │   │   ├── client.js
│   │   │   ├── authApi.js
│   │   │   ├── projectApi.js
│   │   │   └── assessmentApi.js
│   │   ├── components/                   # Reusable UI components
│   │   │   ├── common/Navbar.jsx
│   │   │   ├── common/Sidebar.jsx
│   │   │   ├── common/Badge.jsx
│   │   │   ├── common/Modal.jsx
│   │   │   └── charts/                   # Recharts visualizations
│   │   │       ├── CarsRadarChart.jsx
│   │   │       ├── RiskDistributionPie.jsx
│   │   │       └── BenchmarkBarChart.jsx
│   │   ├── pages/                        # 18 Dashboard Pages
│   │   │   ├── LoginPage.jsx
│   │   │   ├── RegisterPage.jsx
│   │   │   ├── DashboardPage.jsx
│   │   │   ├── ProjectsPage.jsx
│   │   │   ├── ProjectDetailPage.jsx
│   │   │   ├── UploadPage.jsx
│   │   │   ├── ScanProgressPage.jsx
│   │   │   ├── CbomExplorerPage.jsx
│   │   │   ├── FindingsPage.jsx
│   │   │   ├── CweExplorerPage.jsx
│   │   │   ├── QuantumRiskPage.jsx
│   │   │   ├── CarsReadinessPage.jsx
│   │   │   ├── PqcRecommendationsPage.jsx
│   │   │   ├── BenchmarkComparisonPage.jsx
│   │   │   ├── MigrationRoadmapPage.jsx
│   │   │   ├── MigrationValidationPage.jsx
│   │   │   ├── ReportsPage.jsx
│   │   │   └── SettingsPage.jsx
│   │   └── context/                      # React Auth & Theme Context
│   │       └── AuthContext.jsx
│   └── tests/
│       └── App.test.jsx
│
├── datasets/                              # External Reference Datasets
│   ├── cwe/                              # MITRE CWE-1000 CSV
│   │   └── 1000.csv
│   ├── cvefixes/                         # Filtered crypto subset of CVEfixes
│   │   └── crypto_cvefixes_v1.0.0.json
│   ├── kev/                              # CISA Known Exploited Vulnerabilities (Already in datasets/)
│   │   └── known_exploited_vulnerabilities.csv
│   └── pqc_benchmarks/                   # Kaggle PQC benchmark dataset
│       └── pqc_benchmark_data.csv
│
├── test-repos/                            # Standardized Test Fixtures
│   ├── sample-python-rsa-aes/            # Small test repo 1 (Classical vulnerable)
│   ├── sample-java-tls-signatures/       # Small test repo 2 (Certificates & ECDSA)
│   ├── sample-js-crypto-web/             # Small test repo 3 (SubtleCrypto & Node crypto)
│   └── sample-pqc-hybrid/                # Small test repo 4 (Post-quantum ML-KEM refactored)
│
└── migrations/                            # PostgreSQL DB Migrations (SQL / Flyway / Alembic)
    ├── 001_initial_schema.sql
    ├── 002_cwe_cve_indexes.sql
    └── 003_pqc_benchmarks.sql
```

---

## D. Database ER Diagram & Normalized Schema

### Entity-Relationship Diagram (Mermaid)

```mermaid
erDiagram
    USERS ||--o{ AUDIT_LOGS : performs
    USERS ||--o{ PROJECTS : owns
    PROJECTS ||--o{ REPOSITORIES : contains
    PROJECTS ||--o{ ASSESSMENTS : evaluates
    REPOSITORIES ||--o{ SCANNED_FILES : contains
    ASSESSMENTS ||--o{ SCAN_JOBS : executes
    ASSESSMENTS ||--o{ CRYPTOGRAPHIC_FINDINGS : discovers
    ASSESSMENTS ||--o{ CBOM_COMPONENTS : inventories
    ASSESSMENTS ||--|| RISK_ASSESSMENTS : yields
    ASSESSMENTS ||--|| CARS_ASSESSMENTS : calculates
    CARS_ASSESSMENTS ||--|{ CARS_DIMENSIONS : details
    ASSESSMENTS ||--o{ MIGRATION_RECOMMENDATIONS : generates
    MIGRATION_RECOMMENDATIONS ||--o{ MIGRATION_TASKS : decomposes_into
    ASSESSMENTS ||--o{ VALIDATION_RESULTS : validates
    ASSESSMENTS ||--o{ REPORTS : publishes

    CWE_RECORDS ||--o{ CRYPTOGRAPHIC_FINDINGS : maps_to
    CVE_RECORDS ||--o{ CRYPTOGRAPHIC_FINDINGS : correlates_with
    KEV_RECORDS ||--o{ CVE_RECORDS : flags_exploitation
    PQC_ALGORITHMS ||--o{ MIGRATION_RECOMMENDATIONS : prescribes
    PQC_ALGORITHMS ||--o{ BENCHMARK_RESULTS : benchmarks

    USERS {
        uuid id PK
        varchar email UK
        varchar password_hash
        varchar full_name
        varchar role
        timestamp created_at
    }

    PROJECTS {
        uuid id PK
        uuid user_id FK
        varchar name
        text description
        varchar primary_language
        timestamp created_at
    }

    ASSESSMENTS {
        uuid id PK
        uuid project_id FK
        varchar version_tag
        varchar status
        float overall_risk_score
        float cars_score
        timestamp completed_at
    }

    CRYPTOGRAPHIC_FINDINGS {
        uuid id PK
        uuid assessment_id FK
        varchar file_path
        integer line_start
        integer line_end
        varchar detected_algorithm
        varchar operation_type
        varchar library_name
        integer key_size_bits
        varchar detection_method
        varchar confidence_level
        jsonb code_evidence
        varchar cwe_id FK
        varchar quantum_exposure_level
    }

    CBOM_COMPONENTS {
        uuid id PK
        uuid assessment_id FK
        varchar bom_ref UK
        varchar component_name
        varchar algorithm_name
        varchar cryptographic_function
        varchar library_version
        integer key_length
        varchar quantum_risk_class
        jsonb properties
    }

    CARS_ASSESSMENTS {
        uuid id PK
        uuid assessment_id FK
        float total_cars_score
        float inventory_completeness_score
        float algorithm_compliance_score
        float architectural_decoupling_score
        float toolchain_readiness_score
        float governance_alignment_score
        jsonb dimension_breakdown
    }

    MIGRATION_RECOMMENDATIONS {
        uuid id PK
        uuid assessment_id FK
        uuid finding_id FK
        varchar classical_algorithm
        varchar recommended_pqc_standard
        varchar recommended_algorithm
        text rationale
        varchar migration_strategy
        varchar estimated_complexity
    }
```

### Table Definitions & Constraints

1. **`users`**:
   - `id` UUID PRIMARY KEY DEFAULT gen_random_uuid(),
   - `email` VARCHAR(255) UNIQUE NOT NULL,
   - `password_hash` VARCHAR(255) NOT NULL (Argon2id),
   - `full_name` VARCHAR(150),
   - `role` VARCHAR(50) DEFAULT 'security_analyst',
   - `created_at` TIMESTAMPTZ DEFAULT NOW(),
   - `updated_at` TIMESTAMPTZ DEFAULT NOW()

2. **`projects`**:
   - `id` UUID PRIMARY KEY DEFAULT gen_random_uuid(),
   - `user_id` UUID REFERENCES users(id) ON DELETE CASCADE,
   - `name` VARCHAR(255) NOT NULL,
   - `description` TEXT,
   - `repository_type` VARCHAR(50) NOT NULL ('zip_upload', 'git_url'),
   - `primary_language` VARCHAR(50),
   - `created_at` TIMESTAMPTZ DEFAULT NOW(),
   - `updated_at` TIMESTAMPTZ DEFAULT NOW()

3. **`assessments`**:
   - `id` UUID PRIMARY KEY DEFAULT gen_random_uuid(),
   - `project_id` UUID REFERENCES projects(id) ON DELETE CASCADE,
   - `scan_label` VARCHAR(100) NOT NULL,
   - `status` VARCHAR(50) NOT NULL ('QUEUED', 'SCANNING', 'COMPUTING_RISK', 'COMPLETED', 'FAILED'),
   - `error_message` TEXT,
   - `files_scanned` INT DEFAULT 0,
   - `findings_count` INT DEFAULT 0,
   - `overall_risk_score` NUMERIC(5,2),
   - `cars_score` NUMERIC(5,2),
   - `started_at` TIMESTAMPTZ DEFAULT NOW(),
   - `completed_at` TIMESTAMPTZ

4. **`cryptographic_findings`**:
   - `id` UUID PRIMARY KEY DEFAULT gen_random_uuid(),
   - `assessment_id` UUID REFERENCES assessments(id) ON DELETE CASCADE,
   - `file_path` VARCHAR(500) NOT NULL,
   - `line_start` INT,
   - `line_end` INT,
   - `detected_algorithm` VARCHAR(100) NOT NULL,
   - `operation_type` VARCHAR(100) NOT NULL,
   - `library_name` VARCHAR(150),
   - `key_size_bits` INT,
   - `detection_method` VARCHAR(50) NOT NULL,
   - `confidence_level` VARCHAR(50) NOT NULL,
   - `cwe_id` VARCHAR(50),
   - `quantum_vulnerable` BOOLEAN NOT NULL,
   - `quantum_threat_type` VARCHAR(50),
   - `code_evidence` JSONB NOT NULL,
   - `created_at` TIMESTAMPTZ DEFAULT NOW()

5. **`cbom_components`** (CycloneDX 1.6 Cryptographic BOM alignment):
   - `id` UUID PRIMARY KEY DEFAULT gen_random_uuid(),
   - `assessment_id` UUID REFERENCES assessments(id) ON DELETE CASCADE,
   - `bom_ref` VARCHAR(255) NOT NULL,
   - `name` VARCHAR(255) NOT NULL,
   - `algorithm_name` VARCHAR(100) NOT NULL,
   - `crypto_function` VARCHAR(100) NOT NULL,
   - `implementation_library` VARCHAR(200),
   - `key_size` INT,
   - `classical_security_level` INT,
   - `quantum_security_level` INT,
   - `protocol` VARCHAR(100),
   - `evidence_json` JSONB NOT NULL

6. **`cwe_records`** (MITRE CWE-1000):
   - `cwe_id` VARCHAR(50) PRIMARY KEY,
   - `name` VARCHAR(255) NOT NULL,
   - `weakness_abstraction` VARCHAR(50),
   - `status` VARCHAR(50),
   - `description` TEXT NOT NULL,
   - `extended_description` TEXT,
   - `applicable_platforms` TEXT,
   - `background_details` TEXT,
   - `potential_mitigations` JSONB

7. **`cve_records`** & **`kev_records`**:
   - `cve_id` VARCHAR(100) PRIMARY KEY,
   - `cwe_id` VARCHAR(50) REFERENCES cwe_records(cwe_id),
   - `vendor_project` VARCHAR(150),
   - `product` VARCHAR(150),
   - `vulnerability_name` TEXT,
   - `is_known_exploited` BOOLEAN DEFAULT FALSE,
   - `cisa_date_added` DATE,
   - `required_action` TEXT,
   - `notes` TEXT

8. **`risk_assessments`**:
   - `id` UUID PRIMARY KEY DEFAULT gen_random_uuid(),
   - `assessment_id` UUID UNIQUE REFERENCES assessments(id) ON DELETE CASCADE,
   - `quantum_exposure_factor` NUMERIC(5,2) NOT NULL,
   - `data_sensitivity_factor` NUMERIC(5,2) NOT NULL,
   - `system_exposure_factor` NUMERIC(5,2) NOT NULL,
   - `confidentiality_lifetime_factor` NUMERIC(5,2) NOT NULL,
   - `business_criticality_factor` NUMERIC(5,2) NOT NULL,
   - `composite_risk_score` NUMERIC(5,2) NOT NULL,
   - `risk_category` VARCHAR(50) NOT NULL

9. **`cars_assessments`** & **`cars_dimensions`**:
   - Stores the 5 dimensions of Crypto-Agility:
     1. Inventory Completeness ($0-100$)
     2. Algorithm Compliance ($0-100$)
     3. Architectural Decoupling ($0-100$)
     4. Toolchain Readiness ($0-100$)
     5. Governance Alignment ($0-100$)
   - Calculates overall $CARS = \sum_{i=1}^{5} (w_i \times d_i)$, where $\sum w_i = 1.0$.

10. **`pqc_algorithms`** & **`benchmark_results`**:
    - Stores standardized NIST algorithms:
      - ML-KEM (Kyber-512, Kyber-768, Kyber-1024) [FIPS 203]
      - ML-DSA (Dilithium-2, Dilithium-3, Dilithium-5) [FIPS 204]
      - SLH-DSA (SPHINCS+) [FIPS 205]
    - Benchmark table stores: Keygen cycles, encapsulation/signing cycles, decapsulation/verification cycles, public key size (bytes), ciphertext/signature size (bytes), memory footprint (KB), hardware platform notes.

11. **`migration_recommendations`** & **`migration_tasks`**:
    - Stores structured, stepwise tasks mapping every detected classical algorithm to its valid PQC replacement, estimated refactoring complexity, dependency prerequisites, and validation criteria.

---

## E. Module-by-Module Implementation Plan

| Module | Name | Core Objective | Key Logic & Technology | Academic / Viva Defense Concept |
| :--- | :--- | :--- | :--- | :--- |
| **Module 1** | Auth & Project Management | Secure multi-tenant access, user & project state | Argon2id hashing, JWT access tokens, role-based checks, Express middleware | Password security best practices; avoiding plain MD5/SHA or vulnerable PBKDF2 configurations |
| **Module 2** | Secure Repo Upload & Storage | Safely receive, extract, and index codebase files | File magic-byte checks, zip bomb defense (expansion ratio $< 100$), path traversal prevention (`..`), temp directory sandbox | Defense-in-depth against malicious archive payloads and remote code execution |
| **Module 3** | Automated Cryptographic Discovery | Accurately detect crypto without false pattern hits | Multi-layer detection: Python AST visitor + Java/JS regex-parser + dependency manifest parser + TLS config parser | Why AST (syntax tree) is superior to naive grep: AST understands variable scopes, method invocations, and actual cryptographic function arguments |
| **Module 4** | Cryptographic Bill of Materials (CBOM) | Comprehensive, standardized machine-readable inventory | CycloneDX 1.6 Cryptographic extensions, JSON/CSV export, structured schema validation | Explain how modern supply chain security mandates transparency (Executive Order 14028) through SBOM/CBOM |
| **Module 5** | MITRE CWE Weakness Mapping | Correlate findings to recognized security weaknesses | Local indexing of CWE-1000 CSV; mapping to CWE-326 (Inadequate strength), CWE-327 (Broken algorithm), CWE-780 (RSA no OAEP) | Explaining the distinction between generic software bugs and architectural cryptographic weaknesses |
| **Module 6** | CVE & Vulnerability Intelligence | Identify known vulnerabilities and in-the-wild exploitation | Integration of CISA KEV and CVEfixes crypto slice; exact product-version and CVE cross-referencing | KEV indicates active weaponization today; quantum vulnerability indicates future cryptographic collapse |
| **Module 7** | Quantum Risk Assessment Engine | Rigorously classify risk based on quantum physics theory | Categorize algorithms by vulnerability to Shor's (factoring/DLP: total break) vs. Grover's (quadratic search: double key size) | Defending why AES-256 is NOT broken by quantum computers, whereas RSA-4096 is broken regardless of key size |
| **Module 8** | Risk Prioritization Engine | Objective scoring combining technical and business risk | Configurable weighted formula: $0.30 Q + 0.25 S + 0.20 E + 0.15 L + 0.10 C$ | Defending transparent mathematical formulas over opaque "black box" numbers for regulatory explainability |
| **Module 9** | Crypto-Agility Readiness Score (CARS) | Quantify organization's ability to migrate seamlessly | 5 dimensions (Inventory, Compliance, Decoupling, Toolchain, Governance); $0-100$ index | Defining Crypto-Agility: the architectural capacity to swap cryptographic primitives without rewriting business applications |
| **Module 10** | Post-Quantum Recommendation Engine | Prescribe NIST-standardized replacements | Purpose-based mapping: KEM (ML-KEM) vs. Signatures (ML-DSA, SLH-DSA). Explains hybrid schemes (X25519 + ML-KEM-768) | Understanding FIPS 203, 204, 205; avoiding the naive mistake of replacing RSA encryption with ML-DSA |
| **Module 11** | PQC Performance Benchmark Engine | Evaluate operational trade-offs of PQC migration | Kaggle PQC benchmark dataset parsing, comparing key sizes (e.g., Dilithium public key is ~1312 bytes vs. RSA's 256 bytes) | The engineering cost of PQC: larger network packets, TLS fragmentation, memory constraints in embedded systems |
| **Module 12** | AI/ML Decision Support | Assist in classification and complexity estimation | Scikit-learn (Random Forest / Logistic Regression) trained on extractable AST & finding features with clear train/test split | Defending ML boundaries: using ML for classification assistance, never for hallucinating security determinations |
| **Module 13** | Migration Roadmap Generator | Step-by-step phased transition plan | Dependency ordering of migration tasks from low-risk leaf modules to core authentication & transport layers | Phased migration lifecycle: discovery $\rightarrow$ dual-mode/hybrid $\rightarrow$ full PQC $\rightarrow$ deprecation of classical |
| **Module 14** | Migration Validation & Diffing | Verify that remediation eliminated quantum risks | Before-and-after AST diffing, detecting introduced regressions or remaining legacy cryptographic primitives | Proving that a fix actually occurred rather than just renaming variables or deleting comments |

---

## F. Complete API Communication Flow & Endpoint Specifications

### Gateway Authentication & Projects (Node.js / Express)

- **`POST /api/auth/register`**
  - *Body:* `{ "email": "analyst@org.com", "password": "StrongPassword123!", "full_name": "Alice Smith" }`
  - *Response (201):* `{ "status": "success", "user": { "id": "...", "email": "...", "role": "security_analyst" } }`
- **`POST /api/auth/login`**
  - *Body:* `{ "email": "analyst@org.com", "password": "StrongPassword123!" }`
  - *Response (200):* `{ "status": "success", "token": "jwt_token_here", "user": { "id": "...", "email": "..." } }`
- **`GET /api/projects`**
  - *Headers:* `Authorization: Bearer <jwt>`
  - *Response (200):* `[ { "id": "...", "name": "Payment Gateway", "primary_language": "Python", "assessments_count": 2 } ]`
- **`POST /api/projects`**
  - *Headers:* `Authorization: Bearer <jwt>`
  - *Body:* `{ "name": "Auth Service", "description": "Core identity broker", "primary_language": "Java" }`
  - *Response (201):* `{ "id": "...", "name": "Auth Service", "status": "created" }`
- **`POST /api/repositories/upload/:projectId`**
  - *Headers:* `Authorization: Bearer <jwt>`, `Content-Type: multipart/form-data`
  - *Payload:* `file: <zip archive>`
  - *Response (202):* `{ "repository_id": "...", "status": "UPLOADED", "file_count": 42 }`

### Assessment Orchestration (Node.js $\leftrightarrow$ Python FastAPI)

- **`POST /api/assessments`**
  - *Headers:* `Authorization: Bearer <jwt>`
  - *Body:* `{ "project_id": "uuid", "scan_label": "v1.0.0-PreMigration" }`
  - *Gateway Action:* Validates project ownership, creates assessment record in DB with status `QUEUED`, calls Python FastAPI `POST /api/analyzer/scan`.
  - *Response (202):* `{ "assessment_id": "uuid", "status": "QUEUED" }`
- **`GET /api/assessments/:id/status`**
  - *Response (200):* `{ "assessment_id": "...", "status": "SCANNING", "progress_percentage": 65, "current_stage": "CBOM_GENERATION" }`
- **`GET /api/assessments/:id/findings`**
  - *Response (200):* Returns paginated cryptographic findings with complete code evidence, line numbers, detection method, and Shor/Grover risk classification.

### Deep Analysis & Analytics (Python / FastAPI)

- **`POST /api/analyzer/scan`**
  - *Body:* `{ "assessment_id": "uuid", "repo_path": "/safe_storage/project_123" }`
  - *Internal Flow:*
    1. Extracts and audits file manifest safely.
    2. Runs AST Visitors (Python, Java, JS).
    3. Runs Pattern Matching on C/C++ and configuration files.
    4. Generates CBOM components.
    5. Maps CWEs and queries KEV records.
    6. Computes Quantum Risk, Prioritized Risk, and CARS score.
    7. Persists records to PostgreSQL.
  - *Response (200):* `{ "status": "COMPLETED", "findings_discovered": 18, "cars_score": 42.5 }`
- **`GET /api/cbom/:assessmentId/export`**
  - *Query Param:* `format=cyclonedx_json | csv`
  - *Response (200):* Validated CycloneDX 1.6 Cryptographic BOM JSON or structured CSV.
- **`GET /api/risk/:assessmentId`**
  - *Response (200):* Returns formula breakdown: Quantum exposure, sensitivity, lifetime, and overall prioritized risk category.
- **`GET /api/cars/:assessmentId`**
  - *Response (200):* Returns the 5 dimensional scores: Inventory completeness, Algorithm compliance, Architectural decoupling, Toolchain readiness, Governance alignment, and aggregated CARS index ($0-100$).
- **`GET /api/recommendations/:assessmentId`**
  - *Response (200):* Array of actionable PQC recommendations with code refactoring templates, NIST FIPS standards references, and operational considerations.
- **`POST /api/validation/compare`**
  - *Body:* `{ "baseline_assessment_id": "uuid_v1", "migrated_assessment_id": "uuid_v2" }`
  - *Response (200):* Returns resolved findings, remaining findings, newly introduced findings, and overall migration delta score.
- **`GET /api/reports/:assessmentId/download`**
  - *Query Param:* `type=pdf | json`
  - *Response (200):* Application binary stream of the comprehensive audit report.

---

## G. Dependencies and Installation Requirements

### 1. Node.js Gateway Tier (`backend/package.json`)
- `express`: REST API server.
- `argon2`: High-security password hashing.
- `jsonwebtoken`: Stateless signed JWT generation and validation.
- `pg` & `pg-hstore`: PostgreSQL client with connection pooling.
- `multer`: Safe multipart file upload handling with disk storage restrictions.
- `cors` & `helmet`: Secure HTTP headers, CSP, and CORS policy enforcement.
- `express-rate-limit`: Brute-force and DoS protection.
- `dotenv`: Secure environment variable management.
- `pdfkit` / `pdfmake`: Server-side PDF generation for formal audit reports.
- `axios`: High-reliability HTTP client communicating with Python backend.

### 2. Python Analysis Tier (`analyzer/pyproject.toml` or `requirements.txt`)
- `fastapi`: High-performance asynchronous API framework.
- `uvicorn[standard]`: ASGI production server.
- `pydantic` & `pydantic-settings`: Type validation and environment management.
- `sqlalchemy`: Python SQL toolkit and ORM.
- `psycopg2-binary`: High-performance PostgreSQL driver.
- `ast`: Built-in Python standard library for exact Abstract Syntax Tree parsing.
- `javalang`: Pure Python library for parsing Java source code into AST.
- `esprima` / regex-based JS tokenizers: Structured JavaScript/TypeScript cryptographic analysis.
- `pandas` & `numpy`: High-speed tabular processing for datasets (CWE, KEV, PQC benchmarks).
- `scikit-learn`: Decision trees, random forests, and cross-validation for ML categorization experiments.
- `reportlab`: Programmatic generation of vector graphics and PDF summaries.
- `pytest` & `pytest-asyncio`: Automated unit and integration testing harness.

### 3. Frontend Tier (`frontend/package.json`)
- `react` & `react-dom` (v18+): Component architecture.
- `vite`: Fast build tool and HMR server.
- `tailwindcss` & `postcss` & `autoprefixer`: Utility-first enterprise styling.
- `lucide-react`: Modern cybersecurity icons.
- `recharts`: Declarative SVG charting for CARS radar diagrams, risk distributions, and PQC benchmark comparisons.
- `framer-motion`: Smooth micro-interactions for scan progress and modal dialogs.
- `axios`: HTTP client with interceptors for automatic JWT injection and renewal.
- `react-router-dom`: Client-side single-page application routing.

### 4. Database & DevOps
- `PostgreSQL 15+` with `uuid-ossp` extension.
- `Docker` & `Docker Compose` for containerized orchestration across dev and evaluation environments.

---

## H. Dataset Integration Strategy

| Dataset | Format | Source / Reference | Local Ingestion Strategy | Architectural Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **MITRE CWE-1000** | CSV | Official MITRE CWE | Normalized into table `cwe_records`. Ingestion script parses ID, Name, Description, and Potential Mitigations. | Acts as the formal software weakness knowledge base. Maps detected patterns (e.g., weak key generation, ECB mode, broken hash) to official CWE identifiers. |
| **CVEfixes v1.0.0** | JSON / SQL | Zenodo Open Access Repository | Filtered strictly for cryptographic CWEs (CWE-310, CWE-326, CWE-327, CWE-328, CWE-330). Loaded into `cve_records`. | Provides real-world code snippets showing how past developers introduced and remediated cryptographic vulnerabilities. Informs migration code suggestions. |
| **CISA KEV** | CSV | Official CISA KEV Catalog | Normalized into table `kev_records` (already populated in `datasets/known_exploited_vulnerabilities.csv`). Populated with CVE ID, vendor, product, date added, and required mitigation. | Correlates discovered vulnerabilities with active in-the-wild exploitation. Raises prioritization to **CRITICAL** if an identified dependency is in KEV. |
| **Kaggle PQC Benchmark** | CSV | Verified Kaggle dataset (`ranatariq09`) | Verified and normalized into `benchmark_results` table with metrics for keygen, encapsulation, signing, verification, and byte sizes. | Feeds Module 11 comparison dashboard to showcase why migrating from RSA to PQC impacts network bandwidth and latency. |

### Strict Dataset Isolation Rules
- **No Synthetic Mixing:** CWE (weakness taxonomy), CVE (software vulnerability instances), KEV (active exploit telemetry), and PQC Benchmarks (performance measurements) are stored in separate, indexed tables. They will **never** be mashed into one arbitrary dataset.
- **Traceable Attribution:** Every finding mapped to a CWE or CVE retains the exact source ID, version timestamp, and confidence score.

---

## I. Technical Risks, Limitations, and Mitigation Strategies

1. **Malicious File Uploads / Zip Slip / Decompression Bombs:**
   - *Risk:* An attacker uploads a crafted ZIP containing relative paths (`../../etc/passwd`) or a recursive archive expanding to hundreds of gigabytes.
   - *Mitigation:* The `safe_unpack.py` module enforces strict path sanitization (resolves realpaths and verifies they remain inside the isolated sandbox), limits total extracted size (max 100 MB for demo projects), limits file count (max 1,000 files), and rejects symlinks.
2. **ReDoS (Regular Expression Denial of Service):**
   - *Risk:* Regex patterns scanning large files could experience catastrophic backtracking.
   - *Mitigation:* Pre-compile patterns, enforce maximum line length thresholds, run AST visitors before falling back to regex, and apply execution timeouts.
3. **AST Parser Limitations across Languages:**
   - *Risk:* Python AST is native, but Java, C/C++, and JS require structured external parsers or strict lexical patterns.
   - *Mitigation:* Transparent confidence labeling (`CONFIRMED` for AST verified nodes, `PROBABLE` for exact API pattern matches, `POSSIBLE` for keyword heuristics). The system never claims a heuristic match is an AST-confirmed fact.
4. **Secret Leakage in Assessment Reports:**
   - *Risk:* Uploaded code containing hardcoded private keys or API tokens might be displayed in findings and reports.
   - *Mitigation:* A dedicated `secret_redactor.py` utility scrubs private key blocks (`-----BEGIN RSA PRIVATE KEY-----`), API tokens, and passwords, replacing them with `[REDACTED_SECRET]` before persistence.
5. **Academic Viva / Evaluation Clarity:**
   - *Risk:* Evaluators may ask: *"Did you break AES-256 with quantum computing?"* or *"Is every CVE a quantum vulnerability?"*
   - *Defense:* The platform explicitly distinguishes between Shor's algorithm (which breaks asymmetric keys) and Grover's algorithm (which merely halves effective symmetric key length). AES-256 remains quantum-resistant; RSA and ECC do not.

---

## J. Realistic MVP vs. Extended Milestone Roadmap

### Phase 1: Architecture, Database Design & API Specification (CURRENT)
- [x] Complete System Architecture Blueprint
- [x] Normalized Database ER Diagram & DDL Schema
- [x] Module-by-Module Technical Breakdown
- [x] OpenAPI / REST Specification
- [x] Dependency Inventory & Dataset Integration Strategy
- [x] **Checkpoint:** Formal User Review and Approval

### Phase 2: Project Setup & Environment Orchestration
- Initialize Git repository and root `.gitignore`.
- Scaffold `backend/` (Node.js/Express), `analyzer/` (Python/FastAPI), and `frontend/` (React/Vite).
- Setup Docker Compose with PostgreSQL 15+ service.
- Verify health check endpoints across all 3 services simultaneously.

### Phase 3: Module 1 & 2 — Authentication & Safe Repository Management
- Implement user registration, login, and Argon2id password hashing.
- Issue and verify JWT tokens with Express auth middleware.
- Build project management endpoints (Create, List, View, Delete).
- Implement secure file upload, validation, and sandbox extraction.
- **Git Checkpoint:** `git commit -m "feat: complete module 1 & 2 auth and safe file uploads"`

### Phase 4: Module 3 — Automated Cryptographic Discovery Engine
- Implement Python AST visitor for cryptographic libraries (`cryptography`, `hashlib`, `PyCryptodome`).
- Implement pattern and dependency analysis for Java, JavaScript, and C/C++.
- Extract algorithm names, operations, key sizes, and code snippets with secret redaction.
- Verify against curated test repos in `test-repos/sample-python-rsa-aes`.
- **Git Checkpoint:** `git commit -m "feat: complete module 3 cryptographic discovery engine"`

### Phase 5: Module 4 & 5 — CBOM Generation & CWE Mapping
- Implement CycloneDX 1.6-compliant Cryptographic Bill of Materials generator (JSON & CSV export).
- Ingest MITRE CWE-1000 dataset into PostgreSQL.
- Map identified vulnerabilities to CWE-326, CWE-327, CWE-328, CWE-330, CWE-780.
- **Git Checkpoint:** `git commit -m "feat: complete module 4 & 5 cbom and cwe weakness mapping"`

### Phase 6: Module 6 & 7 — Vulnerability Intelligence & Quantum Risk Engine
- Ingest and index CISA KEV and CVEfixes crypto records.
- Implement Shor's vs. Grover's algorithm quantum exposure categorizer.
- Classify asymmetric algorithms (RSA, ECC, DH) as Critical Quantum Risk.
- **Git Checkpoint:** `git commit -m "feat: complete module 6 & 7 vuln intelligence and quantum risk"`

### Phase 7: Module 8 & 9 — Risk Prioritization & CARS Readiness Engine
- Implement configurable 5-factor risk scoring formula.
- Implement 5-dimension Crypto-Agility Readiness Score (CARS).
- Store assessment metrics and dimension breakdowns in DB.
- **Git Checkpoint:** `git commit -m "feat: complete module 8 & 9 risk scoring and cars engine"`

### Phase 8: Module 10 & 11 — PQC Recommendations & Benchmark Engine
- Embed NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) knowledge base.
- Ingest and normalize Kaggle PQC benchmark data.
- Build algorithm comparison logic (key sizes, cycles, memory overhead).
- **Git Checkpoint:** `git commit -m "feat: complete module 10 & 11 pqc recommendations and benchmarks"`

### Phase 9: Module 12, 13 & 14 — AI/ML, Migration Roadmap & Validation
- Implement Scikit-learn classification experiment for migration complexity.
- Generate phased migration roadmap tasks.
- Implement before-and-after AST diffing to validate remediation.
- **Git Checkpoint:** `git commit -m "feat: complete module 12, 13 & 14 ml, roadmap and validation"`

### Phase 10: Complete React Cybersecurity Dashboard & Reports
- Build responsive, professional UI pages with Tailwind CSS, Lucide icons, and Recharts.
- Integrate CBOM table, CARS radar charts, PQC benchmark graphs, and finding inspectors.
- Implement downloadable PDF and JSON executive audit reports.
- **Git Checkpoint:** `git commit -m "feat: complete frontend dashboard and report generation"`

### Phase 11: End-to-End Testing & Demonstration Setup
- Run integration tests with 4 sample repositories (classical vulnerable $\rightarrow$ PQC hybrid).
- Verify scanner accuracy, precision, recall, and zero false-positive claims.
- Final documentation and academic presentation guide.
- **Git Checkpoint:** `git commit -m "release: v1.0.0 capstone project complete"`

---

## Review & Approval Checklist for Phase 1

Please review the architecture, database schema, folder structure, and API contracts above:
1. **System Design:** Does the microservices split between Node.js (Gateway & Auth), Python (AST & Cryptography), and React (UI) align with your expectations?
2. **Database Schema:** Are the entities (Findings, CBOM, CARS, CWE/CVE, PQC) comprehensive and clear for your project evaluation?
3. **Approval to Proceed:** Once you approve this Phase 1 blueprint, we will initialize the Git repository inside `D:\Projects\QCM\`, establish the project directory skeleton, configure the services and Docker setup, and proceed to **Phase 2**!
