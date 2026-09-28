# 🛡️ SentinelAPI

> **Automated, Deterministic, and Safe API Security Testing & Attack Graph Analysis Platform**

[![Tests](https://img.shields.io/badge/pytest-141%20passed-success?style=flat-square&logo=pytest)](file:///Users/rahulseervi/Documents/GitHub/Sentinal-API/backend/tests)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](file:///Users/rahulseervi/Documents/GitHub/Sentinal-API/backend)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?style=flat-square&logo=fastapi)](file:///Users/rahulseervi/Documents/GitHub/Sentinal-API/backend/app/main.py)
[![Next.js](https://img.shields.io/badge/Next.js-16.3-black?style=flat-square&logo=next.js)](file:///Users/rahulseervi/Documents/GitHub/Sentinal-API/frontend)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react)](file:///Users/rahulseervi/Documents/GitHub/Sentinal-API/frontend)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-4169E1?style=flat-square&logo=postgresql)](file:///Users/rahulseervi/Documents/GitHub/Sentinal-API/docker-compose.yml)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker)](file:///Users/rahulseervi/Documents/GitHub/Sentinal-API/docker-compose.yml)

---

## 📌 Overview

**SentinelAPI** is a production-grade, state-of-the-art API security testing and correlation platform designed to detect complex authorization bypasses, business logic flaws, and multi-step exploit chains in RESTful APIs.

Unlike conventional vulnerability scanners that produce noisy, probabilistic alerts or fire destructive payloads, SentinelAPI operates under **strict non-destructive security constraints** and employs **deterministic analytical engines** to synthesize explainable attack paths and security impact assessments without AI hallucinations or risk rating speculation.

---

## 🔐 Core Security Principles & Safety Guarantees

SentinelAPI is built from the ground up to be safe for production-adjacent and staging environments:

- **Non-Destructive Testing Only**: The security engine exclusively issues safe HTTP inspection methods (`GET` and `HEAD`). Destructive methods (`POST`, `PUT`, `DELETE`, `PATCH`) against target systems are strictly prohibited.
- **Strict Explicit Authorization**: Security testing is blocked unless the target project is explicitly marked with `authorization_status: "authorized"`.
- **Zero Credential Persistence**: Raw API keys, Bearer tokens, passwords, and authorization cookies are redacted (`token_***XXXX`) before being written to disk or database.
- **Strict Rate Limiting & Timeouts**: All execution clients enforce timeout caps, redirect limits, and request throttling to prevent accidental denial of service.
- **Deterministic & Explainable Analysis**: Finding correlations, attack paths, and security impacts are computed entirely offline using verified finding evidence and deterministic domain graph logic — **no AI/LLM probabilistic scoring or heuristic guesswork**.

---

## 🚀 Key Features by Architectural Stage

### 1. API Discovery & Ingestion (Stage 1)
- Ingest and parse **OpenAPI 3.x** specifications (JSON / YAML).
- Automatic endpoint cataloging, method filtering, parameter extraction, and schema mapping.
- Live sandbox target environment configuration.

### 2. Authorization & Identity Modeling (Stage 2)
- Multi-tenant **Role-Based Access Control (RBAC)** hierarchy modeling.
- Identity management with credential reference masking and credential lifecycle tracking.
- Domain resource boundaries and **Resource Ownership** tracking (`PRIMARY_OWNER`, `DELEGATE`, etc.).
- Comprehensive interactive **Authorization Model Hierarchy View**.

### 3. Automated BOLA Testing (Stage 3)
- Detection of **Broken Object Level Authorization (OWASP API1:2023)**.
- Safe cross-user object access testing using assigned victim vs. attacker identities.
- Sanitized evidence capture with complete HTTP header/body redacting and status tracking (`CONFIRMED`, `INCONCLUSIVE`, `FALSE_POSITIVE`).

### 4. Function-Level Authorization & BFLA Matrix (Stage 4)
- Detection of **Broken Function Level Authorization (OWASP API5:2023)**.
- Endpoint Authorization Policy definitions and matrix evaluation.
- Automated matrix-based security test generator covering all unprivileged roles against protected administrative operations.

### 5. Property-Level Authorization & Excessive Data Exposure (Stage 5)
- Automated candidate property discovery from OpenAPI specifications and response payloads.
- Fine-grained property sensitivity tagging: `PUBLIC`, `INTERNAL`, `SENSITIVE` (PII), and `SECRET` (keys, tokens).
- Detection of **Broken Object Property Level Authorization (OWASP API3:2023)** and **Mass Assignment** risks.

### 6. Authentication Security Testing (Stage 6)
- Comprehensive test generation across multiple authentication mechanisms: Bearer Tokens, API Keys, Basic Auth, Custom Headers.
- Adversarial test variants: `AUTH_MISSING`, `AUTH_INVALID`, `AUTH_MALFORMED`, `AUTH_EXPIRED`, and `AUTH_SCHEME` manipulation.

### 7. Stateful Workflow & Business Logic Testing (Stages 7.1 – 7.3)
- Sequential state machine modeling for multi-step workflows (e.g., checkout flows, account upgrades).
- Safe stateful workflow execution engine tracking session states and parameter propagation across steps.
- Controlled adversarial attack scenarios:
  - **Invalid State Transitions**: Skipping required approval steps.
  - **Step Replay**: Re-submitting consumed execution states.
  - **Step Skipping & Reordering**: Bypassing prerequisite verification stages.
  - **Identity Switching & Cross-Identity Continuation**: Stealing state sessions across identities.

### 8. Deterministic Attack Graphs & Security Impact Analysis (Stages 8.1 – 8.3)
- **Deterministic Correlation Engine (8.1)**: Synthesizes multi-dimensional relationships across confirmed findings (`AUTH_TO_AUTHORIZATION`, `AUTHORIZATION_TO_WORKFLOW`, `PROPERTY_EXPOSURE_CHAIN`, `SAME_RESOURCE`, `SAME_IDENTITY`).
- **Deterministic Attack Path Detection (8.2)**: Converts correlations into ordered, causal exploit chains with cycle prevention, confidence scoring (`HIGH`/`MEDIUM`/`LOW`), and human-readable sequence narratives.
- **Deterministic Security Impact Analysis (8.3)**:
  - Boundary crossing analysis: `AUTH`, `AUTHORIZATION`, `IDENTITY`, `RESOURCE`, `WORKFLOW`, `PROPERTY`.
  - Sensitive & secret property reachability analysis.
  - Cross-identity & cross-resource traversal detection.
  - Terminal impact classification: `NONE`, `RESOURCE_ACCESS`, `SENSITIVE_PROPERTY_EXPOSURE`, `CROSS_IDENTITY_ACCESS`, `PRIVILEGED_WORKFLOW_ACCESS`, `MULTI_BOUNDARY_ACCESS`.
  - 100% offline rebuild and re-verification without target API network traffic.

---

## 🛠️ Tech Stack

| Domain | Technologies |
| :--- | :--- |
| **Backend Framework** | [FastAPI](https://fastapi.tiangolo.com/), Python 3.10+, Uvicorn |
| **Database & ORM** | [PostgreSQL 15](https://www.postgresql.org/), [SQLAlchemy 2.0](https://www.sqlalchemy.org/), Alembic |
| **Data Validation** | [Pydantic v2](https://docs.pydantic.dev/) |
| **Testing Client** | [HTTPX](https://www.python-httpx.org/) (Async HTTP client with redactor filters) |
| **Frontend Framework** | [Next.js 16 (App Router)](https://nextjs.org/), [React 19](https://react.dev/), TypeScript |
| **Styling & Components** | [Tailwind CSS 4](https://tailwindcss.com/), Radix UI / Lucide Icons |
| **Containerization** | Docker, Docker Compose |
| **Test Suite** | [Pytest](https://docs.pytest.org/) (141 automated unit and integration tests) |

---

## 📂 Project Structure

```text
Sentinal-API/
├── docker-compose.yml              # Multi-container orchestration (Backend, Frontend, PostgreSQL)
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app/
│   │   ├── main.py                 # FastAPI application entrypoint & middleware
│   │   ├── models.py               # SQLAlchemy ORM models (Projects, Findings, Graphs, Impacts)
│   │   ├── schemas.py              # Pydantic v2 schemas and validation models
│   │   ├── core/
│   │   │   └── db.py               # Database engine, session maker, base declarative model
│   │   ├── api/
│   │   │   └── v1/
│   │   │       └── router.py       # Consolidated API v1 REST endpoints
│   │   └── services/
│   │       ├── openapi.py          # OpenAPI 3.x spec ingestion and endpoint parser
│   │       └── security_engine/    # Core analytical and execution testing engines
│   │           ├── client.py       # Safe AsyncSecurityHttpClient (GET/HEAD only)
│   │           ├── redactor.py     # Sensitive credential & header masking utilities
│   │           ├── evaluator.py    # BOLA testing engine
│   │           ├── bfla_engine.py  # BFLA matrix test generator and engine
│   │           ├── property_engine.py # Property discovery and exposure engine
│   │           ├── auth_engine.py  # Authentication testing engine
│   │           ├── workflow_engine.py # Stateful workflow execution engine
│   │           ├── workflow_attack_engine.py # Adversarial workflow scenario engine
│   │           ├── correlation_engine.py # Deterministic finding correlation & graph generator
│   │           ├── attack_path_engine.py # Causal attack path detector
│   │           └── impact_engine.py      # Deterministic security impact analyzer
│   └── tests/                      # Comprehensive Pytest test suite (141 tests)
│       ├── conftest.py             # Test database fixtures and cleanup hooks
│       ├── test_api.py             # Stage 1 API discovery tests
│       ├── test_stage2.py          # Stage 2 Identity & Authorization model tests
│       ├── test_stage3.py          # Stage 3 BOLA testing tests
│       ├── test_stage4.py          # Stage 4 BFLA policy tests
│       ├── test_stage5.py          # Stage 5 Property exposure tests
│       ├── test_stage6.py          # Stage 6 Authentication tests
│       ├── test_stage7_1.py        # Stage 7.1 Workflow modeling tests
│       ├── test_stage7_2.py        # Stage 7.2 Stateful workflow execution tests
│       ├── test_stage7_3.py        # Stage 7.3 Workflow attack scenario tests
│       ├── test_stage8_1.py        # Stage 8.1 Finding correlation & attack graph tests
│       ├── test_stage8_2.py        # Stage 8.2 Attack path detection tests
│       └── test_stage8_3.py        # Stage 8.3 Security impact analysis tests
└── frontend/
    ├── package.json
    ├── next.config.ts
    └── src/
        └── app/                    # Next.js App Router dashboards
            ├── page.tsx            # Executive security overview dashboard
            ├── projects/           # Target project creation and authorization
            ├── api-explorer/       # OpenAPI spec ingestion and endpoint browser
            ├── auth-model/         # Interactive Identity -> Role -> Resource hierarchy
            ├── authorization-matrix/ # BFLA role-versus-endpoint policy matrix
            ├── property-security/  # Resource property sensitivity & exposure view
            ├── authentication-security/ # Auth scheme test configurations
            ├── workflows/          # Stateful business logic workflow builder & execution
            ├── attack-graph/       # Visual Attack Graph, Attack Paths & Impact Analysis
            └── findings/           # Filterable vulnerability findings & evidence drawer
```

---

## ⚡ Quickstart & Installation

### Option 1: Running with Docker Compose (Recommended)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/TheCreativeCodeFlow/Sentinal-API.git
   cd Sentinal-API
   ```

2. **Launch all services:**
   ```bash
   docker-compose up --build
   ```

3. **Access the services:**
   - **Frontend UI**: [http://localhost:3000](http://localhost:3000)
   - **Backend API**: [http://localhost:8000](http://localhost:8000)
   - **Interactive API Docs (Swagger UI)**: [http://localhost:8000/docs](http://localhost:8000/docs)
   - **PostgreSQL Database**: `localhost:5432` (`sentinel` / `sentinel`)

---

### Option 2: Running Locally for Development

#### Prerequisites
- **Python 3.10+**
- **Node.js 20+** and **npm**
- **PostgreSQL** (or SQLite for local dev)

#### 1. Backend Setup
```bash
cd backend

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start backend server
DATABASE_URL="sqlite:///./sentinel_dev.db" uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### 2. Frontend Setup
```bash
cd frontend

# Install npm dependencies
npm install

# Start development server
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🧪 Running Automated Tests

SentinelAPI includes an end-to-end automated verification suite covering all security engines, authorization checks, credential masking rules, graph algorithms, and REST APIs.

### Backend Tests (141 Tests)
```bash
# From repository root
PYTHONPATH=backend python3 -m pytest backend/tests -v
```

Expected output:
```text
======================= 141 passed in 3.50s =======================
```

### Frontend Lint & Production Build
```bash
cd frontend

# Lint check
npm run lint

# Production build verification
npm run build
```

---

## 📡 Key REST API Endpoints

| Category | Method | Endpoint | Description |
| :--- | :--- | :--- | :--- |
| **Projects** | `POST` | `/api/v1/projects/` | Create a target project |
| | `PUT` | `/api/v1/projects/{id}/authorize` | Explicitly authorize security testing |
| **Ingestion** | `POST` | `/api/v1/{project_id}/ingest/` | Upload & parse OpenAPI 3.x spec |
| **BOLA** | `POST` | `/api/v1/projects/{project_id}/security-tests/` | Create BOLA security test |
| | `POST` | `/api/v1/security-tests/{id}/execute` | Execute safe BOLA test |
| **BFLA** | `POST` | `/api/v1/projects/{project_id}/bfla/generate-tests` | Auto-generate matrix tests |
| **Properties** | `POST` | `/api/v1/projects/{project_id}/properties/discover` | Discover sensitive candidate properties |
| **Auth** | `POST` | `/api/v1/projects/{project_id}/auth-security/generate-tests` | Generate authentication tests |
| **Workflows** | `POST` | `/api/v1/workflows/{id}/execute` | Execute stateful workflow safely |
| | `POST` | `/api/v1/workflow-attacks/{id}/execute` | Execute controlled attack scenario |
| **Correlations** | `POST` | `/api/v1/projects/{project_id}/correlation/run` | Generate deterministic finding graph |
| **Attack Paths**| `POST` | `/api/v1/projects/{project_id}/attack-paths/analyze` | Detect causal attack paths |
| | `POST` | `/api/v1/attack-paths/{path_id}/rebuild` | Offline path re-verification |
| **Impact** | `POST` | `/api/v1/projects/{project_id}/impact-analysis/run` | Execute deterministic impact analysis |
| | `GET` | `/api/v1/projects/{project_id}/security-impacts` | List concrete project impacts |
| | `POST` | `/api/v1/security-impacts/{id}/rebuild` | Offline impact re-evaluation |

---

## 🛡️ License

This project is licensed under the [MIT License](LICENSE).
