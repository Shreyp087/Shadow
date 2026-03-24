# ShadowLedger

ShadowLedger is an adversarial AI security platform for continuously probing target LLM systems, scoring risky behavior, and preserving every result in an append-only trust ledger. This monorepo packages the operational dashboard, FastAPI backend, analytics, reporting pipeline, and deployment configuration needed to run local scans and ship production services on Vercel and Railway.

## What It Does

- Registers target systems that ShadowLedger can test against.
- Executes attack runs across prompt injection, jailbreak, data extraction, role confusion, and indirect injection vectors.
- Scores each response with an AI-assisted risk model.
- Persists a tamper-evident trust ledger entry for every recorded attack result.
- Exposes analytics, PDF audit reports, and a protected dashboard for operators.

## Architecture

```text
                           +----------------------+
                           |      Clerk Auth      |
                           | JWT / Session Layer  |
                           +----------+-----------+
                                      |
                                      v
+--------------------+      HTTPS     +----------------------+
|   Vercel Frontend  +---------------->  FastAPI Backend     |
| Next.js App Router |                 | Railway / Docker    |
| Dashboard + Clerk  |                 | Attack Orchestration|
+---------+----------+                 +-----+---------+-----+
          |                                  |         |
          |                                  |         |
          |                                  |         v
          |                                  |   +-----------+
          |                                  |   | Anthropic |
          |                                  |   | Scoring + |
          |                                  |   | Mutation  |
          |                                  |   +-----------+
          |                                  |
          |                                  v
          |                           +-------------+
          |                           | PostgreSQL  |
          |                           | Runs /      |
          |                           | Results /   |
          |                           | Ledger      |
          |                           +------+------+ 
          |                                  |
          |                                  v
          |                           +-------------+
          +---------------------------> PDF Reports |
                                      | Analytics   |
                                      +-------------+
```

## Repository Layout

```text
.
├── .github/workflows/ci.yml
├── backend/
│   ├── alembic/
│   ├── app/
│   ├── auth/
│   ├── models/
│   ├── routes/
│   ├── schemas/
│   ├── seeds/
│   ├── services/
│   ├── tests/
│   ├── railway.toml
│   └── requirements.txt
├── frontend/
│   ├── app/
│   ├── components/
│   ├── lib/
│   ├── types/
│   ├── vercel.json
│   └── package.json
├── shared/
└── docker-compose.yml
```

## Local Setup

### Prerequisites

- Docker Desktop or compatible Docker runtime
- Python 3.11
- Node.js 20+
- npm 10+

### 1. Configure environment files

Backend starter variables are documented in `backend/.env.example`.

Frontend starter variables are documented in `frontend/.env.example`.

### 2. Start the stack with Docker Compose

```bash
docker compose up --build
```

Services:

- Frontend: `http://localhost:3000`
- Backend API: `http://localhost:8000`
- FastAPI docs: `http://localhost:8000/docs`
- Health probe: `http://localhost:8000/health`
- PostgreSQL: `localhost:5432`

### 3. Run services without Docker

Backend:

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

## Environment Variables

### Backend

| Variable | Required | Example | Purpose |
| --- | --- | --- | --- |
| `APP_NAME` | No | `ShadowLedger API` | FastAPI application title |
| `ENVIRONMENT` | No | `development` or `production` | Runtime mode flag |
| `DEBUG` | No | `false` | Enables SQLAlchemy echo and debug behavior |
| `DATABASE_URL` | Yes | `postgresql+asyncpg://...` | Async PostgreSQL connection string |
| `FRONTEND_ORIGIN` | Yes | `https://shadowledger.vercel.app` | Allowed CORS origin |
| `ENCRYPTION_KEY` | Yes | Fernet key | Decrypts stored target API keys |
| `ANTHROPIC_API_KEY` | Yes | `sk-ant-...` | Mutation and risk-scoring client |
| `CLERK_JWT_KEY` | Conditional | Clerk PEM/public key | Direct JWT verification key |
| `CLERK_JWKS_URL` | Conditional | `https://api.clerk.com/v1/jwks` | JWKS endpoint fallback |
| `CLERK_ISSUER` | No | `https://clerk.your-domain.com` | Optional issuer validation |
| `CLERK_AUTHORIZED_PARTIES` | No | `https://shadowledger.vercel.app` | Accepted `azp` values |

Use either `CLERK_JWT_KEY` or `CLERK_JWKS_URL`.

### Frontend

| Variable | Required | Example | Purpose |
| --- | --- | --- | --- |
| `NEXT_PUBLIC_API_URL` | Yes | `https://shadowledger-api.up.railway.app` | Browser-facing backend base URL |
| `RAILWAY_BACKEND_URL` | Production recommended | `https://shadowledger-api.up.railway.app` | Server-side rewrite target for `/api/*` |
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | Yes | `pk_live_...` | Clerk frontend auth |
| `CLERK_SECRET_KEY` | Build/runtime | `sk_live_...` | Clerk server-side integration |

## Testing and CI

### Backend

```bash
pytest backend/tests --cov=backend --cov-report=term-missing --cov-fail-under=60
```

### Frontend

```bash
cd frontend
npm run test
```

The GitHub Actions workflow in `.github/workflows/ci.yml` runs on pushes to `main` and fails when backend or frontend coverage drops below 60%.

## Deployment

### Frontend on Vercel

- Vercel config lives in `frontend/vercel.json`.
- API proxy rewrites are resolved in `frontend/next.config.mjs` using `RAILWAY_BACKEND_URL` or `NEXT_PUBLIC_API_URL`.
- Set the Vercel project root to `frontend/`.

### Backend on Railway

- Railway config lives in `backend/railway.toml`.
- Set the Railway service root to `backend/`.
- The runtime starts with Uvicorn and uses `/health` for the deployment health check.

## API Reference

### Health

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/health` | No | Returns service version and live DB connectivity state |

### Attack Runs

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/api/v1/attack-runs/` | Clerk JWT | Create a new attack run and queue a background scan |
| `GET` | `/api/v1/attack-runs/{run_id}` | Clerk JWT | Fetch run status and summary metadata |
| `GET` | `/api/v1/attack-runs/{run_id}/results` | Clerk JWT | Paginated list of attack results |
| `GET` | `/api/v1/attack-runs/{run_id}/results/critical` | Clerk JWT | Only `HIGH` and `CRITICAL` findings |
| `GET` | `/api/v1/attack-runs/{run_id}/report` | Clerk JWT | Download PDF audit report |

### Analytics

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/api/v1/analytics/target/{target_system_id}/trend` | Clerk JWT | 30-day daily risk trend for a target system |
| `GET` | `/api/v1/analytics/target/{target_system_id}/attack-surface` | Clerk JWT | Category-level risk summary and trend direction |

## Data Flow Summary

1. An authenticated operator starts an attack run from the dashboard.
2. The backend selects attack vectors, adapts prompts, and probes the target system.
3. The risk scorer assigns a score and category to each response.
4. The trust ledger appends a signed chain-of-custody entry for the result.
5. Analytics and PDF reports read from the persisted run, result, and ledger records.

## Notes

- The frontend already expects target-system list/create routes, but those endpoints are not implemented in the current backend route set yet.
- The health endpoint is intentionally suitable for Railway-style probes: it pings the database and returns `503` when the DB is unavailable.
