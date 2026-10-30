# ShadowLedger

ShadowLedger is an adversarial AI security platform for continuously probing target LLM systems, scoring risky behavior, and preserving every result in an append-only trust ledger. This monorepo packages the operational dashboard, FastAPI backend, analytics, reporting pipeline, and deployment configuration needed to run local scans and deploy the frontend and backend together on Vercel.

## What It Does

- Registers target systems that ShadowLedger can test against.
- Executes attack runs across prompt injection, jailbreak, data extraction, role confusion, and indirect injection vectors.
- Routes the Attacker, Mutator, and Judge independently to hosted OpenAI or a local LM Studio model.
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
| Next.js App Router |                 | Railway / Uvicorn   |
| Dashboard + Clerk  |                 | Attack Orchestration|
+---------+----------+                 +-----+---------+-----+
          |                                  |         |
          |                                  |         |
          |                                  |         v
          |                                  |   +----------------+
          |                                  |   | Per-role Router|
          |                                  |   | Attack / Mutate|
          |                                  |   | Judge          |
          |                                  |   +---+--------+---+
          |                                  |       |        |
          |                                  |       v        v
          |                                  |  +---------+ +-----------+
          |                                  |  | OpenAI  | | LM Studio |
          |                                  |  | Hosted  | | Loopback  |
          |                                  |  +---------+ +-----------+
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
├── scripts/
│   ├── backend.mjs
│   ├── frontend.mjs
│   └── setup.mjs
├── shared/
├── package.json
└── docker-compose.yml
```

## Local Setup

### Prerequisites

- Node.js 20.6+
- npm 10+
- Python 3.11+
- PostgreSQL 16 running locally or a reachable managed PostgreSQL database

Docker is not required for the primary development flow.

### 1. Install and configure

```bash
npm ci
npm run setup
```

`npm run setup` does the following without overwriting an existing `.env`:

- Creates the root `.env` from `.env.example` and generates a Fernet encryption key when needed.
- Installs frontend packages from `frontend/package-lock.json`.
- Creates `backend/.venv` with Python 3.11+ and installs backend requirements.

The root `.env` is the canonical local configuration for all root npm commands. Point `DATABASE_URL` at a reachable database. The default expects a local role, password, and database all named `shadowledger`:

```text
postgresql+asyncpg://shadowledger:shadowledger@127.0.0.1:5432/shadowledger
```

You can instead replace it with a managed PostgreSQL URL; bare `postgres://` and `postgresql://` URLs are automatically adapted to the backend's asyncpg driver. Local demo mode does not require Clerk credentials. Before launching a scan, configure Attacker, Mutator, and Judge in **Settings**. A real `OPENAI_API_KEY` is needed only as the fallback for a role using hosted OpenAI without its own saved key; an all-local LM Studio combination does not need one.

### 2. Start the application

```bash
npm run dev
```

Services:

- Frontend: `http://localhost:4200`
- Backend API: `http://localhost:8000`
- FastAPI docs: `http://localhost:8000/docs`
- Health probe: `http://localhost:8000/health`

The backend command applies Alembic migrations and loads the idempotent attack-vector and demo-data seeds before Uvicorn starts. `Ctrl+C` stops both services.

If `npm run dev` reports that port `4200` or `8000` is already in use, the stack may already be running in another terminal. Use that instance or stop it with `Ctrl+C` in its original terminal, then retry. The launcher prints a platform-appropriate command for inspecting the listener and never kills an unknown process or silently changes the configured ports.

### npm commands

| Command | Purpose |
| --- | --- |
| `npm run setup` | Install frontend/backend dependencies and create local configuration |
| `npm run dev` | Prepare the database and run the API and web app together |
| `npm run dev:backend` | Prepare the database and run only FastAPI |
| `npm run dev:frontend` | Run only Next.js |
| `npm run db:prepare` | Apply migrations and load both seed sets |
| `npm run db:migrate` | Apply Alembic migrations only |
| `npm run db:seed` | Load both seed sets only |
| `npm test` | Run backend and frontend test suites together |
| `npm run lint` | Lint the frontend |
| `npm run typecheck` | Type-check the frontend |
| `npm run build` | Create the frontend production build |
| `npm run check:api` | Run the backend API smoke-check script |
| `npm run check:data` | Validate seeded demo data |
| `npm run keys:rotate` | Re-encrypt stored target and LLM-role credentials with a new primary Fernet key |
| `npm run verify:ledger -- <run-id>` | Verify the trust-ledger chain for one attack run |

When the desired Python executable is not on `PATH`, set `SHADOWLEDGER_PYTHON` before setup. On macOS/Linux use `SHADOWLEDGER_PYTHON=/path/to/python npm run setup:backend`; in PowerShell, set `$env:SHADOWLEDGER_PYTHON` first and then run `npm run setup:backend`.

In Clerk mode, `npm run check:api` verifies that protected routes challenge an unauthenticated request with `401`. To smoke-test authenticated data as well, provide a short-lived token only for that process with `SHADOWLEDGER_BEARER_TOKEN=<clerk-session-token> npm run check:api`. `SHADOWLEDGER_API_URL` can point the check at a non-default API base URL.

### Optional Docker fallback

The repository keeps Compose for teams that still want a containerized PostgreSQL and services, but it is no longer the default execution flow:

```bash
docker compose up --build
```

Compose uses `DOCKER_DATABASE_URL` from `.env`; npm uses `DATABASE_URL`.

## Authentication and `Missing Bearer token`

ShadowLedger has two operator-authentication modes. Clerk authenticates the person using ShadowLedger; it is separate from `OPENAI_API_KEY`, saved LLM-role credentials, and the API key stored for a target system.

| Mode | Configuration | API behavior |
| --- | --- | --- |
| Local demo | `ENVIRONMENT=development` and `NEXT_PUBLIC_DEMO_AUTH=true` | The development frontend does not request a Clerk token, and the backend uses the seeded demo user. Clerk verifier settings are ignored in this explicit mode. |
| Clerk | `NEXT_PUBLIC_DEMO_AUTH=false`, frontend Clerk keys configured, and at least one backend JWT-verification source configured | The frontend obtains the signed-in user's short-lived Clerk session token and sends `Authorization: Bearer <session-token>`. This mode is required for production. |

`{"detail":"Missing Bearer token"}` means a protected backend route is in Clerk mode and the request did not include a Clerk session token. Sign in through the web app so its API client can attach the token, or attach a short-lived session token when calling the API directly. For local demo mode, set `NEXT_PUBLIC_DEMO_AUTH=true` in the shared root `.env` and restart both processes with `npm run dev`. Production rejects demo auth even if the flag is accidentally enabled. A Clerk Secret Key, role-provider key, target-provider key, or `OPENAI_API_KEY` is not a Clerk session token and must not be used in this Bearer header.

### Get Clerk credentials

1. Create or select an application in the [Clerk Dashboard](https://dashboard.clerk.com/).
2. On its **API keys** page, copy the application Publishable Key and Secret Key. These are the Clerk application keys, not Clerk's user/organization API-key feature.
3. Copy the instance's Frontend API host from **Domains** and use its `/.well-known/jwks.json` URL. Clerk also offers a JWT public key, but JWKS avoids multiline PEM parsing problems in `.env`. Clerk documents both approaches in its [manual JWT verification guide](https://clerk.com/docs/guides/sessions/manual-jwt-verification) and the standard variables in its [environment-variable guide](https://clerk.com/docs/guides/development/clerk-environment-variables).
4. Replace the angle-bracket values below in the root `.env`; do not leave the placeholders in place:

```dotenv
NEXT_PUBLIC_DEMO_AUTH=false
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=<Clerk Publishable Key>
CLERK_SECRET_KEY=<Clerk Secret Key>

# Choose one backend verification source. JWKS is simplest for local use.
CLERK_JWKS_URL=https://<your-clerk-frontend-api-host>/.well-known/jwks.json
CLERK_JWT_KEY=
CLERK_FRONTEND_API_URL=

# Recommended validation boundaries:
CLERK_ISSUER=https://<your-clerk-frontend-api-host>
CLERK_AUTHORIZED_PARTIES=http://localhost:4200
FRONTEND_ORIGIN=http://localhost:4200
```

Keep the Secret Key server-side. The Publishable Key is designed for the browser. For direct API calls, obtain a short-lived session token from a signed-in Clerk session, such as with Clerk's `getToken()` API; see [Clerk's session-token documentation](https://clerk.com/docs/guides/sessions/session-tokens).

## LLM Role Routing

ShadowLedger uses three internal LLM roles during a scan. These are orchestration models, not the target being tested:

- **Attacker** adapts the initial adversarial prompts to the registered target.
- **Mutator** generates fresh follow-up variants when additional probing is warranted.
- **Judge** evaluates each target response and assigns its risk score and explanation.

Open `http://localhost:4200/dashboard/settings` after starting the npm stack. Each role has its own provider, exact model ID, credential, save action, and connection test. Selecting one role never changes either of the other roles. The summary at the top reports how many roles are local and hosted.

The two provider choices are deliberately constrained:

| Provider | Base URL | Credential | Availability |
| --- | --- | --- | --- |
| Hosted OpenAI | Fixed to `https://api.openai.com/v1` | OpenAI project API key, saved per role or supplied by the server-side `OPENAI_API_KEY` fallback | Development and production |
| Local / LM Studio | A loopback URL such as `http://127.0.0.1:1234/v1`; a full `/chat/completions` route is also normalized | Optional when local-server authentication is disabled | Development only |

Hosted roles cannot redirect their OpenAI key to a custom host. Local URLs must use `localhost`, an address in `127.0.0.0/8`, or `::1`, and may not contain URL credentials, query parameters, or fragments. These restrictions apply specifically to the internal role settings and prevent an authenticated settings request from turning the backend into a general network-request proxy.

All eight independent assignments are supported:

| Combination | Attacker | Mutator | Judge | Summary |
| ---: | --- | --- | --- | --- |
| 1 | Hosted | Hosted | Hosted | 0 local · 3 hosted |
| 2 | Local | Hosted | Hosted | 1 local · 2 hosted |
| 3 | Hosted | Local | Hosted | 1 local · 2 hosted |
| 4 | Hosted | Hosted | Local | 1 local · 2 hosted |
| 5 | Local | Local | Hosted | 2 local · 1 hosted |
| 6 | Local | Hosted | Local | 2 local · 1 hosted |
| 7 | Hosted | Local | Local | 2 local · 1 hosted |
| 8 | Local | Local | Local | 3 local · 0 hosted |

### Configure LM Studio

1. Load and start the chat model in LM Studio, enable its local OpenAI-compatible server, and keep it listening on port `1234`.
2. Confirm the model ID from the same machine that runs the FastAPI backend:

   ```bash
   curl http://127.0.0.1:1234/v1/models
   ```

3. In **Settings**, choose **Local / LM Studio** for any desired roles, set the base URL to `http://127.0.0.1:1234/v1`, and enter the exact returned chat model ID. For the model shown in this setup, use `mistralai/ministral-3-14b-reasoning`; do not select the `text-embedding-nomic-embed-text-v1.5` embedding model for a chat role.
4. Leave the API-key field blank if LM Studio authentication is disabled. Save each changed role, then select **Test** for that role. Unsaved changes are intentionally not tested.

`127.0.0.1` always means the machine running the backend. A Railway or other remote backend cannot use that address to reach LM Studio on your Mac. Local routing is therefore accepted only with `ENVIRONMENT=development` and is intended for the npm-based local stack.

### Defaults and overrides

Users without saved role rows keep the original hosted behavior: `OPENAI_API_KEY` supplies the shared server-side fallback key, while `OPENAI_ATTACKER_MODEL`, `OPENAI_MUTATION_MODEL`, and `OPENAI_SCORER_MODEL` supply the three default model IDs. Saving a role creates a user-scoped override. A hosted override with no matching saved credential may still use `OPENAI_API_KEY`; a local override needs no key when its server accepts the non-secret local bearer placeholder.

Provider credentials are bound to the provider for which they were entered. Switching a role never forwards a retained hosted key to LM Studio, or a retained local key to OpenAI. The target-system credential remains completely separate from all three role credentials.

## Target Execution Guide

An executable scan has two independent configuration layers:

- The three role settings power ShadowLedger's prompt adaptation, mutation, and risk scoring. Every hosted role needs either its own saved OpenAI project key or the server-side `OPENAI_API_KEY` fallback. Create hosted credentials in the OpenAI API dashboard and keep them server-side as described in the [official quickstart](https://platform.openai.com/docs/quickstart/make-your-first-api-request).
- `api_key` on the target-system record authenticates ShadowLedger's outbound requests to the system being tested. It is never used for Attacker, Mutator, or Judge.

Only probe systems you own or have explicit authorization to test. Prefer an isolated staging target, a scoped test credential, and provider-side spend/rate limits.

### Supported target contracts

Only the following `target_type` values and wire contracts are implemented:

- `openai_compatible`: `api_endpoint` may be the API base, a base ending in `/v1`, or the full URL ending in `/chat/completions`. ShadowLedger normalizes those forms to `/v1/chat/completions`, sends `Authorization: Bearer <target-api-key>` and `Content-Type: application/json`, and posts `{"model":"<model_name>","messages":[{"role":"user","content":"<prompt>"}]}`. The response must expose text at `choices[0].message.content`; OpenAI-style `usage` fields are optional. This matches the [OpenAI Chat Completions contract](https://developers.openai.com/api/reference/resources/chat).
- `anthropic`: `api_endpoint` may be the API base or a full URL ending in `/v1/messages`. The Anthropic SDK posts to `/v1/messages` with `x-api-key: <target-api-key>`, its required SDK-managed headers, `model`, `max_tokens=1024`, and one user message. The response must contain Anthropic text content blocks; usage fields are optional. Generate a scoped key under **Settings → API keys** in Claude Console; see [Anthropic authentication](https://platform.claude.com/docs/en/manage-claude/authentication).

The connector has a 15-second request timeout and does not currently support arbitrary paths, custom headers, Azure-style `api-key` authentication, streaming, or provider-specific payload shapes. Add a connector before registering a target that needs a different contract. The endpoint must be reachable from the backend process, not merely from the browser.

The seeded **GPT-4 Customer Support Bot** and **Internal HR Assistant** use illustrative `.demo` endpoints and fake keys. They exist to populate the dashboard, reports, analytics, and ledger history; the seed marks them inactive and they are intentionally non-executable. Create a real, authorized target before launching a live scan. `is_active=false` is enforced at run creation, immediately before background execution, and by the outbound connector.

### Dashboard workflow

1. Choose local demo or Clerk authentication as described above, then start PostgreSQL and run `npm run dev`.
2. Open **Settings**, assign hosted OpenAI or Local / LM Studio independently to Attacker, Mutator, and Judge, save each changed role, and run its connection test. Supply `OPENAI_API_KEY` in `.env` only if a hosted role will use that fallback instead of a saved role key.
3. Open `http://localhost:4200/dashboard/systems`, choose the exact target type, and register a reachable staging endpoint, its model identifier, and its separate target-provider key.
4. Select **Run Full Scan** on the target card, or open **Attack Runs**, select **New Scan**, and choose the newly created target. The dashboard runs all active attack vectors and can generate additional mutations after risky responses, so review hosted-provider budgets, local compute capacity, and the confirmation prompt first.
5. Follow the run detail page while its status moves through `PENDING`, `RUNNING`, and either `COMPLETED` or `FAILED`. Inspect results and download the PDF report there.
6. Optionally verify the stored hash chain with `npm run verify:ledger -- <run-id>`.

### Direct API workflow

The examples below contain placeholders only. In Clerk mode, replace `<clerk-session-token>` with a short-lived session token from the signed-in user. In local demo mode, omit the `Authorization` header entirely. Never substitute the Clerk Secret Key.

Inspect the effective settings, save a local Attacker, and test the saved connection:

```bash
curl -sS "http://localhost:8000/api/v1/llm-role-settings" \
  -H "Authorization: Bearer <clerk-session-token>"

curl -sS -X PUT "http://localhost:8000/api/v1/llm-role-settings/attacker" \
  -H "Authorization: Bearer <clerk-session-token>" \
  -H "Content-Type: application/json" \
  --data '{
    "provider": "local_openai_compatible",
    "model_name": "mistralai/ministral-3-14b-reasoning",
    "base_url": "http://127.0.0.1:1234/v1"
  }'

curl -sS -X POST "http://localhost:8000/api/v1/llm-role-settings/attacker/test" \
  -H "Authorization: Bearer <clerk-session-token>"
```

Use `attacker`, `mutator`, or `judge` in the path. `hosted_openai` and `local_openai_compatible` are the provider values. To configure a hosted role, send its exact OpenAI chat `model_name` and an `api_key`; its base URL is fixed and may be omitted. Omitted or blank keys preserve an existing provider-bound key, and responses expose only `api_key_configured`, never the supplied secret. Save a change before calling its connection-test endpoint.

Register a target and copy `data.id` from the response as `<target-system-id>`:

```bash
curl -sS -X POST "http://localhost:8000/api/v1/target-systems" \
  -H "Authorization: Bearer <clerk-session-token>" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Authorized staging assistant",
    "description": "Non-production target approved for security testing",
    "api_endpoint": "https://<your-target-host>/v1",
    "target_type": "openai_compatible",
    "api_key": "<target-provider-api-key>",
    "model_name": "<target-model-id>",
    "is_active": true
  }'
```

Start a run and copy its `data.id` as `<run-id>`. Omit `vector_category_filter` or set it to `null` to run every active vector:

```bash
curl -sS -X POST "http://localhost:8000/api/v1/attack-runs/" \
  -H "Authorization: Bearer <clerk-session-token>" \
  -H "Content-Type: application/json" \
  --data '{
    "target_system_id": "<target-system-id>",
    "vector_category_filter": ["PROMPT_INJECTION", "JAILBREAK"]
  }'
```

Poll the run, page through results, and download its report:

```bash
curl -sS "http://localhost:8000/api/v1/attack-runs/<run-id>" \
  -H "Authorization: Bearer <clerk-session-token>"

curl -sS "http://localhost:8000/api/v1/attack-runs/<run-id>/results?page=1&page_size=20" \
  -H "Authorization: Bearer <clerk-session-token>"

curl -sS "http://localhost:8000/api/v1/attack-runs/<run-id>/report" \
  -H "Authorization: Bearer <clerk-session-token>" \
  -o shadowledger-report.pdf
```

Valid vector-category filters are `PROMPT_INJECTION`, `JAILBREAK`, `DATA_EXTRACTION`, `ROLE_CONFUSION`, and `INDIRECT_INJECTION`. Result risk categories are `SAFE`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`; `HIGH` and `CRITICAL` count as vulnerabilities and are returned by the `/results/critical` endpoint.

### Secret handling and production boundaries

- `.env` is Git-ignored for local use, but do not commit, paste into tickets, log, or expose `CLERK_SECRET_KEY`, Clerk session tokens, `OPENAI_API_KEY`, `ENCRYPTION_KEY`, saved role-provider keys, or target-provider keys. Use managed secret storage in deployment and rotate scoped credentials after suspected exposure.
- The Settings and target-provisioning forms necessarily handle a newly entered provider key briefly in browser memory and send it to the authenticated backend over loopback HTTP in the documented local flow or HTTPS in production and other non-loopback deployments. The frontend clears each credential field as its submission begins. The backend accepts it as a masked secret value, Fernet-encrypts it before database storage, and API responses expose only `api_key_configured: true|false`—never plaintext, ciphertext, a prefix, or a suffix. Protected API responses also use `Cache-Control: no-store`; the npm launchers remove backend-only secrets from the Next.js child environment and frontend-only secrets from the Python child environment.
- A role key is provider-bound. Hosted OpenAI always uses `https://api.openai.com/v1`, while local providers are development-only and loopback-only, so switching providers cannot redirect a retained hosted key to an arbitrary endpoint. Role-provider requests, target-provider requests, and connection probes do not follow redirects or inherit ambient proxy environment variables. Connection-test failures return sanitized status information instead of provider response bodies or credentials.
- The application must be able to decrypt provider keys while executing a scan: database ciphertext plus `ENCRYPTION_KEY`, or control of the running backend, can expose a key. Encryption at rest does not protect against a fully compromised backend. Keep the primary Fernet key in managed secret storage. To rotate all stored target and role credentials, back up the database and secret configuration, set a new `ENCRYPTION_KEY`, temporarily put old keys in comma-separated `ENCRYPTION_KEY_PREVIOUS`, run `npm run keys:rotate`, verify both target and LLM-provider access, then remove the old-key variable. The command reports target, role, and total counts without logging keys.
- Prompts, target responses, risk explanations, and generated reports are stored in PostgreSQL and may contain sensitive material. Define access, retention, deletion, backup, and incident-response policies appropriate to that data.
- The trust ledger is an application-enforced SHA-256 hash chain. Verification can detect a broken chain, but it is not a digital signature, an external timestamp, a WORM store, or proof against an attacker who controls both the database and application. Use external anchoring or immutable storage if your assurance requirements demand it.
- Target registration requires HTTPS by default and rejects URL credentials, query strings, fragments, and literal private/non-global IPs. The connector resolves hostnames immediately before execution and blocks any private, loopback, link-local, metadata, multicast, or other non-global destination. `ALLOW_INSECURE_TARGET_ENDPOINTS=true` permits HTTP only in development; `ALLOW_PRIVATE_TARGET_ENDPOINTS=true` is the explicit override for an authorized internal target. DNS rebinding and infrastructure compromise still require a network egress allowlist/firewall for strong production containment.
- Use HTTPS for the frontend, backend, and target; set `ENVIRONMENT=production`, `NEXT_PUBLIC_DEMO_AUTH=false`, exact `FRONTEND_ORIGIN`/`CLERK_AUTHORIZED_PARTIES` values, database TLS and least-privilege roles, and provider budgets/rate limits. These controls reduce risk but do not make adversarial testing inherently safe or guarantee that every model failure will be found.

## Environment Variables

### Backend

| Variable | Required | Example | Purpose |
| --- | --- | --- | --- |
| `APP_NAME` | No | `ShadowLedger API` | FastAPI application title |
| `ENVIRONMENT` | No | `development` or `production` | Runtime mode flag |
| `NEXT_PUBLIC_DEMO_AUTH` | Local only | `true` | Shared flag that enables explicit demo authentication in both backend and frontend during development |
| `DEBUG` | No | `false` | Enables SQLAlchemy echo and debug behavior |
| `DATABASE_URL` | Yes | `postgresql+asyncpg://...` | Async PostgreSQL connection string |
| `FRONTEND_ORIGIN` | Yes | `https://shadowledger.vercel.app` | Allowed CORS origin |
| `ENCRYPTION_KEY` | Yes | Fernet key | Encrypts and decrypts stored target and LLM-role API keys |
| `ENCRYPTION_KEY_PREVIOUS` | During rotation | comma-separated Fernet keys | Allows old ciphertext to be re-encrypted under the current primary key |
| `ALLOW_INSECURE_TARGET_ENDPOINTS` | No | `false` | Development-only override for an authorized HTTP target |
| `ALLOW_PRIVATE_TARGET_ENDPOINTS` | No | `false` | Explicitly permits authorized private/internal target addresses |
| `OPENAI_API_KEY` | Conditional | `sk-...` | Server-side fallback for hosted roles without a matching saved credential; unnecessary for an all-local setup |
| `OPENAI_ATTACKER_MODEL` | No | `gpt-4o-mini` | Hosted Attacker model default before a user saves an override |
| `OPENAI_MUTATION_MODEL` | No | `gpt-4o-mini` | Hosted Mutator model default before a user saves an override |
| `OPENAI_SCORER_MODEL` | No | `gpt-4o-mini` | Hosted Judge model default before a user saves an override |
| `CLERK_JWT_KEY` | Conditional | Clerk PEM/public key | Direct JWT verification key |
| `CLERK_JWKS_URL` | Conditional | `https://<your-clerk-domain>/.well-known/jwks.json` | JWKS endpoint fallback |
| `CLERK_FRONTEND_API_URL` | Conditional | Clerk frontend API URL | Derives a Clerk JWKS endpoint |
| `CLERK_ISSUER` | No | `https://clerk.your-domain.com` | Optional issuer validation |
| `CLERK_AUTHORIZED_PARTIES` | No | `https://shadowledger.vercel.app` | Accepted `azp` values |

Use `CLERK_JWT_KEY`, `CLERK_JWKS_URL`, or `CLERK_FRONTEND_API_URL` outside local demo mode. Local LM Studio URLs and model IDs are user-scoped database settings, not environment variables; configure them in **Settings**. Saved role settings override the corresponding hosted model defaults above.

### Frontend

| Variable | Required | Example | Purpose |
| --- | --- | --- | --- |
| `NEXT_PUBLIC_API_URL` | Yes | `https://shadowledger-api.up.railway.app` | Browser-facing backend base URL |
| `RAILWAY_BACKEND_URL` | Production recommended | `https://shadowledger-api.up.railway.app` | Server-side rewrite target for `/api/*` |
| `NEXT_PUBLIC_DEMO_AUTH` | Local only | `true` | Shared with the backend; bypasses Clerk only during local development |
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | Outside demo mode | `pk_live_...` | Clerk frontend auth |
| `CLERK_SECRET_KEY` | Outside demo mode | `sk_live_...` | Clerk server-side integration |

## Testing and CI

```bash
npm test
npm run lint
npm run typecheck
npm run build
```

Run either suite independently when iterating:

```bash
npm run test:backend
npm run test:frontend
```

The GitHub Actions workflow in `.github/workflows/ci.yml` runs on pushes to `main` and fails when backend or frontend coverage drops below 60%.

## Deployment

### Frontend and backend together on Vercel

The repository-root `vercel.json` declares a Next.js frontend service and a Python FastAPI backend service in one Vercel project. Keep the project root at the repository root and deploy from there:

```sh
npx vercel login
npx vercel link
npx vercel deploy --prod
```

The root routing sends `/api/*` and `/health` to Python, and all application pages to Next.js. Set `NEXT_PUBLIC_API_URL=/` and `NEXT_PUBLIC_DEMO_AUTH=false` as non-secret production configuration. A separate backend host or Railway account is unnecessary. `frontend/vercel.json` remains available for standalone frontend deployments.

Vercel installs Python 3.12 and the dependencies locked in `backend/uv.lock`. The workflow registry is declared in `backend/pyproject.toml`. Hosted scan launches enqueue a Vercel Workflow; each primary attack and each mutation executes in a separate bounded step. Credentials are loaded inside steps, never passed as workflow arguments. Deterministic result IDs and transactions prevent retries from duplicating stored results, metrics, or ledger entries. Local development continues using FastAPI background tasks.

**Deployment without credentials:** no local `.env` files are uploaded. The landing page remains available, sign-in stays disabled, and protected backend routes return `503` while configuration is incomplete. `/api/status` returns `200` with the missing variable names and execution mode, without accessing the database or returning any values. `/health` returns `503` with `db: not_configured` until a database URL is supplied. A `configured` status reports presence of settings, not verified database connectivity.

When ready, configure the following manually in Vercel's environment settings, then redeploy:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | Hosted PostgreSQL connection string. Neon can be provisioned through Vercel Marketplace; the database itself is hosted by Neon. |
| `ENCRYPTION_KEY` | A fresh Fernet key for encrypting saved provider credentials. Keep this stable across deployments. |
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY`, `CLERK_SECRET_KEY` | Matching Clerk application keys for frontend authentication. |
| `CLERK_JWKS_URL` | Your Clerk instance's `/.well-known/jwks.json` URL. `CLERK_JWT_KEY` or `CLERK_FRONTEND_API_URL` is also supported. |
| `OPENAI_API_KEY` | Optional server-side fallback for hosted roles without their own saved provider key. |

`ENVIRONMENT` defaults to `production` on Vercel, and the frontend origin defaults to Vercel's deployment domain. Set `FRONTEND_ORIGIN` and `CLERK_AUTHORIZED_PARTIES` to the site's exact HTTPS origin, including for `https://shadowledger-iota.vercel.app`. Equivalent trailing slashes and default ports are normalized; unrelated origins remain rejected. Standard managed PostgreSQL URLs containing `sslmode` or `channel_binding` automatically use Psycopg so those protections are preserved. Existing asyncpg connection URLs remain supported.

The Python service build runs `scripts/prepare_deployment.py`. With a hosted `DATABASE_URL`, this applies additive Alembic migrations and seeds reference attack vectors before the new code is published. It skips missing or local-only database configuration on Vercel so a credential-free deployment can still publish. No synthetic target systems, attack results, or users are created by this step. No database is provisioned by the deployment itself.

### Real starter targets and Claude role settings

Each signed-in user's inventory automatically receives **IT Support** (GPT-4.1 Mini), **Restaurant Help** (GPT-4.1 Nano), and **Customer Support** (GPT-4o Mini). Each assistant has distinct system instructions covering its job, knowledge limits, privacy, and escalation rules; these are sent in the provider's actual system field on every attempt and supplied to the scorer as the expected policy. The inventory shows each prompt, and custom targets accept their own role and system prompt. These assistants call OpenAI's real Chat Completions endpoint and use the existing server-side `OPENAI_API_KEY`. They are live model configurations, with no external helpdesk, booking, store database, or sample results attached. Their IDs are deterministic per user; existing starter records are upgraded in place without replacing credentials, activation state, or scan history. The shared credential is never copied into target records or returned by the API. Shared-key access is restricted to the exact starter ID, owner, endpoint, model, and provider combination. Custom targets continue to require their own encrypted credential. Set `STARTER_TARGETS_ENABLED=false` to turn off automatic provisioning and shared-key access.

Starter targets do not contain sample results: scans make real provider requests and incur usage against the app's OpenAI account. Visitors' targets and results remain user-scoped. The model catalog is documented in OpenAI's [GPT-4.1 Mini](https://developers.openai.com/api/docs/models/gpt-4.1-mini), [GPT-4.1 Nano](https://developers.openai.com/api/docs/models/gpt-4.1-nano), and [GPT-4o Mini](https://developers.openai.com/api/docs/models/gpt-4o-mini) references. Model access and quota depend on the configured OpenAI account.

Anthropic Claude is an **internal role provider** for Attacker, Mutator, and Scorer/Judge, not a starter target. Select **Anthropic Claude** for any role in Settings; the model field is prefilled with the active `claude-sonnet-4-6` model. Configure `ANTHROPIC_API_KEY` in Vercel, or enter an Anthropic key for each role. An OpenAI credential is never reused for Anthropic. Claude uses Anthropic's native Messages API at a fixed official endpoint with redirects disabled, and the Test button verifies the configured model. Existing OpenAI defaults remain usable while the Anthropic key is pending. See Anthropic's [Sonnet 4.6 reference](https://platform.claude.com/docs/en/models/sonnet-4-6/overview).

Scan orchestration imports only sandbox-safe step declarations. Database and provider libraries load inside the executable steps, outside the deterministic workflow sandbox. The detail page and dashboard poll both Pending and Running scans, and the detail page reloads final results when a run ends. Each new run stores its Vercel workflow ID so worker failures can be reconciled to a visible Failed state. Migration `20261030_0004` marks legacy Pending records left by the previous worker import failure as Failed; their evidence is preserved, and the detail page offers a new full scan rather than silently re-running provider calls.

For the pinned `vercel-workflow==0.12.0` SDK, `app/workflow_transport.py` supplies a host-only transport adapter: 30-second event API reads and up to three attempts with backoff for GET/HEAD requests and `step_created` events with an existing run and correlation ID. It preserves the SDK's authentication, CBOR parsing, and 409 conflict handling, so a committed step whose acknowledgement timed out can still be dispatched without creating another step. Authentication errors and redirects are not retried; Retry-After is honored, and long throttles are returned to queue delivery. Other event writes, including `step_started` (which increments attempts), are never blindly retried. This uses a narrow private SDK integration covered by transport and sandbox regression tests; review it when upgrading the pinned SDK.

See [Vercel Services](https://vercel.com/docs/services), [Python Workflows](https://vercel.com/kb/guide/python-and-durable-workflows), and [Postgres integrations](https://vercel.com/docs/postgres) for platform setup.

### Optional separate backend on Railway

- Railway config lives in `backend/railway.toml`.
- Set the Railway service root to `backend/`.
- Railway runs `alembic upgrade head` as a pre-deploy command, so schema migrations must succeed before a new API deployment starts.
- The runtime starts with Uvicorn and uses `/health` for the deployment health check.

## API Reference

### Health

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/health` | No | Returns service version and live DB connectivity state |
| `GET` | `/api/status` | No | Reports configuration readiness and scan execution mode; never returns credential values |

### LLM Role Settings

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/api/v1/llm-role-settings` | Clerk session JWT; local demo may omit | Return effective Attacker, Mutator, and Judge settings with credential-configured booleans only |
| `PUT` | `/api/v1/llm-role-settings/{role}` | Clerk session JWT; local demo may omit | Save one user-scoped provider, model, optional local base URL, and write-only credential |
| `POST` | `/api/v1/llm-role-settings/{role}/test` | Clerk session JWT; local demo may omit | Probe the saved/effective role configuration and return a sanitized result and latency |

`{role}` is `attacker`, `mutator`, or `judge`. The update body uses `provider`, `model_name`, optional `base_url`, and optional `api_key`; valid provider values are `hosted_openai` and `local_openai_compatible`.

### Target Systems

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/api/v1/target-systems` | Clerk session JWT; local demo may omit | List targets owned by the request user; only credential-configured state is returned |
| `POST` | `/api/v1/target-systems` | Clerk session JWT; local demo may omit | Register a target and encrypt its provider key |

### Attack Runs

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/api/v1/attack-runs/` | Clerk session JWT; local demo may omit | List the request user's runs |
| `GET` | `/api/v1/attack-runs/summary` | Clerk session JWT; local demo may omit | Return dashboard totals and average risk |
| `POST` | `/api/v1/attack-runs/` | Clerk session JWT; local demo may omit | Create a new attack run and queue a background scan |
| `GET` | `/api/v1/attack-runs/{run_id}` | Clerk session JWT; local demo may omit | Fetch run status and summary metadata |
| `GET` | `/api/v1/attack-runs/{run_id}/results` | Clerk session JWT; local demo may omit | Paginated list of attack results |
| `GET` | `/api/v1/attack-runs/{run_id}/results/critical` | Clerk session JWT; local demo may omit | Only `HIGH` and `CRITICAL` findings |
| `GET` | `/api/v1/attack-runs/{run_id}/report` | Clerk session JWT; local demo may omit | Download PDF audit report |

### Analytics

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/api/v1/analytics/target/{target_system_id}/trend` | Clerk session JWT; local demo may omit | 30-day daily risk trend for a target system |
| `GET` | `/api/v1/analytics/target/{target_system_id}/attack-surface` | Clerk session JWT; local demo may omit | Category-level risk summary and trend direction |

## Data Flow Summary

1. An authenticated operator starts an attack run from the dashboard.
2. The backend resolves the operator's three effective role settings and creates independent Attacker, Mutator, and Judge clients.
3. The backend selects attack vectors, adapts prompts with the Attacker, and probes the separately configured target system.
4. The Mutator creates warranted follow-ups and the Judge assigns a score, category, and explanation to each response.
5. The trust ledger appends a hash-chained evidence entry for the result.
6. Analytics and PDF reports read from the persisted run, result, and ledger records.

## Notes

- Target-system list/create routes are available at `/api/v1/target-systems`.
- Role-provider controls are available at `/dashboard/settings`; local providers require the development backend and a loopback server reachable from that backend process.
- Demo authentication is development-only. Set `NEXT_PUBLIC_DEMO_AUTH=false` and configure Clerk before a production build.
- The health endpoint is intentionally suitable for Railway-style probes: it pings the database and returns `503` when the DB is unavailable.
