# Q-SHIELD frontend integration notes

This update preserves the existing assisted migration, project comparison, PQC migration lab and Module 7.10 audit screens, and adds a connected security-operations overview.

## New live API connections

- `GET /api/health` — backend/database connection indicator.
- `GET /api/projects` — project selector and project count.
- `POST /api/scanner/upload` — ZIP upload, static scan and inventory generation.
- `GET /api/scanner/summary/<project_id>` — severity summary.
- `GET /api/inventory/<project_id>` — cryptographic inventory table.
- `GET /api/assessment/<project_id>` and `POST /api/assessment/<project_id>/generate` — readiness assessment.
- `GET /api/recommendations/<project_id>` and `POST /api/recommendations/<project_id>/generate` — PQC recommendations.
- `GET /api/benchmarks/catalog`, `POST /api/benchmarks/run`, `GET /api/benchmarks/runs` — provider catalog, comparative benchmark execution and persisted history.

## Existing workflows retained

- Human-approved assisted migration.
- Classical-versus-migrated project comparison, PDF/evidence downloads and PQC verification.
- ML-KEM-768 demonstration migration.
- Module 7.10 end-to-end audit, governance decisions, PDF and evidence ZIP.

## Run locally

1. Keep the Flask backend running at `http://127.0.0.1:5000`.
2. In `frontend`, run `npm ci` then `npm run dev`.
3. Open `http://127.0.0.1:5173`.
4. If the API is hosted elsewhere, set `VITE_API_BASE_URL` in `frontend/.env`.

The frontend source is included without `node_modules`; install dependencies locally using the lockfile. No backend files are changed by this frontend integration ZIP.

## Scope notes

The overview uses the existing scanner and inventory APIs. Readiness is presented as the backend's heuristic assessment, not a certification. Scanner results are static analysis only. Comparative benchmarks are local provider microbenchmarks and are not universal performance rankings. X25519 key agreement is not a KEM.
