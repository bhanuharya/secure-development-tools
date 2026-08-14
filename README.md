# Secure SDLC Platform

Security-scan orchestration platform: upload or pull code (Bitbucket),
run scanner engines (SAST/DAST/secrets/dependencies), collect findings,
and report.

## Stack

- Backend: FastAPI + SQLModel (SQLite), routers under `src/api/`
- Dashboard: vanilla JS static app under `src/dashboard/`
- Tests: pytest + pytest-asyncio (`tests/`)
- Engines/config: `rules/` · fixtures: `fixtures/`

## Quickstart

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

Run tests:

```bash
.venv/bin/pytest
```

## Layout notes

- `data/` (SQLite + reports), `scan_work/` (scan artifacts), `.env`
  are runtime/generated and gitignored — never commit them.
- Access model: internal tooling; bind to trusted networks only.
- Dependencies use `>=` ranges — pin with `pip freeze` before prod deploy.

## Security posture (OWASP quick pass)

| Area | Verdict |
|---|---|
| Injection | Parameterized via SQLModel/ORM; input validation in routers |
| Secrets handling | `.env` gitignored; gitleaks engine included as scanner |
| AuthN/AuthZ | TODO — add auth before any non-trusted exposure |
| Security headers | Add middleware (CSP, nosniff, XFO) before serving dashboard |
| Dependencies | Audit before deploy (`uvx pip-audit -r requirements.txt`) |
| XSS | Dashboard uses vanilla JS; review dynamic HTML rendering |
| Known vulns | Track via pip-audit; pin versions at release |
