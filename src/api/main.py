from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from src.api.database import init_db
from src.api.routers import bitbucket, findings, projects, reports, scans, uploads
from src.api.security import AuthMiddleware, SecurityHeadersMiddleware

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("scp")

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    logger.info("control plane database ready")
    yield


app = FastAPI(title="Mirae Secure SDLC - Unified SAST/DAST Control Plane", version="0.2.0", lifespan=lifespan)

# Last-added middleware runs first: SecurityHeaders wraps everything (incl.
# auth 401s), Auth sits above the routers and the static dashboard mount.
app.add_middleware(AuthMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(projects.router)
app.include_router(bitbucket.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(uploads.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "secure-sdlc-control-plane", "version": "0.2.0"}


@app.get("/api/scanners/status")
def scanners_status():
    from src.scanners.availability import engine_statuses

    return engine_statuses()


if DASHBOARD_DIR.exists():
    app.mount("/", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")