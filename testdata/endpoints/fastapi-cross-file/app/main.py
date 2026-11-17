from fastapi import Depends, FastAPI

from app.api import api_router
from app.auth import require_user
from app.routers import health

app = FastAPI()
app.include_router(api_router, prefix="/api/v1", dependencies=[Depends(require_user)])
app.include_router(health.router)
