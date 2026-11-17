"""Application dependencies reach direct routes and included routers."""
from fastapi import APIRouter, Depends, FastAPI

app = FastAPI(dependencies=[Depends(require_auth)])
router = APIRouter(prefix="/api", dependencies=[Depends(require_auth)])


@router.post("/transfer")
def transfer():
    return {}


@app.post("/admin/users")
def users():
    return {}


app.include_router(router)
