"""Catalog API: FastAPI routers, dependencies and parameter gates."""
from fastapi import APIRouter, Depends, FastAPI, Security

from catalog.auth import require_admin, require_api_key, require_user, verify_token
from catalog.external import external_router

app = FastAPI()
router = APIRouter(prefix="/api/v1", dependencies=[Depends(verify_token)])
open_router = APIRouter(prefix="/open")


@app.get("/health")
def health():
    return {"status": "ok"}


@router.get("/items")
def list_items():
    return []


@router.get("/items/{item_id}")
def get_item(item_id: int):
    return {"id": item_id}


@router.post("/items", dependencies=[Depends(require_admin)])
def create_item(item: dict, user=Depends(require_user)):
    return item


@router.delete("/items/{item_id}")
def delete_item(item_id: int, user: User = Security(require_admin)):
    return {"deleted": item_id}


@open_router.put("/widgets/{widget_id}")
def update_widget(widget_id: int, user=Depends(require_user)):
    return {"id": widget_id}


@external_router.get("/imports")
def list_imports():
    return []


app.include_router(router)
app.include_router(open_router, prefix="/beta", dependencies=[Depends(require_api_key)])
