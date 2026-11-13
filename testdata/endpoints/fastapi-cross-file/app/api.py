from fastapi import APIRouter

from .routers.users import router as users_router
from .routers import admin

api_router = APIRouter()
api_router.include_router(users_router, prefix="/users")
api_router.include_router(admin.router, prefix="/admin")
