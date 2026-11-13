from fastapi import APIRouter, Depends

from app.auth import require_admin_role

router = APIRouter(dependencies=[Depends(require_admin_role)])


@router.delete("/users/{user_id}")
def delete_user(user_id: str):
    return {}
