from fastapi import APIRouter

router = APIRouter()


@router.get("/me")
def me():
    return {}


@router.post("/{user_id}/reset-password")
def reset_password(user_id: str):
    return {}
