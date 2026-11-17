from fastapi import APIRouter

# Not included anywhere in the service.
router = APIRouter()


@router.post("/payouts")
def payout():
    return {}
