from fastapi import Depends, FastAPI

app = FastAPI()


def require_auth():
    return None


@app.post("/secure", dependencies=[Depends(require_auth)])
@app.post(
    "/transfer",
)
async def transfer():
    return {"ok": True}
