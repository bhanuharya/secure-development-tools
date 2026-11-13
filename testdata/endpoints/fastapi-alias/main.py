"""Two registrations on one handler: each keeps its own dependencies."""
from fastapi import Depends, FastAPI

app = FastAPI()


@app.post("/admin/secure", dependencies=[Depends(require_auth)])
@app.post("/admin/open")
def update():
    return {}
