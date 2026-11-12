from fastapi import FastAPI

app = FastAPI()

DOCS = """
Example:
@app.post("/transfer")
async def transfer():
    return {}
"""


@app.post("/orders")
async def orders():
    """Example handler.

    @app.post("/internal")
    async def internal():
        return {}
    """
    return {}
