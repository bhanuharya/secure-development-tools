"""The decorator above a route decorator wraps it, not the route handler."""
from flask import Flask

app = Flask(__name__)


@login_required
@app.post("/transfer")
def transfer():
    return "ok"
