"""Two functions share a name; gates belong to the function that has them."""
from flask import Flask

app = Flask(__name__)


@app.post("/admin/secure")
@login_required
def update():
    return "secure"


@app.post("/transfer")
def update():
    return "open"
