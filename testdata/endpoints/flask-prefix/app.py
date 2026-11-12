"""register_blueprint replaces the blueprint's own url_prefix."""
from flask import Blueprint, Flask

app = Flask(__name__)
bp = Blueprint("bp", __name__, url_prefix="/internal")


@bp.post("/transfer")
def transfer():
    return "ok"


app.register_blueprint(bp, url_prefix="/api")
