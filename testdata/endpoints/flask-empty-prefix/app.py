from flask import Blueprint, Flask

app = Flask(__name__)
bp = Blueprint("ops", __name__, url_prefix="/public")


@bp.post("/transfer")
def transfer():
    return {"ok": True}


app.register_blueprint(bp, url_prefix="")
