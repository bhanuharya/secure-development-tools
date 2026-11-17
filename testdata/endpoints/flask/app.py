"""Orders API: Flask routes, blueprints and gate decorators."""
from flask import Blueprint, Flask, jsonify
from flask_jwt_extended import jwt_required
from flask_login import login_required

from orders.auth import roles_required
from billing.routes import billing

app = Flask(__name__)
public_api = Blueprint("public_api", __name__, url_prefix="/public")
admin_api = Blueprint("admin_api", __name__)


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/orders")
@login_required
def list_orders():
    return jsonify([])


@app.route("/orders/<int:order_id>", methods=["GET", "DELETE"])
@login_required
def order_detail(order_id):
    return jsonify(id=order_id)


@app.route("/admin/users", methods=["POST"])
@roles_required("admin")
def create_user():
    return jsonify(created=True)


@public_api.route("/catalog", methods=["GET"])
@jwt_required()
def catalog():
    return jsonify([])


@admin_api.route("/roles", methods=["PUT"])
@roles_required("admin", "operator")
def update_roles():
    return jsonify(updated=True)


@billing.route("/invoices", methods=["POST"])
def create_invoice():
    return jsonify(created=True)


app.register_blueprint(public_api)
app.register_blueprint(admin_api, url_prefix="/v2")
