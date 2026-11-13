from flask import Blueprint
from flask_login import login_required

billing_bp = Blueprint("billing", __name__, url_prefix="/ignored")


@billing_bp.route("/invoices", methods=["POST"])
@login_required
def create_invoice():
    return "", 201


@billing_bp.route("/admin/refund", methods=["POST"])
def refund():
    return "", 200
