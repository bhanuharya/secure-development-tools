"""Annotated tests for rules/endpoint-facts/python.yaml."""
from flask import Blueprint, Flask
from fastapi import APIRouter, Depends, FastAPI, Security

# ruleid: fact.py.flask_app
app = Flask(__name__)

# ruleid: fact.py.fastapi_app
api = FastAPI()

# ruleid: fact.py.fastapi_app, fact.py.fastapi_app_deps
secured = FastAPI(dependencies=[Depends(require_auth)])

# ruleid: fact.py.blueprint
public = Blueprint("public", __name__, url_prefix="/public")

# ruleid: fact.py.blueprint
admin = Blueprint("admin", __name__)

# ruleid: fact.py.apirouter
r1 = APIRouter(prefix="/api", dependencies=[Depends(verify_token)])

# ruleid: fact.py.apirouter
r2 = APIRouter(dependencies=[Depends(verify_token)], prefix="/api")

# ruleid: fact.py.apirouter
r3 = APIRouter(prefix="/api")

# ruleid: fact.py.apirouter
r4 = APIRouter(dependencies=[Depends(verify_token)])

# ruleid: fact.py.apirouter
r5 = APIRouter()

# ruleid: fact.py.include_bare
app.include_router(r5)

# ruleid: fact.py.include_prefix
app.include_router(r3, prefix="/v1")

# ruleid: fact.py.include_deps
app.include_router(r4, dependencies=[Depends(require_user)])

# ruleid: fact.py.register_blueprint
app.register_blueprint(admin)

# ruleid: fact.py.register_blueprint
app.register_blueprint(public, url_prefix="/v2")

# ruleid: fact.py.route, fact.py.route_decorator
@app.route("/plain")
def plain():
    return None

# ruleid: fact.py.route, fact.py.route_decorator
@app.route("/orders", methods=["GET", "DELETE"])
def orders():
    return None

# ruleid: fact.py.route, fact.py.route_decorator
@app.route("/reports", methods=["POST"], endpoint="reports")
def reports():
    return None

# ruleid: fact.py.verb_route, fact.py.route_decorator
@api.get("/items")
def list_items():
    return None

# ruleid: fact.py.verb_route, fact.py.route_decorator
@api.post("/items", dependencies=[Depends(require_admin)], response_model=dict)
def create_item():
    return None

# ruleid: fact.py.decorator
@login_required
def login_only():
    return None

# ruleid: fact.py.decorator
@jwt_required()
def jwt_only():
    return None

# ruleid: fact.py.decorator
@roles_required("admin", "operator")
def role_only():
    return None

# ruleid: fact.py.param_gate
def one(user=Depends(require_user)):
    return user

# ruleid: fact.py.param_gate
def two(user: User = Depends(require_user)):
    return user

# ruleid: fact.py.param_gate
def three(user=Security(require_admin)):
    return user

# ruleid: fact.py.param_gate
def four(user: User = Security(require_admin)):
    return user
