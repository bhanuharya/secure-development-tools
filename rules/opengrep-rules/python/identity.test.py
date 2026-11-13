# Annotated tests for python/identity.yaml.
import logging

logger = logging.getLogger(__name__)


# ruleid: scp.python.authz.credential-change-by-request-id
@app.route("/users/<user_id>/reset-password", methods=["POST"])
@login_required
def reset_password(user_id):
    users.update_password(user_id, request.json["password"])
    return "ok"


# ruleid: scp.python.authz.credential-change-by-request-id
@router.put("/users/{user_id}/update-email")
def update_email(user_id: str, body: Change, db=Depends(get_db)):
    users.update_email(db, user_id, body.email)
    return {"ok": True}


# ok: scp.python.authz.credential-change-by-request-id
@app.route("/users/<user_id>/change-password", methods=["POST"])
@login_required
def change_own(user_id):
    if current_user.id != user_id:
        abort(403)
    users.change_password(user_id, request.json["old"], request.json["new"])
    return "ok"


# ok: scp.python.authz.credential-change-by-request-id
@router.put("/users/{user_id}/reset-pin")
def reset_pin(user_id: str, body: Change, admin=Depends(require_admin)):
    users.reset_pin(user_id)
    return {"ok": True}


# ok: scp.python.authz.credential-change-by-request-id
@router.put("/users/{user_id}/preferences")
def preferences(user_id: str, body: Preferences):
    users.update_preferences(user_id, body)
    return {"ok": True}


def check_pin(account, pin, fernet):
    # ruleid: scp.python.crypto.recoverable-password
    return fernet.decrypt(account.pin) == pin


def read_document(doc, fernet):
    # ok: scp.python.crypto.recoverable-password
    return fernet.decrypt(doc.content)


def check_hash(user, password):
    # ok: scp.python.crypto.recoverable-password
    return bcrypt.checkpw(password, user.password)


def login(username, password, otp, session):
    # ruleid: scp.python.logging.secret-in-log
    logger.info("login attempt %s %s", username, password)
    # ruleid: scp.python.logging.secret-in-log
    logging.debug(f"otp for {username} is {otp}")
    # ruleid: scp.python.logging.secret-in-log
    print("token", session.access_token)
    # ok: scp.python.logging.secret-in-log
    logger.info("login attempt %s", username)
    # ok: scp.python.logging.secret-in-log
    logger.debug("token length %d", len(session.access_token))
    # ok: scp.python.logging.secret-in-log
    logger.info("next page %s", session.next_page_token)


# ---- hardcoded-secret
# ruleid: scp.python.secrets.hardcoded-secret
SECRET_KEY = "Ex4mpleSecretValue91"
# ruleid: scp.python.secrets.hardcoded-secret
api_key = "abcDEF1234567890"
# ruleid: scp.python.secrets.hardcoded-secret
auth_token = "eyJhbGciOiJIUzI1NiJ9.abc123"


class SecretConfig:
    # ruleid: scp.python.secrets.hardcoded-secret
    client_secret = "f3a91c0d7b2e4a6c9d81"
    # ruleid: scp.python.secrets.hardcoded-secret
    password: str = "S3cretPass!2024"


# ok: scp.python.secrets.hardcoded-secret
field_secret = "client_secret"
# ok: scp.python.secrets.hardcoded-secret
header_secret = "X-Api-Key"
# ok: scp.python.secrets.hardcoded-secret
jwt_secret = "/oauth/token"
# ok: scp.python.secrets.hardcoded-secret
app_secret = "jwt.secret"
# ok: scp.python.secrets.hardcoded-secret
db_password = "changeme"
# ok: scp.python.secrets.hardcoded-secret
admin_password = "password"
# ok: scp.python.secrets.hardcoded-secret
user_password = "At least eight characters"
# ok: scp.python.secrets.hardcoded-secret
encryption_key = ""
# ok: scp.python.secrets.hardcoded-secret
signing_secret = "${SIGNING_KEY}"
# ok: scp.python.secrets.hardcoded-secret
token = "abc123456789"
# ok: scp.python.secrets.hardcoded-secret
private_key = "-----BEGIN PRIVATE KEY-----"
# ok: scp.python.secrets.hardcoded-secret
api_secret = "https://example.com/oauth/token"

# A JWT-shaped value is still material: the segments hold uppercase letters.
# ruleid: scp.python.secrets.hardcoded-secret
JWT_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcmRlcnMifQ.c2lnbmF0dXJl"
# ok: scp.python.secrets.hardcoded-secret
KEY_ORDERS_API_KEY = "orders.apikey"
# ok: scp.python.secrets.hardcoded-secret
KEY_JWT_PRIVATE_KEY = "auth.jwt.private_key_path"
# ok: scp.python.secrets.hardcoded-secret
MSG_SUCCESS_TOKEN = "success.token_issued"
# ok: scp.python.secrets.hardcoded-secret
VERIFY_PASSWORD = "/services/orders/api/authenticate"
