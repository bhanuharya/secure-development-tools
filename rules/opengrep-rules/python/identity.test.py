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
