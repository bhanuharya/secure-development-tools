import hmac
import random
import secrets


# ---- mass-assignment-from-request

def create_user_unsafe(request):
    # ruleid: scp.python.logic.mass-assignment-from-request
    user = User(**request.json)
    return user


def update_user_unsafe(request, user):
    # ruleid: scp.python.logic.mass-assignment-from-request
    for k, v in request.get_json().items():
        setattr(user, k, v)


def create_user_safe(request):
    data = request.get_json()
    # ok: scp.python.logic.mass-assignment-from-request
    user = User(display_name=data["display_name"], email=data["email"])
    return user


# ---- weak-prng-otp-or-token

def make_otp_unsafe():
    # ruleid: scp.python.logic.weak-prng-otp-or-token
    otp_code = random.randint(100000, 999999)
    # ruleid: scp.python.logic.weak-prng-otp-or-token
    reset_token = "".join(random.choices("abcdef0123456789", k=32))
    return otp_code, reset_token


def make_otp_safe():
    # ok: scp.python.logic.weak-prng-otp-or-token
    otp_code = secrets.randbelow(900000) + 100000
    # ok: scp.python.logic.weak-prng-otp-or-token
    backoff_ms = random.randint(50, 200)
    return otp_code, backoff_ms


# ---- non-constant-time-token-compare

def check_webhook_unsafe(expected_signature, provided):
    # ruleid: scp.python.logic.non-constant-time-token-compare
    return expected_signature == provided


def check_webhook_safe(expected_signature, provided):
    # ok: scp.python.logic.non-constant-time-token-compare
    if expected_signature == "":
        return False
    # ok: scp.python.logic.non-constant-time-token-compare
    return hmac.compare_digest(expected_signature, provided)


# ---- trust-spoofable-identity-header

def read_headers(request):
    # ruleid: scp.python.logic.trust-spoofable-identity-header
    uid = request.headers.get("X-User-Id")
    # ruleid: scp.python.logic.trust-spoofable-identity-header
    role = request.headers["X-Role"]
    # ok: scp.python.logic.trust-spoofable-identity-header
    trace = request.headers.get("X-Request-Id")
    return uid, role, trace


# ---- unbounded-pagination-limit

def list_items_unsafe(request, db):
    limit = int(request.args.get("limit", 20))
    # ruleid: scp.python.logic.unbounded-pagination-limit
    return db.query(Item).limit(limit).all()


def list_items_safe(request, db):
    limit = min(int(request.args.get("limit", 20)), 100)
    # ok: scp.python.logic.unbounded-pagination-limit
    return db.query(Item).limit(limit).all()
