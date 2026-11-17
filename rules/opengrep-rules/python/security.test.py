"""Annotated tests for python/security.yaml."""
import hashlib
import os
import pickle
import subprocess
from os import getenv

import environ
from decouple import config

env = environ.Env()


def tainted(user_input):
    # ruleid: scp.python.exec.eval
    eval(user_input)
    # ruleid: scp.python.exec.eval
    exec(user_input)
    # ruleid: scp.python.crypto.weak-md5
    hashlib.md5(b"x").hexdigest()
    # ruleid: scp.python.crypto.weak-md5
    hashlib.sha1(b"x").hexdigest()
    # ruleid: scp.python.deserialization.pickle
    pickle.loads(user_input)
    # ruleid: scp.python.injection.command
    os.system("echo " + user_input)
    # ruleid: scp.python.injection.command
    subprocess.call("ls " + user_input, shell=True)


def safe(data):
    # ok: scp.python.exec.eval
    compile(data, "<s>", "eval")
    # ok: scp.python.crypto.weak-md5
    hashlib.sha256(b"x").hexdigest()
    # ok: scp.python.injection.command
    subprocess.run(["ls", data], shell=False)


# Secrets read from the environment with a literal fallback.
# ruleid: scp.python.secrets.env-fallback-literal
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "django-insecure-0123456789abcdef")
# ruleid: scp.python.secrets.env-fallback-literal
JWT_SECRET = getenv("JWT_SECRET", "dev-secret")
# ruleid: scp.python.secrets.env-fallback-literal
DB_PASSWORD = os.getenv("DB_PASSWORD") or "postgres"
# ruleid: scp.python.secrets.env-fallback-literal
API_KEY = config("PAYMENT_API_KEY", default="test-key")
# ruleid: scp.python.secrets.env-fallback-literal
SIGNING = env.str("SIGNING_KEY", default="changeme")

# ok: scp.python.secrets.env-fallback-literal
STRICT = os.environ["DJANGO_SECRET_KEY"]
# ok: scp.python.secrets.env-fallback-literal
NO_DEFAULT = os.getenv("JWT_SECRET")
# ok: scp.python.secrets.env-fallback-literal
EMPTY = os.getenv("JWT_SECRET", "")
# ok: scp.python.secrets.env-fallback-literal
SETTINGS = os.environ.setdefault("DJANGO_SETTINGS_MODULE", "app.settings")
# ok: scp.python.secrets.env-fallback-literal
TTL = os.getenv("TOKEN_TTL", "3600")
# ok: scp.python.secrets.env-fallback-literal
HOST = os.getenv("DB_HOST", "localhost")
