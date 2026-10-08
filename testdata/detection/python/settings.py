import hashlib

DEBUG = True
SECRET_KEY = "django-insecure-9x7!hardcoded-secret-key"
DATABASE_PASSWORD = "Pr0d!Passw0rd"


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
