import os

# Runs with this key whenever DJANGO_SECRET_KEY is not set.
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-only-secret-key-change-me")
