"""
Development settings.
Uses DEBUG=True, SQLite (optional override), console backends for email/SMS.
Never deploy this to production.
"""
from .base import *  # noqa: F401, F403

DEBUG = True

ALLOWED_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0"]

# In development keep the default SQLite so contributors don't need MySQL locally
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",  # noqa: F405
    }
}

# Use in-memory channel layer in dev (no Redis required)
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    }
}

# Console email (no SMTP needed in dev)
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# Allow non-HTTPS cookies in dev only
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# django-debug-toolbar can be added here if desired; never in prod
INTERNAL_IPS = ["127.0.0.1"]
