"""
Test settings.
Uses SQLite in-memory so CI does not need MySQL service containers or
libmysqlclient-dev. All other security settings inherited from base.py.

Why SQLite for tests: mysqlclient requires compiled C extensions and a running
MySQL server. Using SQLite in-memory keeps CI fast and dependency-free while
still exercising the same Django ORM query logic. Prod parity is verified in
the staging deployment (Phase 9).
"""

import os

# Seed required env vars BEFORE base.py imports them via django-environ.
# These are test-only dummy values and are never used in production.
os.environ.setdefault(
    "SECRET_KEY", "django-insecure-test-only-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)  # nosemgrep # noqa: S105
os.environ.setdefault("DATABASE_URL", "sqlite://:memory:")
# T2/SR-02: test-only HMAC key; never used outside CI/test environments
os.environ.setdefault(
    "OTP_HMAC_KEY",
    "test-otp-hmac-key-not-real-aaaaaaaaaaaaaaaaaaaaa",
)  # nosemgrep # noqa: S105
# T13/SR-11: use in-memory cache (no Redis needed in CI)
os.environ.setdefault("CACHE_URL", "locmemcache://")
# T13/SR-11: use in-memory SMS backend (OTPs readable from integrations.sms._outbox)
os.environ.setdefault("SMS_BACKEND", "integrations.sms.LocMemSmsBackend")
# T13/SR-11: 0 proxies in test — X-Forwarded-For is not trusted
os.environ.setdefault("NUM_PROXIES", "0")

from .base import *  # noqa: F401, F403

# ---------------------------------------------------------------------------
# In-memory SQLite – fast, isolated, no MySQL required in CI
# ---------------------------------------------------------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

# ---------------------------------------------------------------------------
# In-memory channel layer – no Redis required in CI
# ---------------------------------------------------------------------------
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    }
}

# ---------------------------------------------------------------------------
# Minimal secrets for tests (not real values)
# ---------------------------------------------------------------------------
SECRET_KEY = "django-insecure-test-only-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # nosemgrep # noqa: S105

DEBUG = False  # keep DEBUG=False to catch prod-only code paths

ALLOWED_HOSTS = ["testserver", "localhost"]

# Disable migrations for speed (use sync_db instead)
# Note: re-enable when testing migration logic specifically
# MIGRATION_MODULES = {app: None for app in INSTALLED_APPS}

EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
