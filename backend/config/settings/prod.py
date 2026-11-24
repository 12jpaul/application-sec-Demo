"""
Production settings.
All security headers and HTTPS enforcement are active here.
Deployed behind Nginx (see docs/deployment-checklist.md).
"""
import environ

from .base import *  # noqa: F401, F403

env = environ.Env()

# ---------------------------------------------------------------------------
# Core – hard OFF in production (Security rule 12)
# ---------------------------------------------------------------------------
DEBUG = False

ALLOWED_HOSTS = env.list("ALLOWED_HOSTS")  # e.g. ["sokolink.rw", "api.sokolink.rw"]

# ---------------------------------------------------------------------------
# Database – MySQL in production (T9: encryption at rest, least-privilege user)
# ---------------------------------------------------------------------------
DATABASES = {
    "default": env.db("DATABASE_URL"),  # mysql://user:pass@host/db
}

# ---------------------------------------------------------------------------
# HTTPS enforcement (SR-10 / T16)
# ---------------------------------------------------------------------------
SECURE_SSL_REDIRECT = True

# Tell Django that Nginx has already terminated TLS and forwarded the header
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# ---------------------------------------------------------------------------
# HSTS – tell browsers to only connect over HTTPS (SR-10)
# ---------------------------------------------------------------------------
SECURE_HSTS_SECONDS = 31536000          # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# ---------------------------------------------------------------------------
# Cookie security (T2: account takeover)
# ---------------------------------------------------------------------------
SESSION_COOKIE_SECURE = True    # only sent over HTTPS
CSRF_COOKIE_SECURE = True       # only sent over HTTPS
SESSION_COOKIE_HTTPONLY = True  # not accessible from JavaScript
CSRF_COOKIE_HTTPONLY = True

# ---------------------------------------------------------------------------
# Additional security headers
# ---------------------------------------------------------------------------
SECURE_CONTENT_TYPE_NOSNIFF = True      # prevent MIME-type sniffing (T10)
X_FRAME_OPTIONS = "DENY"                # prevent clickjacking (T10)
SECURE_REFERRER_POLICY = "same-origin"  # limit Referer header leakage (T9)

# ---------------------------------------------------------------------------
# CSRF trusted origins – loaded from env (comma-separated)
# ---------------------------------------------------------------------------
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=[])

# ---------------------------------------------------------------------------
# Channels – Redis in production (must use TLS in prod: rediss://)
# ---------------------------------------------------------------------------
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [env("REDIS_URL")],
        },
    },
}

# ---------------------------------------------------------------------------
# Email – real SMTP in production
# ---------------------------------------------------------------------------
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = env("EMAIL_HOST")
EMAIL_PORT = env.int("EMAIL_PORT", default=587)
EMAIL_HOST_USER = env("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD")
EMAIL_USE_TLS = True

# ---------------------------------------------------------------------------
# Logging – errors go to console (captured by systemd/Docker); security events
# to sokolink.security logger (and later to the AuditLog model in Phase 1+)
# ---------------------------------------------------------------------------
LOGGING["handlers"]["mail_admins"] = {  # noqa: F405
    "level": "ERROR",
    "class": "django.utils.log.AdminEmailHandler",
    "filters": ["require_debug_false"],  # noqa: F405
}
LOGGING["loggers"]["django.request"]["handlers"] = ["mail_admins", "console"]  # noqa: F405
