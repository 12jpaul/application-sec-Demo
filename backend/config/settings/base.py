"""
Base settings shared by all environments.
Environment-specific files (dev.py, prod.py, test.py) import from here.
Secrets are loaded exclusively from environment variables via django-environ.
Never hard-code secrets here (Security rule 10 / T17).
"""
from datetime import timedelta
from pathlib import Path

import environ

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent.parent  # backend/

# ---------------------------------------------------------------------------
# django-environ: reads .env when present; falls back to real env vars
# ---------------------------------------------------------------------------
env = environ.Env(
    DEBUG=(bool, False),
    ALLOWED_HOSTS=(list, []),
)
environ.Env.read_env(BASE_DIR / ".env", overwrite=False)

# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------
SECRET_KEY = env("SECRET_KEY")
DEBUG = env("DEBUG")
ALLOWED_HOSTS = env("ALLOWED_HOSTS")

# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------
INSTALLED_APPS = [
    # daphne must be before django.contrib.staticfiles (Daphne requirement)
    "daphne",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third-party
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",  # JWT refresh rotation (SR-02)
    "channels",
    "drf_spectacular",
    # SokoLink apps (populated in later phases)
    "accounts",
    "listings",
    "profiles",
    "messaging",
    "orders",
    "moderation",
    "audit",
    "integrations",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
            # Auto-escaping is on by default; never disable it (SR-08 / T10)
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# ---------------------------------------------------------------------------
# Database – overridden per environment
# ---------------------------------------------------------------------------
DATABASES = {
    "default": env.db("DATABASE_URL"),
}

# ---------------------------------------------------------------------------
# Password hashing – Argon2 first (SR-01 / T1)
# ---------------------------------------------------------------------------
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",  # fallback for migrations
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": 10}},  # SR-01: ≥ 10 characters
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ---------------------------------------------------------------------------
# Internationalisation
# ---------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Africa/Kigali"
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Static and media files
# ---------------------------------------------------------------------------
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = env("MEDIA_URL", default="/media/")
MEDIA_ROOT = BASE_DIR / env("MEDIA_ROOT", default="media/")

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Django REST Framework – secure defaults
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    # Default deny: every endpoint requires authentication (SR-03 / T8)
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
    # Rate limiting – overridden per-view where tighter limits are needed (SR-11 / T13)
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "20/min",
        "user": "200/min",
    },
    # OpenAPI schema generation
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    # Return generic errors; stack traces only in DEBUG mode (Security rule 12)
    "EXCEPTION_HANDLER": "rest_framework.views.exception_handler",
}

# ---------------------------------------------------------------------------
# JWT – djangorestframework-simplejwt (SR-02 / T2)
# ---------------------------------------------------------------------------
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),   # short-lived access tokens
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,       # each use issues a new refresh token
    "BLACKLIST_AFTER_ROTATION": True,    # old refresh tokens are invalidated
    "UPDATE_LAST_LOGIN": True,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": env("SECRET_KEY"),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    # Never put the token value in logs (T17)
    "TOKEN_OBTAIN_SERIALIZER": "rest_framework_simplejwt.serializers.TokenObtainPairSerializer",
}

# ---------------------------------------------------------------------------
# Django Channels – Redis channel layer (SR-10: WebSockets over TLS)
# ---------------------------------------------------------------------------
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [env("REDIS_URL", default="redis://127.0.0.1:6379/0")],
        },
    },
}

# ---------------------------------------------------------------------------
# API documentation (drf-spectacular)
# ---------------------------------------------------------------------------
SPECTACULAR_SETTINGS = {
    "TITLE": "SokoLink API",
    "DESCRIPTION": "Secure local marketplace API – CIS 4163 Application Security Technologies",
    "VERSION": "0.1.0",
    "SERVE_INCLUDE_SCHEMA": False,
}

# ---------------------------------------------------------------------------
# Logging – security events only; NEVER log passwords, OTPs, tokens (T17 / SR-12)
# ---------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "require_debug_false": {
            "()": "django.utils.log.RequireDebugFalse",
        },
    },
    "formatters": {
        "verbose": {
            "format": "{asctime} {levelname} {name} {message}",
            "style": "{",
        },
        "simple": {
            "format": "{levelname} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "simple",
        },
        # Audit events go to a dedicated logger; the AuditLog model is the
        # primary store (SR-12). This handler is a secondary safety net.
        "security_console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
        "django.request": {
            "handlers": ["console"],
            "level": "ERROR",   # no request bodies in logs (T17)
            "propagate": False,
        },
        # sokolink.security captures: login, OTP failures, role changes,
        # payout changes, order status, moderation, payment callbacks (SR-12).
        # Rule: log the WHAT and WHO, never the secret value.
        "sokolink.security": {
            "handlers": ["security_console"],
            "level": "INFO",
            "propagate": False,
        },
        "sokolink": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
