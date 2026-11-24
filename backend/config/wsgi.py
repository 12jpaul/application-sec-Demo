"""
WSGI config – used for synchronous HTTP (Gunicorn, etc.).
Production uses Daphne via ASGI; this file is kept for compatibility.
"""
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

application = get_wsgi_application()
