"""
ASGI config – used by Daphne in production and by Django Channels for WebSockets.
"""
import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

# Routing is expanded in Phase 5 (messaging) with the chat consumer URLs.
application = ProtocolTypeRouter(
    {
        "http": get_asgi_application(),
        # WebSocket routing added in Phase 5:
        # "websocket": AllowedHostsOriginValidator(
        #     AuthMiddlewareStack(URLRouter(websocket_urlpatterns))
        # ),
    }
)
