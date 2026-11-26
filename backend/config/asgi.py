"""
ASGI config – used by Daphne in production and by Django Channels for WebSockets.
"""

import os

from channels.routing import ProtocolTypeRouter
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")  # nosemgrep

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
