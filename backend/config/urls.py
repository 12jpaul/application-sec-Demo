"""
Root URL configuration.
Feature URLs are added in later phases as apps are built out.
"""
from django.contrib import admin
from django.http import JsonResponse
from django.urls import include, path


def health(_request):
    """
    GET /api/health/
    Lightweight liveness probe used by CI and load balancers.
    Returns HTTP 200 with {"status": "ok"}.
    No authentication required (unauthenticated callers need to know the
    service is up). The endpoint reveals no internal state.
    """
    return JsonResponse({"status": "ok"})


urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/health/", health, name="health"),
    # JWT auth endpoints – added in Phase 2
    # path("api/auth/", include("accounts.urls")),
    # Feature endpoints added per phase:
    # path("api/", include("listings.urls")),
    # path("api/", include("orders.urls")),
    # path("api/", include("messaging.urls")),
    # path("api/", include("moderation.urls")),
]
