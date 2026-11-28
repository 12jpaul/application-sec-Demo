"""
Auth URL routing — mounted at /api/auth/ in config/urls.py.
"""

from django.urls import path

from accounts.views import (
    DeviceVerifyView,
    LoginView,
    LogoutView,
    PhoneVerifyView,
    RegisterView,
    TokenRefreshView,
)

urlpatterns = [
    path("register/", RegisterView.as_view(), name="auth-register"),
    path("verify-phone/", PhoneVerifyView.as_view(), name="auth-verify-phone"),
    path("login/", LoginView.as_view(), name="auth-login"),
    path("verify-device/", DeviceVerifyView.as_view(), name="auth-verify-device"),
    path("logout/", LogoutView.as_view(), name="auth-logout"),
    path("token/refresh/", TokenRefreshView.as_view(), name="auth-token-refresh"),
]
