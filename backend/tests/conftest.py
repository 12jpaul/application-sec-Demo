"""
Shared test fixtures for the SokoLink security test suite.

reset_between_tests (autouse) – clears the Django cache and SMS outbox
    before and after every test so throttle counts and OTP state never
    bleed between tests (T13/SR-11).

make_verified_user – factory for active, phone-verified User instances.
tokens_for         – issues (access, refresh) token strings directly for a user.
"""

import itertools

import pytest
from django.core.cache import cache
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

import integrations.sms as sms_module
from accounts.models import User


@pytest.fixture(autouse=True)
def reset_between_tests():
    """Clear cache and SMS outbox before and after every test (T13/SR-11)."""
    cache.clear()
    sms_module._outbox.clear()
    yield
    cache.clear()
    sms_module._outbox.clear()


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def make_verified_user(db):
    """
    Factory for creating active, phone-verified User instances.

    Usage:
        user = make_verified_user()                       # auto-phone
        user = make_verified_user(phone="+250788001001")  # explicit phone
        user = make_verified_user(is_moderator=True)      # moderator role
    """
    _counter = itertools.count(1)

    def _make(phone=None, password="Str0ng_Pass!1", is_moderator=False):
        idx = next(_counter)
        p = phone or f"+25078900{idx:04d}"
        user = User.objects.create_user(
            phone=p,
            password=password,
            display_name=f"Test User {idx}",
            is_active=True,
            is_phone_verified=True,
        )
        if is_moderator:
            User.objects.filter(pk=user.pk).update(is_moderator=True)
            user.refresh_from_db()
        return user

    return _make


@pytest.fixture
def tokens_for():
    """
    Return (access_token_str, refresh_token_str) for a user, bypassing the
    login view.  Used when the test needs tokens without exercising the full
    auth flow (e.g. logout ownership, inactive-user, token rotation tests).
    """

    def _issue(user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token), str(refresh)

    return _issue
