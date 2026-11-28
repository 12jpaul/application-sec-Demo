"""
ST-08 – Privilege escalation.

Threat : T8 (Privilege escalation)
Control: Default-deny DRF permissions (IsAuthenticated); role flags additive
         (is_moderator, is_staff); IsModerator and IsOwner restrict endpoints.
         Admin panel at non-default path behind VPN in production.

Pass when:
  - Requests without a valid JWT return 401 on IsAuthenticated endpoints.
  - Regular (non-moderator) users fail IsModerator.has_permission.
  - A user with is_moderator=True passes IsModerator.has_permission.
  - A JWT for an inactive user is rejected with 401.
  - IsOwner.has_object_permission returns False for non-owners.
  - IsOwner.has_object_permission returns True for the owner.
"""

import pytest
from rest_framework.test import APIRequestFactory

from accounts.models import User
from accounts.permissions import IsModerator, IsOwner

LOGOUT_URL = "/api/auth/logout/"


@pytest.mark.django_db
def test_st08_unauthenticated_gets_401(api_client):
    """
    Requests without a valid JWT must return 401 on IsAuthenticated endpoints.
    LogoutView uses permission_classes = [IsAuthenticated] (default-deny T8/SR-03).
    """
    res = api_client.post(LOGOUT_URL, {"refresh": "dummy-token"})
    assert res.status_code == 401


@pytest.mark.django_db
def test_st08_non_moderator_blocked_by_is_moderator(make_verified_user):
    """
    A regular user (is_moderator=False) must not pass IsModerator.has_permission.
    Basic access does not escalate to moderator access — additive role model (T8/SR-03).
    """
    user = make_verified_user(phone="+250788208002")
    factory = APIRequestFactory()
    request = factory.get("/")
    request.user = user

    perm = IsModerator()
    assert perm.has_permission(request, None) is False


@pytest.mark.django_db
def test_st08_moderator_flag_grants_is_moderator(make_verified_user):
    """
    A user with is_moderator=True must pass IsModerator.has_permission.
    Baseline to confirm the additive flag model works (T8/SR-03).
    """
    moderator = make_verified_user(phone="+250788208003", is_moderator=True)
    factory = APIRequestFactory()
    request = factory.get("/")
    request.user = moderator

    perm = IsModerator()
    assert perm.has_permission(request, None) is True


@pytest.mark.django_db
def test_st08_inactive_user_blocked(api_client, make_verified_user, tokens_for):
    """
    A JWT issued to a user whose account is later deactivated must be rejected.
    simplejwt's get_user() raises AuthenticationFailed when is_active=False (T8/SR-03).
    Prevents use of stolen tokens after account suspension.
    """
    user = make_verified_user(phone="+250788208004")
    access, _ = tokens_for(user)

    # Deactivate the account after the token was issued
    User.objects.filter(pk=user.pk).update(is_active=False)

    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
    res = api_client.post(LOGOUT_URL, {"refresh": "dummy"})
    assert res.status_code == 401


@pytest.mark.django_db
def test_st08_is_owner_rejects_non_owner(make_verified_user):
    """
    IsOwner.has_object_permission must return False when the request user is
    not the object owner (T3/SR-03: prevents IDOR; view must return 404).
    """
    owner = make_verified_user(phone="+250788208005")
    other = make_verified_user(phone="+250788208006")

    factory = APIRequestFactory()
    request = factory.get("/")
    request.user = other  # not the owner

    perm = IsOwner()
    # object is the owner user; other must be rejected
    assert perm.has_object_permission(request, None, owner) is False


@pytest.mark.django_db
def test_st08_is_owner_accepts_owner(make_verified_user):
    """
    IsOwner.has_object_permission must return True for the object owner (T3/SR-03).
    """
    owner = make_verified_user(phone="+250788208007")

    factory = APIRequestFactory()
    request = factory.get("/")
    request.user = owner

    perm = IsOwner()
    assert perm.has_object_permission(request, None, owner) is True
