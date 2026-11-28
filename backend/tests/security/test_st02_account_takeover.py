"""
ST-02 – Account takeover / session hijacking.

Threat : T2 (Seller account takeover; payout number changed)
Control: OTP for new-device login; lockout after 5 wrong passwords (15 min);
         same 401 "Invalid credentials" for all failure paths (anti-enumeration);
         JWT refresh-token blacklist on logout; LogoutView validates token ownership.

Pass when:
  - 5 wrong passwords trigger a 15-minute lockout; failed_login_count resets to 0.
  - Locked account with correct password returns the same 401 as a wrong password.
  - Login from an unknown device returns {action: device_verification_required}.
  - After device OTP verification the same fingerprint returns tokens directly.
  - A blacklisted refresh token is rejected on the token-refresh endpoint.
  - The old refresh token is rejected after a rotation cycle.
  - Logout rejects a refresh token that belongs to a different user.
  - An OTP code is locked after 5 wrong attempts (brute-force protection).
"""

import pytest
from django.utils import timezone

import integrations.sms as sms_module
from accounts.models import OtpCode

LOGIN_URL = "/api/auth/login/"
REGISTER_URL = "/api/auth/register/"
VERIFY_URL = "/api/auth/verify-phone/"
VERIFY_DEVICE_URL = "/api/auth/verify-device/"
LOGOUT_URL = "/api/auth/logout/"
REFRESH_URL = "/api/auth/token/refresh/"

_PASSWORD = "Str0ng_Pass!1"


# ---------------------------------------------------------------------------
# Lockout (T2/SR-02)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_st02_lockout_after_5_failed_logins(api_client, make_verified_user):
    """
    5 consecutive wrong passwords must trigger a 15-minute lockout.
    failed_login_count must be reset to 0 when the lockout fires so the user
    gets 5 fresh attempts after the timeout expires (T2/SR-02).
    """
    user = make_verified_user(phone="+250788202001")

    for _ in range(5):
        api_client.post(LOGIN_URL, {"phone": user.phone, "password": "wrong-password!"})

    user.refresh_from_db()
    assert user.login_locked_until is not None
    assert user.login_locked_until > timezone.now()
    assert user.failed_login_count == 0, (
        "failed_login_count must be reset to 0 when lockout fires "
        "(ensures 5 fresh attempts are available after the 15-min window)"
    )


@pytest.mark.django_db
def test_st02_locked_account_same_401_as_wrong_password(api_client, make_verified_user):
    """
    A locked account with the correct password must return the same generic
    401 "Invalid credentials" as a wrong password — no hint that the account
    is locked (T2/SR-02 anti-enumeration).
    """
    user = make_verified_user(phone="+250788202002")

    for _ in range(5):
        api_client.post(LOGIN_URL, {"phone": user.phone, "password": "wrong-password!"})

    # Correct password while locked — must still return 401
    res = api_client.post(LOGIN_URL, {"phone": user.phone, "password": _PASSWORD})
    assert res.status_code == 401
    assert res.data["detail"] == "Invalid credentials."


# ---------------------------------------------------------------------------
# Device trust (T2/SR-02)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_st02_new_device_login_triggers_otp(api_client, make_verified_user):
    """Login from an unknown device must require OTP verification (T2/SR-02)."""
    user = make_verified_user(phone="+250788202003")

    res = api_client.post(
        LOGIN_URL,
        {
            "phone": user.phone,
            "password": _PASSWORD,
            "device_fingerprint": "brand-new-device-fp",
        },
    )
    assert res.status_code == 200
    assert res.data["action"] == "device_verification_required"
    assert len(sms_module._outbox) == 1


@pytest.mark.django_db
def test_st02_trusted_device_returns_tokens(api_client, make_verified_user):
    """
    After completing the new-device OTP flow, the same fingerprint must
    return tokens directly on subsequent logins without another OTP (T2/SR-02).
    """
    user = make_verified_user(phone="+250788202004")
    fp = "trusted-fp-abc123"

    # Step 1: login with new fingerprint → OTP required
    res = api_client.post(
        LOGIN_URL,
        {
            "phone": user.phone,
            "password": _PASSWORD,
            "device_fingerprint": fp,
        },
    )
    assert res.status_code == 200
    assert res.data["action"] == "device_verification_required"

    # Step 2: verify device OTP
    code = sms_module._outbox[-1]["code"]
    res = api_client.post(
        VERIFY_DEVICE_URL,
        {
            "phone": user.phone,
            "code": code,
            "device_fingerprint": fp,
        },
    )
    assert res.status_code == 200
    assert "access" in res.data

    # Step 3: login again with the same fingerprint → tokens without OTP
    sms_module._outbox.clear()
    res = api_client.post(
        LOGIN_URL,
        {
            "phone": user.phone,
            "password": _PASSWORD,
            "device_fingerprint": fp,
        },
    )
    assert res.status_code == 200
    assert "access" in res.data
    assert "action" not in res.data
    assert len(sms_module._outbox) == 0  # no OTP sent for trusted device


# ---------------------------------------------------------------------------
# JWT token lifecycle (T2/SR-02)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_st02_blacklisted_token_rejected_after_logout(
    api_client, make_verified_user, tokens_for
):
    """Refresh token must be unusable after the user logs out (T2/SR-02)."""
    user = make_verified_user(phone="+250788202005")
    access, refresh = tokens_for(user)

    # Logout — blacklists the refresh token
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
    res = api_client.post(LOGOUT_URL, {"refresh": refresh})
    assert res.status_code == 204

    # Blacklisted token must be rejected on the refresh endpoint
    api_client.credentials()
    res = api_client.post(REFRESH_URL, {"refresh": refresh})
    assert res.status_code == 401


@pytest.mark.django_db
def test_st02_old_refresh_token_rejected_after_rotation(
    api_client, make_verified_user, tokens_for
):
    """
    After a token refresh (rotation), the old refresh token must be blacklisted
    and rejected (ROTATE_REFRESH_TOKENS=True, BLACKLIST_AFTER_ROTATION=True).
    Prevents session fixation via stolen refresh tokens (T2/SR-02).
    """
    user = make_verified_user(phone="+250788202006")
    _, refresh_old = tokens_for(user)

    # First rotation — should succeed and issue a new refresh token
    res = api_client.post(REFRESH_URL, {"refresh": refresh_old})
    assert res.status_code == 200

    # Old token must now be rejected (blacklisted on rotation)
    res = api_client.post(REFRESH_URL, {"refresh": refresh_old})
    assert res.status_code == 401


@pytest.mark.django_db
def test_st02_logout_rejects_another_users_token(
    api_client, make_verified_user, tokens_for
):
    """
    A user must not be able to blacklist another user's refresh token (T2/SR-02).
    LogoutView verifies token["user_id"] == request.user.id before blacklisting.
    """
    user_a = make_verified_user(phone="+250788202007")
    user_b = make_verified_user(phone="+250788202008")

    access_a, _ = tokens_for(user_a)
    _, refresh_b = tokens_for(user_b)

    # Authenticated as user A, but submitting user B's refresh token
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_a}")
    res = api_client.post(LOGOUT_URL, {"refresh": refresh_b})
    assert res.status_code == 400
    assert "does not belong" in res.data["detail"]


# ---------------------------------------------------------------------------
# OTP brute-force protection (T2/SR-02)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_st02_otp_locked_after_5_wrong_codes(api_client):
    """
    5 consecutive wrong OTP codes must lock the OtpCode entry.
    The correct code must be rejected afterwards (can_attempt=False after 5
    failed attempts — T2/SR-02 brute-force protection).
    """
    phone = "+250788202009"

    # Register — creates OTP
    api_client.post(
        REGISTER_URL,
        {
            "phone": phone,
            "display_name": "BruteForce Test",
            "password": _PASSWORD,
        },
    )
    correct_code = sms_module._outbox[-1]["code"]

    # Submit 5 wrong codes
    for _ in range(5):
        api_client.post(VERIFY_URL, {"phone": phone, "code": "000000"})

    # Confirm attempt_count reached 5 in the database
    otp = OtpCode.objects.filter(
        user__phone=phone,
        purpose=OtpCode.Purpose.SIGNUP,
        is_used=False,
    ).first()
    assert otp is not None
    assert otp.attempt_count == 5
    assert not otp.can_attempt

    # Correct code must now be rejected due to lockout
    res = api_client.post(VERIFY_URL, {"phone": phone, "code": correct_code})
    assert res.status_code == 400
    assert "expired or locked" in res.data["detail"].lower()
