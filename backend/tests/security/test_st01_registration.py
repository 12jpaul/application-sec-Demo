"""
ST-01 – Fake seller / account enumeration via registration.

Threat : T1 (Fake seller accounts / phone enumeration)
Control: RegisterView returns the same 201 whether the phone is new, already
         registered, or squatted — prevents user enumeration.
         Unverified sign-ups older than 24 h are deleted; recent ones have
         credentials overwritten so only the legitimate owner can verify.

Pass when:
  - Registering a new phone returns 201 with the generic OTP message.
  - Registering an already-verified phone returns the same 201 (anti-enumeration).
  - Attempting login before phone verification returns 403.
  - A squatter's password is overwritten when the legitimate owner re-registers
    the same phone within 24 hours and verifies successfully.
"""

import pytest

import integrations.sms as sms_module

REGISTER_URL = "/api/auth/register/"
VERIFY_URL = "/api/auth/verify-phone/"
LOGIN_URL = "/api/auth/login/"

_GENERIC_201_MSG = "Verification code sent to your phone."


@pytest.mark.django_db
def test_st01_new_phone_returns_201(api_client):
    """Normal registration with an unseen phone returns 201 and the generic message."""
    res = api_client.post(
        REGISTER_URL,
        {
            "phone": "+250788101001",
            "display_name": "New User",
            "password": "Str0ng_Pass!1",
        },
    )
    assert res.status_code == 201
    assert res.data["detail"] == _GENERIC_201_MSG
    # OTP must have been dispatched to the SMS backend
    assert len(sms_module._outbox) == 1


@pytest.mark.django_db
def test_st01_existing_verified_phone_returns_same_201(api_client, make_verified_user):
    """
    Re-registering an already-verified phone returns the same 201 message.
    The response must not indicate whether the phone is taken (T1 anti-enumeration).
    No new OTP is dispatched for the silent 201 path.
    """
    make_verified_user(phone="+250788101002")

    res = api_client.post(
        REGISTER_URL,
        {
            "phone": "+250788101002",
            "display_name": "Re-register Attempt",
            "password": "Str0ng_Pass!1",
        },
    )
    assert res.status_code == 201
    assert res.data["detail"] == _GENERIC_201_MSG
    # Active phone → silent 201; no SMS sent (would leak that the phone is registered)
    assert len(sms_module._outbox) == 0


@pytest.mark.django_db
def test_st01_login_blocked_before_phone_verification(api_client):
    """
    A user who registered but has not verified their phone must not be able
    to log in.  Returns 403 so the client knows to prompt for verification
    (SR-01/T1).
    """
    api_client.post(
        REGISTER_URL,
        {
            "phone": "+250788101003",
            "display_name": "Unverified User",
            "password": "Str0ng_Pass!1",
        },
    )

    res = api_client.post(
        LOGIN_URL,
        {
            "phone": "+250788101003",
            "password": "Str0ng_Pass!1",
        },
    )
    assert res.status_code == 403


@pytest.mark.django_db
def test_st01_squatting_prevention(api_client):
    """
    Phone-squatting prevention (T1):
      1. Squatter registers the victim's phone with their own password.
      2. Victim re-registers within 24 h → credentials are overwritten.
      3. Victim receives a fresh OTP and verifies successfully.
      4. Squatter's old password is rejected.
      5. Victim's password is accepted (device OTP required, not 401/403).
    """
    phone = "+250788101004"

    # --- Squatter registers ---
    api_client.post(
        REGISTER_URL,
        {
            "phone": phone,
            "display_name": "Squatter",
            "password": "Squat_Pass!1_xx",
        },
    )
    sms_module._outbox.clear()  # ignore squatter's OTP

    # --- Victim re-registers within 24 h → credential overwrite ---
    api_client.post(
        REGISTER_URL,
        {
            "phone": phone,
            "display_name": "Victim",
            "password": "Victim_Pass!1_v",
        },
    )
    assert len(sms_module._outbox) == 1, "Victim must receive a fresh OTP"

    # --- Victim verifies using the latest OTP ---
    code = sms_module._outbox[-1]["code"]
    res = api_client.post(VERIFY_URL, {"phone": phone, "code": code})
    assert res.status_code == 200, "Verification must succeed for the victim"

    # --- Squatter's old password must be rejected ---
    res = api_client.post(
        LOGIN_URL,
        {
            "phone": phone,
            "password": "Squat_Pass!1_xx",
        },
    )
    assert res.status_code == 401  # squatter's old password must not work

    # --- Victim's password must be accepted ---
    res = api_client.post(
        LOGIN_URL,
        {
            "phone": phone,
            "password": "Victim_Pass!1_v",
        },
    )
    # No trusted device registered → device_verification_required (not 401/403)
    assert res.status_code == 200
    assert res.data.get("action") == "device_verification_required"
