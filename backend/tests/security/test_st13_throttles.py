"""
ST-13 – Spam bots / SMS flooding.

Threat : T13 (Spam bots / SMS flooding)
Control: OtpPhoneThrottle (3/hour per normalised phone), OtpIpThrottle (20/hour
         per IP), LoginThrottle (10/15 min per IP); 60-second resend cooldown;
         NUM_PROXIES=0 so X-Forwarded-For cannot spoof IP throttles.

Pass when:
  - 4th OTP request for the same normalised phone (mixing E.164 and local
    format) returns 429 — proves normalisation shares one throttle counter.
  - A second new-device OTP request within 60 seconds returns 429 (cooldown).
  - The OTP code never appears in log output (T17/SR-12).
  - X-Forwarded-For cannot bypass the IP throttle when NUM_PROXIES=0.
"""

import logging

import pytest

import integrations.sms as sms_module

REGISTER_URL = "/api/auth/register/"
LOGIN_URL = "/api/auth/login/"

_PASSWORD = "Str0ng_Pass!1"


@pytest.mark.django_db
def test_st13_otp_phone_throttled_after_3_per_hour(api_client):
    """
    Four OTP requests for the same normalised phone in one hour triggers 429.

    Phone format normalisation is exercised: requests 1–2 use E.164, request 3
    uses the Rwanda local format (0788…) which normalises to the same counter
    key as +250788… (T13/SR-11).

    Re-registration clears the old unused OTP so the 60-second resend cooldown
    does not interfere; only the per-phone throttle counter is exercised here.
    """
    # Requests 1–2: E.164 format
    for _ in range(2):
        res = api_client.post(
            REGISTER_URL,
            {
                "phone": "+250788113001",
                "display_name": "Throttle Test",
                "password": _PASSWORD,
            },
        )
        assert res.status_code == 201

    # Request 3: local Rwanda format (normalises to +250788113001 → same throttle key)
    res = api_client.post(
        REGISTER_URL,
        {
            "phone": "0788113001",
            "display_name": "Throttle Test",
            "password": _PASSWORD,
        },
    )
    assert res.status_code == 201

    # Request 4: must be throttled (counter exceeds 3/hour)
    res = api_client.post(
        REGISTER_URL,
        {
            "phone": "+250788113001",
            "display_name": "Throttle Test",
            "password": _PASSWORD,
        },
    )
    # 4th request must be throttled: counter exceeds 3/hour (T13/SR-11)
    assert res.status_code == 429


@pytest.mark.django_db
def test_st13_resend_cooldown_returns_429(api_client, make_verified_user):
    """
    A second new-device OTP request within 60 seconds for the same user
    must return 429 (resend cooldown prevents SMS flooding T13/SR-11).
    LoginView's cooldown is tested here: it checks for an unused NEW_DEVICE
    OtpCode created within the past 60 seconds and does not delete it first.
    """
    user = make_verified_user(phone="+250788113002")

    # First login from new device → OTP dispatched
    res = api_client.post(
        LOGIN_URL,
        {
            "phone": user.phone,
            "password": _PASSWORD,
            "device_fingerprint": "new-fp-cooldown-test",
        },
    )
    assert res.status_code == 200
    assert res.data["action"] == "device_verification_required"

    # Second login within 60 s — cooldown must fire
    res = api_client.post(
        LOGIN_URL,
        {
            "phone": user.phone,
            "password": _PASSWORD,
            "device_fingerprint": "new-fp-cooldown-test",
        },
    )
    assert res.status_code == 429
    assert "wait" in res.data["detail"].lower()


@pytest.mark.django_db
def test_st13_otp_code_absent_from_logs(api_client, caplog):
    """
    The OTP code must never appear in log output (T17/SR-12).
    LocMemSmsBackend (used in tests) does not log at all.
    ConsoleSmsBackend (dev only) logs only the masked phone, never the code.
    """
    with caplog.at_level(logging.DEBUG, logger="sokolink.security"):
        api_client.post(
            REGISTER_URL,
            {
                "phone": "+250788113003",
                "display_name": "Log Test",
                "password": _PASSWORD,
            },
        )

    assert len(sms_module._outbox) == 1
    code = sms_module._outbox[-1]["code"]

    for record in caplog.records:
        leak_msg = f"OTP code leaked in log: {record.getMessage()!r}"
        assert code not in record.getMessage(), leak_msg


@pytest.mark.django_db
def test_st13_x_forwarded_for_not_trusted_num_proxies_0(api_client):
    """
    With NUM_PROXIES=0, X-Forwarded-For is ignored; REMOTE_ADDR is the only
    identifier for IP-based throttles.

    An attacker rotating XFF headers while keeping the same REMOTE_ADDR cannot
    bypass OtpIpThrottle (20/hour per IP).  After 20 requests from 127.0.0.1
    the 21st must be throttled regardless of XFF value (T13/SR-11).

    Different phones are used each request so OtpPhoneThrottle (3/hour) is not
    the cause of any 429.
    """
    for i in range(20):
        # Different phone per request to avoid per-phone throttle
        # Rotate XFF to simulate an attacker trying to spoof different source IPs
        api_client.post(
            REGISTER_URL,
            {
                "phone": f"+25078811{i:04d}",
                "display_name": "XFF Test",
                "password": _PASSWORD,
            },
            HTTP_X_FORWARDED_FOR=f"5.5.5.{i % 256}",
        )

    # 21st request — XFF claims yet another IP; REMOTE_ADDR is 127.0.0.1 throughout
    res = api_client.post(
        REGISTER_URL,
        {
            "phone": "+250788119999",
            "display_name": "XFF Test",
            "password": _PASSWORD,
        },
        HTTP_X_FORWARDED_FOR="99.99.99.99",
    )
    # OtpIpThrottle must use REMOTE_ADDR, not X-Forwarded-For (NUM_PROXIES=0)
    assert res.status_code == 429
