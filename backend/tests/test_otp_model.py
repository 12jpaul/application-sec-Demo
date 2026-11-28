"""
OtpCode model tests – HMAC-SHA256 storage, expiry, and attempt guard.

Threat : T2 (Account takeover), T17 (Secrets in logs)
Control: Plain OTP codes are never stored; only their HMAC-SHA256 (keyed with
         OTP_HMAC_KEY) digest is persisted.  Using a server-side key means the
         hash cannot be brute-forced offline even for 6-digit codes (10^6 values)
         without knowledge of the key.  Codes expire after 5 minutes; blocked after
         5 failed attempts (SR-02).

Pass when:
  - stored code_hash != plain code (hash not reversible to plain code)
  - same code + different key → different hash (key-dependency; T2)
  - verify_code() returns True for the correct code, False for a wrong code
  - is_expired returns True when expires_at is in the past
  - can_attempt returns False when attempt_count >= 5
  - hash_code() is deterministic for the same input and key
"""

from datetime import timedelta

import pytest
from django.test import override_settings
from django.utils import timezone

from accounts.models import OtpCode, User


@pytest.fixture
def user(db):
    return User.objects.create_user(
        phone="+250788000001",
        display_name="Test User",
        password="Testpass1234!",
    )


@pytest.mark.django_db
def test_otp_code_stored_as_hash(user):
    """
    The plain code must NEVER be stored; only its HMAC-SHA256 digest is persisted.
    Mitigates T17/SR-02: a database leak cannot expose plain OTP codes.
    """
    plain_code = "123456"

    otp = OtpCode.objects.create(
        user=user,
        purpose=OtpCode.Purpose.SIGNUP,
        code_hash=OtpCode.hash_code(plain_code),
        expires_at=timezone.now() + timedelta(minutes=5),
    )

    assert otp.code_hash != plain_code, "Plain code must not be stored"
    assert len(otp.code_hash) == 64, "HMAC-SHA256 hex digest is always 64 chars"


@pytest.mark.django_db
def test_otp_code_hash_key_dependent(user):
    """
    hash_code() result differs when OTP_HMAC_KEY differs.
    Mitigates T2: offline brute-force of the 10^6 possible codes is impossible
    without knowledge of the server-side key.
    """
    plain_code = "123456"
    with override_settings(OTP_HMAC_KEY="key-alpha-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"):
        hash_alpha = OtpCode.hash_code(plain_code)
    with override_settings(OTP_HMAC_KEY="key-beta-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"):
        hash_beta = OtpCode.hash_code(plain_code)
    assert hash_alpha != hash_beta, "Different keys must produce different hashes"


@pytest.mark.django_db
def test_otp_verify_code_correct(user):
    """
    verify_code() returns True for the correct plain code.
    Mitigates T2/SR-02: only the original code unlocks the OTP.
    """
    plain_code = "654321"
    stored = OtpCode.hash_code(plain_code)
    assert OtpCode.verify_code(plain_code, stored) is True


@pytest.mark.django_db
def test_otp_verify_code_wrong(user):
    """
    verify_code() returns False for an incorrect plain code.
    Mitigates T2/SR-02: a wrong submission is rejected.
    """
    stored = OtpCode.hash_code("654321")
    assert OtpCode.verify_code("111111", stored) is False


@pytest.mark.django_db
def test_otp_code_expired_flag(user):
    """
    is_expired must return True when expires_at is in the past.
    Mitigates SR-02/T2: stale codes cannot be replayed.
    """
    otp = OtpCode.objects.create(
        user=user,
        purpose=OtpCode.Purpose.SIGNUP,
        code_hash=OtpCode.hash_code("654321"),
        expires_at=timezone.now() - timedelta(minutes=1),  # already expired
    )

    assert otp.is_expired is True
    assert otp.can_attempt is False


@pytest.mark.django_db
def test_otp_code_max_attempts_blocked(user):
    """
    can_attempt must return False when attempt_count has reached 5.
    Mitigates SR-02/T2: brute-force is blocked after 5 failed tries.
    """
    otp = OtpCode.objects.create(
        user=user,
        purpose=OtpCode.Purpose.NEW_DEVICE,
        code_hash=OtpCode.hash_code("111111"),
        expires_at=timezone.now() + timedelta(minutes=5),
        attempt_count=5,  # max attempts reached
    )

    assert otp.can_attempt is False
    assert otp.is_expired is False  # not expired, just locked


@pytest.mark.django_db
def test_otp_code_hash_is_deterministic(user):
    """hash_code() must return the same digest for the same input and key."""
    code = "999999"
    assert OtpCode.hash_code(code) == OtpCode.hash_code(code)
