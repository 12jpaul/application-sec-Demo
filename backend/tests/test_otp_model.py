"""
OtpCode model tests – hash storage, expiry, and attempt guard.

Threat : T2 (Account takeover), T17 (Secrets in logs)
Control: Plain OTP codes are never stored; only their SHA-256 hash is persisted.
         Codes expire after 5 minutes; blocked after 5 failed attempts (SR-02).

Pass when:
  - stored code_hash != plain code (hash not reversible to plain code)
  - sha256(plain) == stored code_hash (hash is deterministic)
  - is_expired returns True when expires_at is in the past
  - can_attempt returns False when attempt_count >= 5
"""

import hashlib
from datetime import timedelta

import pytest
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
    The plain code must NEVER be stored; only its SHA-256 digest is persisted.
    Mitigates T17/SR-02: a database leak cannot expose plain OTP codes.
    """
    plain_code = "123456"
    expected_hash = hashlib.sha256(plain_code.encode()).hexdigest()

    otp = OtpCode.objects.create(
        user=user,
        purpose=OtpCode.Purpose.SIGNUP,
        code_hash=OtpCode.hash_code(plain_code),
        expires_at=timezone.now() + timedelta(minutes=5),
    )

    assert otp.code_hash != plain_code, "Plain code must not be stored"
    assert otp.code_hash == expected_hash, "Stored hash must equal sha256(plain_code)"
    assert len(otp.code_hash) == 64, "SHA-256 hex digest is always 64 chars"


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
    """hash_code() must return the same digest for the same input."""
    code = "999999"
    assert OtpCode.hash_code(code) == OtpCode.hash_code(code)
