"""
Accounts utility functions.

normalize_phone  – coerce phone to E.164; used in serializers AND throttle
                   cache keys so format variants share one throttle counter.
                   Mitigates T13/SR-11.
generate_otp     – cryptographically secure 6-digit code.
                   Mitigates T2/SR-02.
"""

import re
import secrets

from django.core.exceptions import ValidationError

# Rwanda local mobile: 07XXXXXXXX  → +250 7XXXXXXXX
_RW_LOCAL_RE = re.compile(r"^0([7]\d{8})$")
# Minimal E.164 sanity: + then country code (1 digit) + national number (7-14 digits)
_E164_RE = re.compile(r"^\+[1-9]\d{7,14}$")


def normalize_phone(raw: str) -> str:
    """
    Coerce common Rwandan phone formats to E.164 (+250XXXXXXXXX).

    Strips spaces and hyphens so "0788 123 456", "0788-123-456", and
    "+250788123456" all normalise to "+250788123456".

    Used in both serialiser validate_phone() methods **and** in
    OtpPhoneThrottle.get_cache_key(), ensuring every format variant shares
    the same throttle counter (T13/SR-11: prevents bypassing the per-phone
    OTP limit by submitting "0788…" vs "+250788…").

    Raises ValidationError for numbers that cannot be mapped to E.164.
    """
    cleaned = re.sub(r"[\s\-]", "", raw.strip())
    m = _RW_LOCAL_RE.match(cleaned)
    if m:
        cleaned = "+250" + m.group(1)
    if not _E164_RE.match(cleaned):
        raise ValidationError(
            "Enter a valid phone number in E.164 format, e.g. +250788123456."
        )
    return cleaned


def generate_otp() -> str:
    """
    Return a 6-digit one-time code as a zero-padded string (e.g. '007431').

    Uses secrets.randbelow() for cryptographically uniform distribution.
    Never use random.randint() — it is not cryptographically secure (T2/SR-02).
    """
    return str(secrets.randbelow(1_000_000)).zfill(6)
