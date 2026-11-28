"""
SMS provider abstraction.

Backends
--------
ConsoleSmsBackend   – dev only: prints to stdout; raises ImproperlyConfigured
                      when DEBUG=False so it can never reach production.
LocMemSmsBackend    – test only: stores messages in module-level _outbox list
                      (like django.core.mail.outbox).  No DEBUG guard.

Usage
-----
    from integrations.sms import get_sms_backend
    get_sms_backend().send_otp(phone, code)   # T17: code is NOT logged

Security
--------
T13 / SR-11 : Backend abstraction; ConsoleSmsBackend refuses DEBUG=False.
T17 / SR-12 : OTP code must NEVER appear in log entries.
              All log calls use _mask_phone() — not the full number.
T9  / SR-09 : Full phone numbers must not appear in logs (+25078****123).
"""

import importlib
import logging

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger("sokolink.security")

# In-memory outbox for LocMemSmsBackend (tests only).
# Tests access this via: import integrations.sms; integrations.sms._outbox
# Cleared by the reset_between_tests fixture in conftest.py.
_outbox: list[dict] = []


def _mask_phone(phone: str) -> str:
    """
    Mask a phone number for log lines: +25078****123.
    T9/SR-09: full phone numbers must not appear in log output.
    """
    if len(phone) <= 7:
        return "***"
    return phone[:4] + "****" + phone[-3:]


class ConsoleSmsBackend:
    """
    Development/CI backend.  Prints the OTP to stdout (never to a log).
    Raises ImproperlyConfigured if DEBUG=False — cannot be used in production
    (T13/SR-11).
    """

    def __init__(self):
        if not settings.DEBUG:  # T13/SR-11: guard against accidental prod use
            raise ImproperlyConfigured(
                "ConsoleSmsBackend must not be used in production (DEBUG=False). "
                "Set SMS_BACKEND to a production SMS provider in .env."
            )

    def send_otp(self, phone: str, code: str) -> None:  # noqa: ARG002
        # T17: log only masked phone; the OTP code MUST NOT appear in logs
        logger.info(
            "OTP dispatched to %s via ConsoleSmsBackend",
            _mask_phone(phone),
        )
        # Print to stdout for developer convenience; not captured by loggers
        print(f"[SMS DEV] To: {_mask_phone(phone)}  Code: {code}")  # noqa: T201


class LocMemSmsBackend:
    """
    In-memory backend for tests.  Messages are appended to the module-level
    ``_outbox`` list so test code can read the OTP without hitting any
    real SMS provider.

    Compatible with DEBUG=False (no guard).  Used by config/settings/test.py.

    Usage in tests::

        import integrations.sms as sms_module
        code = sms_module._outbox[-1]["code"]
    """

    def send_otp(self, phone: str, code: str) -> None:
        # T17: code is kept in memory only; never reaches a logger or external system
        _outbox.append({"phone": phone, "code": code})


def get_sms_backend():
    """
    Instantiate and return the configured SMS backend.
    Backend class resolved from settings.SMS_BACKEND (T13/SR-11).
    """
    path = getattr(settings, "SMS_BACKEND", "integrations.sms.ConsoleSmsBackend")
    module_path, class_name = path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)()
