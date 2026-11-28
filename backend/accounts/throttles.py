"""
Rate-throttling classes for auth endpoints.

OtpPhoneThrottle – 3 OTP sends per hour per normalised phone number.
                   Cache key uses normalize_phone() so "0788…" and "+250788…"
                   share one counter — prevents throttle bypass by format
                   variation (T13/SR-11).
OtpIpThrottle    – 20 OTP sends per hour per IP; prevents mass SMS pumping
                   across many different numbers from one origin (T13/SR-11).
LoginThrottle    – 10 login attempts per 15 min per IP (T2/SR-02).

NUM_PROXIES in REST_FRAMEWORK settings controls whether X-Forwarded-For is
trusted for IP-based throttles:
  0  – dev/test: use REMOTE_ADDR only; X-Forwarded-For is ignored.
  1  – prod (behind one Nginx): trust one X-Forwarded-For hop.
Setting NUM_PROXIES=0 means get_ident() uses REMOTE_ADDR, so a spoofed
X-Forwarded-For header cannot bypass the IP limit (T13/SR-11).
"""

from rest_framework.throttling import SimpleRateThrottle


class OtpPhoneThrottle(SimpleRateThrottle):
    """3 OTP SMS sends per hour per normalised phone (SR-11/T13)."""

    scope = "otp_phone"

    def get_cache_key(self, request, view):
        from accounts.utils import (
            normalize_phone,
        )  # local import avoids circular import

        raw = request.data.get("phone", "")
        try:
            phone = normalize_phone(raw)
        except Exception:
            # Malformed phone: fall back to raw value so it still gets throttled
            phone = raw
        return self.cache_format % {"scope": self.scope, "ident": phone}


class OtpIpThrottle(SimpleRateThrottle):
    """20 OTP SMS sends per hour per IP (SMS pumping prevention T13/SR-11)."""

    scope = "otp_ip"

    def get_cache_key(self, request, view):
        return self.cache_format % {
            "scope": self.scope,
            "ident": self.get_ident(request),
        }


class LoginThrottle(SimpleRateThrottle):
    """10 login attempts per 15 min per IP (T2/SR-02)."""

    scope = "login"

    def get_cache_key(self, request, view):
        return self.cache_format % {
            "scope": self.scope,
            "ident": self.get_ident(request),
        }
