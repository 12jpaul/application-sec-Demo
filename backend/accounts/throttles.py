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

    def parse_rate(self, rate):
        """
        Extend SimpleRateThrottle.parse_rate to support multi-unit minute
        periods (e.g. "10/15min" → 10 requests per 900 seconds).

        DRF's default implementation only reads period[0], which chokes on
        "15min" because '1' is not a valid period key.  This override handles
        the "Xmin" suffix used in DEFAULT_THROTTLE_RATES["login"].
        """
        if rate is None:
            return None, None
        num, period = rate.split("/")
        num_requests = int(num)
        if period.endswith("min") and len(period) > 3:
            # e.g. "15min" → 15 * 60 = 900 seconds
            duration = int(period[:-3]) * 60
        else:
            duration = {"s": 1, "m": 60, "h": 3600, "d": 86400}[period[0]]
        return num_requests, duration

    def get_cache_key(self, request, view):
        return self.cache_format % {
            "scope": self.scope,
            "ident": self.get_ident(request),
        }
