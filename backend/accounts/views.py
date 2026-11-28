"""
Authentication views: Register, PhoneVerify, Login, DeviceVerify, Logout, TokenRefresh.

Security notes
--------------
T1  / SR-01 : RegisterView returns the same 201 response whether the phone is new,
              already registered, or squatted — prevents user enumeration.
T2  / SR-02 : OTP for phone verification and new-device login.  Lockout after 5
              wrong passwords (15 min); failed_login_count reset to 0 when lockout
              fires so the user gets 5 fresh attempts after the timeout expires.
T8  / SR-03 : Default deny; custom permission classes in accounts/permissions.py.
T13 / SR-11 : Per-phone and per-IP throttles on every endpoint that sends an SMS;
              LoginView additionally applies a per-IP throttle.
T17 / SR-12 : OTP code and tokens never appear in log entries.
"""

import hashlib
import logging
from datetime import timedelta

from django.contrib.auth.hashers import check_password, make_password
from django.db.models import F
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import (
    TokenRefreshView as _SimpleJWTTokenRefreshView,
)

from accounts.models import Device, OtpCode, User
from accounts.serializers import (
    DeviceVerifySerializer,
    LoginSerializer,
    LogoutSerializer,
    PhoneVerifySerializer,
    RegisterSerializer,
)
from accounts.throttles import LoginThrottle, OtpIpThrottle, OtpPhoneThrottle
from accounts.utils import generate_otp
from audit.models import AuditLog
from integrations.sms import get_sms_backend

logger = logging.getLogger("sokolink.security")

# Generic message used for ALL login failures (wrong password, unknown phone, locked).
# Uniform wording prevents user enumeration (T1/SR-01).
_GENERIC_401 = "Invalid credentials."

# Generic message used for ALL registration responses, regardless of outcome.
_GENERIC_OTP = "Verification code sent to your phone."

# Pre-computed dummy Argon2 hash for constant-time comparison when the submitted
# phone is not in the database.  Computed once at module load (startup).
# Prevents timing-based enumeration: a "phone not found" check would otherwise
# return instantly compared to a real Argon2 check (T1/SR-01).
_DUMMY_HASH = make_password(  # nosemgrep # noqa: S106
    "sokolink-login-timing-oracle-prevention-dummy"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _issue_tokens(user: User) -> tuple[str, str]:
    """Return (access_token, refresh_token) strings for the given user."""
    refresh = RefreshToken.for_user(user)
    return str(refresh.access_token), str(refresh)


def _hash_device_fingerprint(fingerprint: str) -> str:
    """
    SHA-256 of the device fingerprint supplied by the Flutter app.
    The plain fingerprint is never stored — only the hash (T2/SR-02).
    The fingerprint itself is a random ID generated once by the app and kept
    in flutter_secure_storage; it is not a hardware identifier.
    """
    return hashlib.sha256(fingerprint.encode()).hexdigest()


# ---------------------------------------------------------------------------
# RegisterView
# ---------------------------------------------------------------------------


class RegisterView(APIView):
    """
    POST /api/auth/register/

    Returns 201 with the same generic message regardless of whether the phone
    is new, already registered, or squatted.  This prevents user enumeration
    (T1/SR-01).

    Phone-squatting prevention (T1):
    - If a user registered this phone but never verified it AND the sign-up is
      older than 24 hours: delete the stale record and create a fresh one.
    - If the sign-up is less than 24 hours old: update the password AND
      display_name so the legitimate owner's credentials overwrite a squatter's.
    - If the phone is already verified (is_active=True): silently return 201.

    Throttled per normalised phone + per IP to prevent SMS pumping (T13/SR-11).
    """

    permission_classes = [AllowAny]
    throttle_classes = [OtpPhoneThrottle, OtpIpThrottle]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone = serializer.validated_data["phone"]
        password = serializer.validated_data["password"]
        display_name = serializer.validated_data["display_name"]

        try:
            existing = User.objects.get(phone=phone)
        except User.DoesNotExist:
            existing = None

        if existing is not None:
            if existing.is_active:
                # T1: active phone already registered — same 201 (anti-enumeration)
                logger.info(
                    "Register attempt for existing verified phone; returning 201 silently"
                )
                return Response(
                    {"detail": _GENERIC_OTP}, status=status.HTTP_201_CREATED
                )

            # Unverified (is_active=False) user
            cutoff = timezone.now() - timedelta(hours=24)
            if existing.date_joined < cutoff:
                # Stale squatter — delete and create fresh (T1 phone squatting)
                existing.delete()
                user = User.objects.create_user(
                    phone=phone,
                    password=password,
                    display_name=display_name,
                    is_active=False,
                    is_phone_verified=False,
                )
            else:
                # Recent unverified — legitimate owner may be re-registering after
                # a squatter pre-registered their number.  Overwrite credentials
                # so only the most recent submitter can verify (T1/SR-01).
                existing.set_password(password)
                existing.display_name = display_name
                existing.save(update_fields=["password", "display_name"])
                # Remove old unverified OTPs to prevent confusion
                OtpCode.objects.filter(
                    user=existing,
                    purpose=OtpCode.Purpose.SIGNUP,
                    is_used=False,
                ).delete()
                user = existing
        else:
            user = User.objects.create_user(
                phone=phone,
                password=password,
                display_name=display_name,
                is_active=False,
                is_phone_verified=False,
            )

        # Resend cooldown: refuse if a code was sent in the last 60 seconds (T13)
        if OtpCode.objects.filter(
            user=user,
            purpose=OtpCode.Purpose.SIGNUP,
            is_used=False,
            created_at__gte=timezone.now() - timedelta(seconds=60),
        ).exists():
            return Response(
                {"detail": "Please wait before requesting another code."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        code = generate_otp()
        OtpCode.objects.create(
            user=user,
            purpose=OtpCode.Purpose.SIGNUP,
            code_hash=OtpCode.hash_code(code),
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        get_sms_backend().send_otp(phone, code)  # T17: code not logged
        AuditLog.objects.create(action=AuditLog.Action.OTP_REQUESTED, actor=user)

        return Response({"detail": _GENERIC_OTP}, status=status.HTTP_201_CREATED)


# ---------------------------------------------------------------------------
# PhoneVerifyView
# ---------------------------------------------------------------------------


class PhoneVerifyView(APIView):
    """
    POST /api/auth/verify-phone/

    Verifies the OTP sent at sign-up.  On success, activates the account and
    issues JWT tokens.

    Uses conditional ORM updates to prevent race conditions on simultaneous
    requests (T2/SR-02):
    - attempt_count incremented with attempt_count__lt=5 guard.
    - is_used marked with is_used=False guard; tokens only issued if 1 row
      changed, preventing token issuance if a concurrent request won the race.
    """

    permission_classes = [AllowAny]
    throttle_classes = [OtpIpThrottle]  # verify endpoints: IP throttle only

    def post(self, request):
        serializer = PhoneVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone = serializer.validated_data["phone"]
        code = serializer.validated_data["code"]
        device_fingerprint = serializer.validated_data.get("device_fingerprint", "")

        try:
            user = User.objects.get(phone=phone)
        except User.DoesNotExist:
            return Response(
                {"detail": "Invalid code."}, status=status.HTTP_400_BAD_REQUEST
            )

        otp = (
            OtpCode.objects.filter(
                user=user, purpose=OtpCode.Purpose.SIGNUP, is_used=False
            )
            .order_by("-created_at")
            .first()
        )

        if otp is None or not otp.can_attempt:
            return Response(
                {"detail": "Code expired or locked."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not OtpCode.verify_code(code, otp.code_hash):
            # Atomic increment with max-5 guard prevents parallel-request brute force (T2)
            OtpCode.objects.filter(pk=otp.pk, attempt_count__lt=5).update(
                attempt_count=F("attempt_count") + 1
            )
            AuditLog.objects.create(
                action=AuditLog.Action.OTP_FAILED,
                actor=user,
                extra={"purpose": "signup"},
            )
            return Response(
                {"detail": "Invalid code."}, status=status.HTTP_400_BAD_REQUEST
            )

        # Atomically mark used: only proceed if exactly 1 row changed (prevents replay)
        rows = OtpCode.objects.filter(pk=otp.pk, is_used=False).update(is_used=True)
        if rows == 0:
            # Race: another request already consumed this OTP
            return Response(
                {"detail": "Code already used."}, status=status.HTTP_400_BAD_REQUEST
            )

        User.objects.filter(pk=user.pk).update(is_phone_verified=True, is_active=True)
        user.refresh_from_db(fields=["is_phone_verified", "is_active"])

        if device_fingerprint:
            fp_hash = _hash_device_fingerprint(device_fingerprint)
            Device.objects.update_or_create(
                user=user,
                fingerprint_hash=fp_hash,
                defaults={"is_trusted": True, "trusted_at": timezone.now()},
            )

        access, refresh = _issue_tokens(user)
        AuditLog.objects.create(
            action=AuditLog.Action.SIGNUP,
            actor=user,
            ip_address=request.META.get("REMOTE_ADDR"),
        )

        return Response(
            {"access": access, "refresh": refresh}, status=status.HTTP_200_OK
        )


# ---------------------------------------------------------------------------
# LoginView
# ---------------------------------------------------------------------------


class LoginView(APIView):
    """
    POST /api/auth/login/

    Anti-enumeration: same 401 "Invalid credentials" for every failure path:
    - unknown phone
    - locked account  (AuditLog records the reason; response does not)
    - wrong password

    Timing oracle prevention: when the phone is not found, a dummy Argon2
    check is still performed so the response time matches a real password
    check (T1/SR-01).

    Lockout (T2/SR-02): after 5 wrong passwords, login_locked_until is set
    to now()+15 min AND failed_login_count is reset to 0, so the user gets
    5 fresh attempts after the timeout expires.

    New-device OTP (T2/SR-02): if the submitted fingerprint is not in the
    trusted-device list (or no fingerprint given), an OTP is dispatched and
    the response signals device_verification_required.  OTP throttles are
    applied manually in this branch because throttle_classes on this view
    is [LoginThrottle].
    """

    permission_classes = [AllowAny]
    throttle_classes = [LoginThrottle]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone = serializer.validated_data["phone"]
        password = serializer.validated_data["password"]
        device_fingerprint = serializer.validated_data.get("device_fingerprint", "")
        client_ip = request.META.get("REMOTE_ADDR")

        # --- 1. Look up user (or run dummy check to prevent timing oracle) ---
        try:
            user = User.objects.get(phone=phone)
        except User.DoesNotExist:
            # T1: constant-time dummy check prevents "phone not found" timing
            check_password(password, _DUMMY_HASH)
            AuditLog.objects.create(
                action=AuditLog.Action.LOGIN_FAILURE,
                actor=None,
                ip_address=client_ip,
                extra={"reason": "unknown_phone"},
            )
            return Response(
                {"detail": _GENERIC_401}, status=status.HTTP_401_UNAUTHORIZED
            )

        # --- 2. Lockout check (same 401 — do NOT reveal "locked") ---
        if user.is_login_locked:
            AuditLog.objects.create(
                action=AuditLog.Action.LOGIN_FAILURE,
                actor=user,
                ip_address=client_ip,
                extra={"reason": "locked"},
            )
            return Response(
                {"detail": _GENERIC_401}, status=status.HTTP_401_UNAUTHORIZED
            )

        # --- 3. Password check ---
        if not user.check_password(password):
            # Atomic increment (T2: prevents parallel-request brute force)
            User.objects.filter(pk=user.pk).update(
                failed_login_count=F("failed_login_count") + 1
            )
            user.refresh_from_db(fields=["failed_login_count"])

            if user.failed_login_count >= 5:
                # Set lockout; reset counter to 0 so user gets 5 fresh attempts
                # after the 15-minute window expires (T2/SR-02)
                User.objects.filter(pk=user.pk).update(
                    login_locked_until=timezone.now() + timedelta(minutes=15),
                    failed_login_count=0,
                )
            AuditLog.objects.create(
                action=AuditLog.Action.LOGIN_FAILURE,
                actor=user,
                ip_address=client_ip,
                extra={"failed_login_count": user.failed_login_count},
            )
            return Response(
                {"detail": _GENERIC_401}, status=status.HTTP_401_UNAUTHORIZED
            )

        # --- 4. Phone verification gate ---
        if not user.is_phone_verified:
            return Response(
                {"detail": "Verify your phone number before logging in."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # --- 5. Successful auth — reset lockout state ---
        User.objects.filter(pk=user.pk).update(
            failed_login_count=0, login_locked_until=None
        )

        # --- 6. Device trust check ---
        trusted = False
        if device_fingerprint:
            fp_hash = _hash_device_fingerprint(device_fingerprint)
            trusted = Device.objects.filter(
                user=user, fingerprint_hash=fp_hash, is_trusted=True
            ).exists()

        if trusted:
            access, refresh_tok = _issue_tokens(user)
            AuditLog.objects.create(
                action=AuditLog.Action.LOGIN_SUCCESS,
                actor=user,
                ip_address=client_ip,
            )
            return Response(
                {"access": access, "refresh": refresh_tok},
                status=status.HTTP_200_OK,
            )

        # --- 7. New / unknown device — trigger OTP ---
        # Apply OTP throttles manually: LoginView.throttle_classes = [LoginThrottle]
        # and the new-device branch dispatches an SMS (T13/SR-11)
        otp_phone_throttle = OtpPhoneThrottle()
        otp_ip_throttle = OtpIpThrottle()
        if not otp_phone_throttle.allow_request(request, self):
            return Response(
                {"detail": "Too many OTP requests for this number."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )
        if not otp_ip_throttle.allow_request(request, self):
            return Response(
                {"detail": "Too many OTP requests from this IP."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        # Resend cooldown: refuse if a code was sent in the last 60 seconds (T13)
        if OtpCode.objects.filter(
            user=user,
            purpose=OtpCode.Purpose.NEW_DEVICE,
            is_used=False,
            created_at__gte=timezone.now() - timedelta(seconds=60),
        ).exists():
            return Response(
                {"detail": "Please wait before requesting another code."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        # Register the unverified device (trusted=False until OTP succeeds)
        if device_fingerprint:
            fp_hash = _hash_device_fingerprint(device_fingerprint)
            Device.objects.update_or_create(
                user=user,
                fingerprint_hash=fp_hash,
                defaults={"is_trusted": False},
            )

        code = generate_otp()
        OtpCode.objects.create(
            user=user,
            purpose=OtpCode.Purpose.NEW_DEVICE,
            code_hash=OtpCode.hash_code(code),
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        get_sms_backend().send_otp(phone, code)  # T17: code not logged
        AuditLog.objects.create(
            action=AuditLog.Action.OTP_REQUESTED,
            actor=user,
            ip_address=client_ip,
            extra={"purpose": "new_device"},
        )

        return Response(
            {"action": "device_verification_required"},
            status=status.HTTP_200_OK,
        )


# ---------------------------------------------------------------------------
# DeviceVerifyView
# ---------------------------------------------------------------------------


class DeviceVerifyView(APIView):
    """
    POST /api/auth/verify-device/

    Verifies the OTP sent during a new-device login.  Uses the same
    conditional-update pattern as PhoneVerifyView (T2/SR-02).
    """

    permission_classes = [AllowAny]
    throttle_classes = [OtpIpThrottle]

    def post(self, request):
        serializer = DeviceVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone = serializer.validated_data["phone"]
        code = serializer.validated_data["code"]
        device_fingerprint = serializer.validated_data.get("device_fingerprint", "")
        client_ip = request.META.get("REMOTE_ADDR")

        try:
            user = User.objects.get(phone=phone)
        except User.DoesNotExist:
            return Response(
                {"detail": "Invalid code."}, status=status.HTTP_400_BAD_REQUEST
            )

        otp = (
            OtpCode.objects.filter(
                user=user, purpose=OtpCode.Purpose.NEW_DEVICE, is_used=False
            )
            .order_by("-created_at")
            .first()
        )

        if otp is None or not otp.can_attempt:
            return Response(
                {"detail": "Code expired or locked."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not OtpCode.verify_code(code, otp.code_hash):
            # Atomic increment with max-5 guard (T2)
            OtpCode.objects.filter(pk=otp.pk, attempt_count__lt=5).update(
                attempt_count=F("attempt_count") + 1
            )
            AuditLog.objects.create(
                action=AuditLog.Action.OTP_FAILED,
                actor=user,
                extra={"purpose": "new_device"},
            )
            return Response(
                {"detail": "Invalid code."}, status=status.HTTP_400_BAD_REQUEST
            )

        # Atomically mark used: prevent replay (T2)
        rows = OtpCode.objects.filter(pk=otp.pk, is_used=False).update(is_used=True)
        if rows == 0:
            return Response(
                {"detail": "Code already used."}, status=status.HTTP_400_BAD_REQUEST
            )

        # Trust the device
        if device_fingerprint:
            fp_hash = _hash_device_fingerprint(device_fingerprint)
            Device.objects.update_or_create(
                user=user,
                fingerprint_hash=fp_hash,
                defaults={"is_trusted": True, "trusted_at": timezone.now()},
            )

        access, refresh_tok = _issue_tokens(user)
        AuditLog.objects.create(
            action=AuditLog.Action.DEVICE_TRUSTED,
            actor=user,
            ip_address=client_ip,
        )

        return Response(
            {"access": access, "refresh": refresh_tok}, status=status.HTTP_200_OK
        )


# ---------------------------------------------------------------------------
# LogoutView
# ---------------------------------------------------------------------------


class LogoutView(APIView):
    """
    POST /api/auth/logout/

    Blacklists the refresh token so it cannot be used again (T2/SR-02).
    Verifies the token's user_id matches request.user to prevent an
    attacker from blacklisting another user's session (T2).
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            token = RefreshToken(serializer.validated_data["refresh"])
        except Exception:
            return Response(
                {"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST
            )

        # T2: verify the token belongs to the authenticated user
        if str(token["user_id"]) != str(request.user.id):
            return Response(
                {"detail": "Token does not belong to the authenticated user."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        token.blacklist()
        AuditLog.objects.create(
            action=AuditLog.Action.LOGOUT,
            actor=request.user,
            ip_address=request.META.get("REMOTE_ADDR"),
        )

        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# TokenRefreshView
# ---------------------------------------------------------------------------


class TokenRefreshView(_SimpleJWTTokenRefreshView):
    """
    POST /api/auth/token/refresh/

    Wraps simplejwt's TokenRefreshView.  Rotation and blacklisting are
    configured in SIMPLE_JWT (ROTATE_REFRESH_TOKENS=True,
    BLACKLIST_AFTER_ROTATION=True).  No additional logic needed here.
    """
