"""
Accounts serializers: Register, PhoneVerify, Login, DeviceVerify, Logout, UserPublic.

Security notes
--------------
T1  / SR-01 : RegisterSerializer has NO UniqueValidator on phone.
              The view returns the same 201 response whether the phone is new,
              already registered, or squatted — this prevents user enumeration.
T9  / SR-09 : UserPublicSerializer excludes phone from all responses.
"""

from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

from accounts.utils import normalize_phone


class RegisterSerializer(serializers.Serializer):
    """
    Phone registration.  No UniqueValidator — anti-enumeration (T1/SR-01):
    the response is identical whether the phone is new or already registered.
    """

    phone = serializers.CharField(max_length=20)
    display_name = serializers.CharField(max_length=120)
    # write_only: never echoed back in a response (T17)
    password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
    )

    def validate_phone(self, value):
        return normalize_phone(value)

    def validate_password(self, value):
        # Django built-in validators: min_length=10, common password check (SR-01)
        validate_password(value)
        return value


class PhoneVerifySerializer(serializers.Serializer):
    """OTP verification at sign-up."""

    phone = serializers.CharField(max_length=20)
    code = serializers.CharField(min_length=6, max_length=6)
    device_fingerprint = serializers.CharField(
        max_length=255, required=False, allow_blank=True
    )

    def validate_phone(self, value):
        return normalize_phone(value)


class LoginSerializer(serializers.Serializer):
    """
    Login credentials.  No UniqueValidator or existence check — anti-enumeration
    (T1/SR-01).  The view performs the lookup and returns a uniform error.
    """

    phone = serializers.CharField(max_length=20)
    password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
    )
    # Optional: a random ID generated once by the Flutter app and stored in
    # flutter_secure_storage.  The server hashes it before storing (T2/SR-02).
    device_fingerprint = serializers.CharField(
        max_length=255, required=False, allow_blank=True
    )

    def validate_phone(self, value):
        return normalize_phone(value)


class DeviceVerifySerializer(serializers.Serializer):
    """OTP verification for a new device login."""

    phone = serializers.CharField(max_length=20)
    code = serializers.CharField(min_length=6, max_length=6)
    device_fingerprint = serializers.CharField(
        max_length=255, required=False, allow_blank=True
    )

    def validate_phone(self, value):
        return normalize_phone(value)


class LogoutSerializer(serializers.Serializer):
    """Refresh token to blacklist on logout."""

    refresh = serializers.CharField()


class UserPublicSerializer(serializers.Serializer):
    """
    Public-safe representation of a User.
    phone excluded (T9/SR-09: private; shared only inside orders).
    """

    id = serializers.UUIDField(read_only=True)
    display_name = serializers.CharField(read_only=True)
    is_seller = serializers.BooleanField(read_only=True)
    is_phone_verified = serializers.BooleanField(read_only=True)
