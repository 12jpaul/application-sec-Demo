"""
Accounts models: User, Device, OtpCode.

Security notes
--------------
T1  / SR-01 : Phone-based identity; phone verified by SMS before full access.
              Argon2 hashing configured globally in settings.PASSWORD_HASHERS.
T2  / SR-02 : OTP required for new-device login and payout-number change.
              Codes stored as SHA-256 hashes; plain code sent via SMS then discarded.
              Max 5 attempts; 5-minute expiry.
T9  / SR-09 : Phone number is private.  It is NEVER included in public API
              responses; shared only inside an order between its buyer and seller.
T17 / SR-12 : OTP code hashes must never appear in logs or error messages.
"""

import hashlib
import uuid

from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.db import models
from django.utils import timezone


# ---------------------------------------------------------------------------
# User manager
# ---------------------------------------------------------------------------


class UserManager(BaseUserManager):
    """Custom manager for the phone-based User model."""

    use_in_migrations = True

    def create_user(self, phone, password=None, **extra_fields):
        """Create and save a regular user with the given phone and password."""
        if not phone:
            raise ValueError("Phone number is required (SR-01)")
        user = self.model(phone=phone, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone, password=None, **extra_fields):
        """Create and save a superuser."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_phone_verified", True)
        return self.create_user(phone, password, **extra_fields)


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------


class User(AbstractBaseUser, PermissionsMixin):
    """
    SokoLink user.  Phone number is the primary identifier.

    Role flags
    ----------
    Every active user may browse and buy (buyer capability is implicit).
    is_seller     – user has registered a SellerProfile and may create listings.
    is_moderator  – user has moderation privileges; always requires OTP (SR-02).
    is_staff      – Django admin access (admin role).

    Mitigates T1 : phone-based identity, no guessable username.
    Mitigates T8 : default-deny; roles are additive flags, not a single field
                   that could be escalated to a higher enum value.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # E.164 format, e.g. +250788123456
    # T9/SR-09: phone is PRIVATE – excluded from all public API serializers
    phone = models.CharField(max_length=20, unique=True)

    display_name = models.CharField(max_length=120)

    # --- Role flags ---
    # All active users can buy; sellers additionally create listings (T1).
    is_seller = models.BooleanField(default=False)
    # Moderators have restricted endpoints; always OTP at login (SR-02 / T8).
    is_moderator = models.BooleanField(default=False)

    # --- Django internals ---
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)  # Django admin access

    # SR-01: phone must be verified before full marketplace access
    is_phone_verified = models.BooleanField(default=False)

    date_joined = models.DateTimeField(default=timezone.now)
    # last_login is provided by AbstractBaseUser

    USERNAME_FIELD = "phone"
    REQUIRED_FIELDS = ["display_name"]

    objects = UserManager()

    class Meta:
        indexes = [
            models.Index(fields=["is_seller", "is_active"]),
            models.Index(fields=["is_moderator"]),
        ]

    def __str__(self):
        return f"{self.display_name} ({self.phone})"


# ---------------------------------------------------------------------------
# Device
# ---------------------------------------------------------------------------


class Device(models.Model):
    """
    Tracks trusted devices per user.

    When a user logs in from an unrecognised device (fingerprint_hash not in
    their trusted list), an OTP is required before the device is marked trusted
    (SR-02 / T2: OTP on new device).

    fingerprint_hash is a SHA-256 of device-side identifiers supplied by the
    mobile app.  It is never returned via the API.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
        related_name="devices",
    )
    # SHA-256 of device identifiers; never returned raw in API responses
    fingerprint_hash = models.CharField(max_length=64)
    is_trusted = models.BooleanField(default=False)
    trusted_at = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(default=timezone.now)
    user_agent = models.CharField(max_length=255, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "fingerprint_hash"],
                name="unique_device_per_user",
            )
        ]
        indexes = [
            models.Index(fields=["is_trusted"]),
        ]

    def __str__(self):
        status = "trusted" if self.is_trusted else "untrusted"
        return f"Device({status}) for {self.user_id}"


# ---------------------------------------------------------------------------
# OtpCode
# ---------------------------------------------------------------------------


class OtpCode(models.Model):
    """
    One-time codes for phone verification, new-device login, payout changes,
    and admin/moderator login.

    Security contract (SR-02 / T2 / T17):
    - The plain code (6 digits) is NEVER stored.  Only its SHA-256 hex digest
      is persisted in code_hash.
    - The plain code is transmitted to the user via SmsProvider, then discarded.
    - Verification: sha256(submitted_code) == stored code_hash.
    - attempt_count is incremented on each failed verification.
    - After 5 failed attempts, can_attempt returns False (lockout).
    - Codes expire after 5 minutes.
    - code_hash MUST NEVER appear in logs or error messages (T17).
    """

    class Purpose(models.TextChoices):
        SIGNUP = "signup", "Sign-up phone verification"
        NEW_DEVICE = "new_device", "New device login"
        PAYOUT_CHANGE = "payout_change", "Payout number change"
        ADMIN_LOGIN = "admin_login", "Admin / moderator login"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
        related_name="otp_codes",
    )
    purpose = models.CharField(max_length=30, choices=Purpose.choices)

    # T17/SR-02: SHA-256 hex digest of the plain code; plain code is discarded
    # after SMS dispatch and NEVER stored here.
    code_hash = models.CharField(max_length=64)  # nosemgrep

    expires_at = models.DateTimeField()
    attempt_count = models.IntegerField(default=0)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "purpose", "is_used"]),
            models.Index(fields=["expires_at"]),
        ]

    # --- Convenience properties used in Phase 2 auth logic ---

    @property
    def is_expired(self):
        """Return True if the code's 5-minute window has passed."""
        return timezone.now() >= self.expires_at

    @property
    def can_attempt(self):
        """
        Return True when the code may still be verified.
        SR-02/T2: blocked after 5 failed attempts or once expired/used.
        """
        return not self.is_used and not self.is_expired and self.attempt_count < 5

    @staticmethod
    def hash_code(plain_code: str) -> str:
        """
        Return the SHA-256 hex digest of plain_code.
        Call this before saving and again during verification.
        The plain code must NEVER be passed to logging calls (T17).
        """
        return hashlib.sha256(plain_code.encode()).hexdigest()

    def __str__(self):
        return f"OtpCode({self.purpose}) for {self.user_id}"
