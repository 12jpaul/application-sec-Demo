"""
AuditLog model – append-only event store.

Security notes
--------------
T12 / SR-12 : Every security-relevant action (login, OTP failure, role change,
              payout change, order status change, moderation action, payment
              callback) is recorded here.  Entries are immutable: neither the
              application nor ORM bulk operations can update or delete them.
T17 / SR-12 : The `extra` JSONField MUST NEVER contain passwords, OTP values,
              JWT tokens, or payment keys.  Log the WHAT and WHO, not the secret.

Append-only enforcement (T12)
-----------------------------
1. AuditLog.save()           – raises IntegrityError if the instance already
                               has a primary key (i.e., it is an update attempt).
2. AuditLog.delete()         – always raises PermissionError.
3. AuditLogQuerySet.update() – raises IntegrityError on any bulk update.
4. AuditLogQuerySet.delete() – raises PermissionError on any bulk delete.

The Django admin and any direct database console can still read rows.  Database-
level deletion (e.g. for GDPR right-to-erasure) must go through a privileged,
out-of-band process outside the Django ORM.
"""

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import IntegrityError, models


# ---------------------------------------------------------------------------
# Custom QuerySet – blocks bulk mutations
# ---------------------------------------------------------------------------


class AuditLogQuerySet(models.QuerySet):
    """Prevent bulk update/delete so the audit log stays immutable (T12)."""

    def update(self, **kwargs):  # Mitigates T12/SR-12
        raise IntegrityError("AuditLog entries are immutable (T12/SR-12)")

    def delete(self):  # Mitigates T12/SR-12
        raise PermissionError("AuditLog entries cannot be deleted (T12/SR-12)")


class AuditLogManager(models.Manager):
    def get_queryset(self):
        return AuditLogQuerySet(self.model, using=self._db)


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------


class AuditLog(models.Model):
    """
    Immutable record of a security-relevant event.

    actor       – the User who performed the action (null for system/cron events).
    action      – what happened (choose from Action.choices).
    target_*    – optional GenericForeignKey to the affected object (listing,
                  order, user, …).  Stored as content-type + object-id string
                  so rows survive target deletion.
    ip_address  – client IP at the time of the event (nullable for system events).
    user_agent  – raw User-Agent header (truncated to 255 chars).
    extra       – supplementary context as a JSON dict.
                  RULE: never put passwords, OTPs, tokens, or payment keys here.
    created_at  – set once at creation; never updated.
    """

    class Action(models.TextChoices):
        LOGIN_SUCCESS = "login_success", "Login success"
        LOGIN_FAILURE = "login_failure", "Login failure"
        LOGOUT = "logout", "Logout"
        SIGNUP = "signup", "Account sign-up"
        DEVICE_TRUSTED = "device_trusted", "Device trusted"
        OTP_REQUESTED = "otp_requested", "OTP requested"
        OTP_FAILED = "otp_failed", "OTP verification failed"
        OTP_SUCCESS = "otp_success", "OTP verification succeeded"
        ROLE_CHANGED = "role_changed", "Role changed"
        PAYOUT_CHANGED = "payout_changed", "Payout number changed"
        ORDER_STATUS_CHANGED = "order_status_changed", "Order status changed"
        MODERATION_ACTION = "moderation_action", "Moderation action taken"
        PAYMENT_CALLBACK = "payment_callback", "Payment callback received"
        ACCOUNT_SUSPENDED = "account_suspended", "Account suspended"
        ACCOUNT_UNSUSPENDED = "account_unsuspended", "Account unsuspended"
        BADGE_APPROVED = "badge_approved", "Business badge approved"
        BADGE_REJECTED = "badge_rejected", "Business badge rejected"

    objects = AuditLogManager()

    # BigAutoField PK: sequential, opaque to end users (admin-only table).
    # Using BigAutoField (not UUID) makes ordering and range queries fast.

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
        help_text="User who triggered the event; null for automated/system events.",
    )
    action = models.CharField(max_length=60, choices=Action.choices)

    # GenericForeignKey to the affected object (optional)
    target_content_type = models.ForeignKey(
        ContentType,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    # CharField instead of UUIDField: targets may have integer or UUID PKs
    target_object_id = models.CharField(max_length=64, blank=True, default="")
    target = GenericForeignKey("target_content_type", "target_object_id")

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)

    # T17/SR-12: NEVER store passwords, OTPs, tokens, or payment keys in extra.
    extra = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["actor", "created_at"]),
            models.Index(fields=["action"]),
            models.Index(fields=["created_at"]),
        ]
        ordering = ["-created_at"]
        get_latest_by = "created_at"

    # --- Append-only enforcement ---

    def save(self, *args, **kwargs):  # Mitigates T12/SR-12
        if self.pk:
            raise IntegrityError(
                "AuditLog entries are immutable and cannot be updated (T12/SR-12)"
            )
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):  # Mitigates T12/SR-12
        raise PermissionError("AuditLog entries cannot be deleted (T12/SR-12)")

    def __str__(self):
        actor = str(self.actor_id) if self.actor_id else "system"
        return f"AuditLog({self.action}) by {actor} at {self.created_at}"
