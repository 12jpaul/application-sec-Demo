"""
Moderation models: Report, ModerationAction.

Security notes
--------------
T8  / SR-03 : Moderation endpoints are restricted to users with is_moderator=True
              (IsModerator permission class – Phase 4).  Moderators may NOT read
              private chats unless a Message is directly attached to a Report.
T12 / SR-12 : ModerationAction entries are append-only: no updates or deletes
              through the app.  Every moderator decision is permanently recorded.
"""

import uuid

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models

# T8: explicit allowlist prevents using the Report system as a probe into
# internal models (AuditLog, Order, Payment, …) that are not user-facing.
REPORTABLE_CONTENT_TYPES: frozenset = frozenset(
    [
        ("listings", "listing"),
        ("messaging", "message"),
        ("accounts", "user"),
        ("profiles", "review"),
    ]
)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


class Report(models.Model):
    """
    A user's report of a listing or another user.

    GenericForeignKey (content_type + object_id) allows a single Report model
    to target different content types (Listing, User, Message, …) without
    separate report tables.

    reporter FK ensures the reporter is identified.  Moderators read all
    reports; reporters can view their own (IsModerator or IsReporter – Phase 4).
    """

    class Reason(models.TextChoices):
        SPAM = "spam", "Spam"
        SCAM = "scam", "Scam / fraud"
        INAPPROPRIATE = "inappropriate", "Inappropriate content"
        FAKE = "fake", "Fake listing or account"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        REVIEWED = "reviewed", "Reviewed"
        DISMISSED = "dismissed", "Dismissed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="reports_filed",
    )

    # GenericFK: targets Listing, User, or Message
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        related_name="+",
    )
    object_id = models.UUIDField()
    reported_object = GenericForeignKey("content_type", "object_id")

    reason = models.CharField(max_length=30, choices=Reason.choices)
    description = models.TextField(max_length=1000, blank=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["content_type", "object_id"]),
            models.Index(fields=["reporter"]),
        ]

    def clean(self):
        """
        Restrict content_type to the REPORTABLE_CONTENT_TYPES allowlist.
        Mitigates T8: prevents the Report API from being used as a probe against
        internal models (AuditLog, Order, Payment, …) or future models added to
        the project that should not be user-reportable.
        """
        if self.content_type_id:
            ct = self.content_type
            key = (ct.app_label, ct.model)
            if key not in REPORTABLE_CONTENT_TYPES:
                raise ValidationError(
                    {
                        "content_type": (
                            f"Reports may not target {ct.app_label}.{ct.model}. "
                            "Only Listing, Message, User, and Review may be reported."
                        )
                    }
                )

    def __str__(self):
        return f"Report({self.reason}) by {self.reporter_id} [{self.status}]"


# ---------------------------------------------------------------------------
# ModerationAction
# ---------------------------------------------------------------------------


class ModerationAction(models.Model):
    """
    An append-only record of a moderation decision.

    T12/SR-12: entries cannot be updated or deleted through the app.
    T8/SR-03:  only users with is_moderator=True may create entries.

    report: nullable — a moderator may act proactively without an open report.
    target_*: GenericFK to the affected object (Listing, User, SellerProfile, …).
    """

    class ActionType(models.TextChoices):
        HIDE_LISTING = "hide_listing", "Hide listing"
        UNHIDE_LISTING = "unhide_listing", "Unhide listing"
        SUSPEND_USER = "suspend_user", "Suspend user"
        UNSUSPEND_USER = "unsuspend_user", "Unsuspend user"
        APPROVE_BADGE = "approve_badge", "Approve business badge"
        REJECT_BADGE = "reject_badge", "Reject business badge"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Nullable: proactive moderation without an open report
    report = models.ForeignKey(
        Report,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="actions",
    )

    moderator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="moderation_actions",
        limit_choices_to={"is_moderator": True},
    )

    action_type = models.CharField(max_length=30, choices=ActionType.choices)

    # GenericFK to the targeted object
    target_content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        related_name="+",
    )
    target_object_id = models.UUIDField()
    target = GenericForeignKey("target_content_type", "target_object_id")

    reason = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["moderator"]),
            models.Index(fields=["action_type"]),
            models.Index(fields=["created_at"]),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return f"ModerationAction({self.action_type}) by {self.moderator_id}"
