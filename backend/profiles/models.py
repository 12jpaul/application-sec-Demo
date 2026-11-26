"""
Profiles models: SellerProfile, Review, BusinessBadgeRequest.

Security notes
--------------
T1  / SR-01 : Reviews are accepted only from buyers who completed an order with
              that seller.  One review per order (UNIQUE constraint).
T2  / SR-02 : payout_phone requires OTP to change and is NEVER returned via any
              public API serialiser.
T6  / SR-06 : BusinessBadgeRequest documents are private file paths; served via
              signed URL only.  Badge status changes to 'verified' only after a
              moderator reviews documents.
T9  / SR-09 : average_rating and review_count are public.  bio and avatar are
              public.  payout_phone is private.
"""

import uuid

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from orders.models import Order


# ---------------------------------------------------------------------------
# SellerProfile
# ---------------------------------------------------------------------------


class SellerProfile(models.Model):
    """
    Extended profile for sellers.  Created when a user activates seller mode.

    payout_phone: private field – excluded from all public serialisers.
                  Requires OTP to change (SR-02/T2).
    average_rating / review_count: denormalised aggregates; updated each time a
                  Review is saved or deleted (Phase 4 signal).
    """

    class BadgeStatus(models.TextChoices):
        NONE = "none", "No badge"
        PENDING = "pending", "Pending moderator review"
        VERIFIED = "verified", "Verified business"

    # AutoField PK: SellerProfile is an internal join table; UUID not needed
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="seller_profile",
    )
    bio = models.TextField(max_length=1000, blank=True)
    avatar_path = models.CharField(max_length=512, blank=True)

    # T2/SR-02: OTP required to change; NEVER included in API responses
    payout_phone = models.CharField(max_length=20, blank=True)
    payout_phone_verified = models.BooleanField(default=False)

    # Denormalised; updated via signal when a Review is saved (Phase 4)
    average_rating = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        default=0,
    )
    review_count = models.PositiveIntegerField(default=0)

    badge_status = models.CharField(
        max_length=20,
        choices=BadgeStatus.choices,
        default=BadgeStatus.NONE,
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["badge_status"]),
        ]

    def __str__(self):
        return f"SellerProfile for {self.user_id}"


# ---------------------------------------------------------------------------
# Review
# ---------------------------------------------------------------------------


class Review(models.Model):
    """
    A buyer's review of a seller after a completed order.

    T1/SR-01: a review is accepted only when the reviewer has a completed Order
              with this seller (enforced in Phase 4 serialiser/view logic).
    One review per order: UNIQUE(reviewer, order) prevents double-reviewing.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="reviews_given",
    )
    seller = models.ForeignKey(
        SellerProfile,
        on_delete=models.CASCADE,
        related_name="reviews",
    )

    # PROTECT: deleting an order should not silently erase a review
    order = models.OneToOneField(
        Order,
        on_delete=models.PROTECT,
        related_name="review",
    )

    rating = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
    )
    comment = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["reviewer", "order"],
                name="unique_review_per_order",
            )
        ]
        indexes = [
            models.Index(fields=["seller", "created_at"]),
        ]

    def __str__(self):
        return f"Review({self.rating}★) by {self.reviewer_id} for {self.seller_id}"


# ---------------------------------------------------------------------------
# BusinessBadgeRequest
# ---------------------------------------------------------------------------


class BusinessBadgeRequest(models.Model):
    """
    A seller's application for a 'Verified Business' badge.

    documents: list of private file paths (JSON array).  Phase 3 upload
               pipeline strips EXIF and stores them privately; they are NEVER
               served raw (SR-07).
    Status transitions: pending → approved/rejected (by a moderator only).
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending review"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    seller_profile = models.ForeignKey(
        SellerProfile,
        on_delete=models.CASCADE,
        related_name="badge_requests",
    )

    # T6/SR-07: private file paths; served via signed URL only
    documents = models.JSONField(default=list, blank=True)

    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
    )

    # Nullable: set when a moderator acts
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="badge_reviews",
        limit_choices_to={"is_moderator": True},
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    moderator_notes = models.TextField(max_length=1000, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["seller_profile"]),
        ]

    def __str__(self):
        return f"BadgeRequest({self.status}) for {self.seller_profile_id}"
