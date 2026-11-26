"""
Orders models: Order, OrderStatusHistory, Payment.

Security notes
--------------
T3  / SR-03 : Order and Payment are visible ONLY to their buyer and seller.
              The IsOrderParticipant permission class (Phase 2) enforces this.
              Non-participants receive 404.
T4  / SR-04 : unit_price and total_amount are SERVER-CALCULATED from the stored
              Listing.price at order-creation time.  Any client-submitted price
              or total is ignored.  The listing_snapshot records the price at
              the moment of purchase so historical accuracy is preserved.
T6  / SR-05 : An order is marked paid ONLY after the payment-provider callback
              arrives with a valid signature (callback_verified=True).
              provider_reference is UNIQUE: each payment reference is processed
              exactly once (idempotency).  The amount in the callback is verified
              against order.total_amount before marking the payment successful.
T12 / SR-12 : OrderStatusHistory is append-only: no updates or deletes via the
              app.  Every status transition is recorded with the actor and time.
"""

import uuid

from django.conf import settings
from django.db import models

from listings.models import Listing


# ---------------------------------------------------------------------------
# Order
# ---------------------------------------------------------------------------


class Order(models.Model):
    """
    A buyer's purchase of a listed item.

    Access: buyer and seller only (IsOrderParticipant – Phase 2).
    unit_price / total_amount: set by the server, never from the client (T4).
    listing: SET_NULL on delete so the order survives listing removal; the
             listing_snapshot preserves title and price at order time.
    """

    class Status(models.TextChoices):
        PLACED = "placed", "Placed"
        CONFIRMED = "confirmed", "Confirmed by seller"
        DELIVERED = "delivered", "Delivered"
        COMPLETED = "completed", "Completed"
        CANCELLED = "cancelled", "Cancelled"

    class PaymentMethod(models.TextChoices):
        MOBILE_MONEY = "mobile_money", "Mobile Money"
        CASH_ON_DELIVERY = "cash_on_delivery", "Cash on Delivery"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Listing may be deleted; SET_NULL preserves the order record.
    listing = models.ForeignKey(
        Listing,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="orders",
    )

    # T3/SR-03: visible only to these two parties
    buyer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="buy_orders",
    )
    seller = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="sell_orders",
    )

    # Snapshot: title and price at the time of order (T4 audit trail)
    listing_snapshot = models.JSONField(default=dict)

    quantity = models.PositiveIntegerField(default=1)

    # T4/SR-04: server reads from Listing.price, never from client input
    unit_price = models.DecimalField(max_digits=12, decimal_places=2)
    total_amount = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        help_text="Server-calculated: quantity × unit_price (T4/SR-04)",
    )

    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PLACED,
    )
    payment_method = models.CharField(
        max_length=20,
        choices=PaymentMethod.choices,
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["buyer"]),
            models.Index(fields=["seller"]),
            models.Index(fields=["status"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self):
        return f"Order({self.status}) {self.id} buyer={self.buyer_id}"


# ---------------------------------------------------------------------------
# OrderStatusHistory
# ---------------------------------------------------------------------------


class OrderStatusHistory(models.Model):
    """
    Immutable audit trail of every status transition on an Order.

    T12/SR-12: entries are append-only; no updates or deletes through the app.
    BigAutoField PK keeps ordering fast (admin and reporting queries).
    """

    order = models.ForeignKey(
        Order,
        on_delete=models.CASCADE,
        related_name="status_history",
    )
    from_status = models.CharField(max_length=20, blank=True)
    to_status = models.CharField(max_length=20)
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="order_status_changes",
    )
    reason = models.CharField(max_length=500, blank=True)
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["order", "changed_at"]),
        ]
        ordering = ["order", "changed_at"]

    def __str__(self):
        return f"{self.from_status} → {self.to_status} on order {self.order_id}"


# ---------------------------------------------------------------------------
# Payment
# ---------------------------------------------------------------------------


class Payment(models.Model):
    """
    One payment attempt against an Order.

    T6/SR-05: an Order is considered paid only when callback_verified=True.
    provider_reference UNIQUE: each reference is processed exactly once
    (idempotency guard against replayed payment callbacks).
    amount MUST equal order.total_amount – verified in the callback handler.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        SUCCESS = "success", "Success"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    order = models.ForeignKey(
        Order,
        on_delete=models.CASCADE,
        related_name="payments",
    )

    # T6/SR-05: UNIQUE enforces idempotency – same reference cannot be replayed
    provider_reference = models.CharField(max_length=128, unique=True)

    # T6/SR-05: amount verified against order.total_amount in callback handler
    amount = models.DecimalField(max_digits=14, decimal_places=2)

    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
    )

    # T6/SR-05: True only after provider signature has been cryptographically verified
    callback_verified = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["order"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self):
        return f"Payment({self.status}) ref={self.provider_reference[:20]}"
