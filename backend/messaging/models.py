"""
Messaging models: Conversation, Message.

Security notes
--------------
T3  / SR-03 : Conversations and messages are visible ONLY to their buyer and
              seller (IsConversationParticipant – Phase 5).  Non-participants
              receive 404.
T5  / SR-08 : Messages are stored as plain text.  The mobile app renders them
              with Flutter Text(), never in a WebView.
              is_flagged is set by the backend when the content contains a URL
              or phrases associated with off-app payment requests (Phase 5).
              The app shows a warning dialog before opening any flagged link.
T13 / SR-11 : Message creation is rate-limited (custom throttle in Phase 5).
"""

import uuid

from django.conf import settings
from django.db import models

from listings.models import Listing


# ---------------------------------------------------------------------------
# Conversation
# ---------------------------------------------------------------------------


class Conversation(models.Model):
    """
    A private thread between a buyer and the seller of a listing.

    UNIQUE(listing, buyer): one conversation per buyer per listing; prevents
    duplicate threads.
    listing: SET_NULL on delete so the conversation history is preserved when
             the listing is removed.
    seller: denormalised from listing.seller at conversation creation for fast
            queries (avoids a join on every message lookup).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Nullable: conversation survives listing deletion (history preserved)
    listing = models.ForeignKey(
        Listing,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="conversations",
    )

    # T3/SR-03: visible only to these two parties
    buyer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="buyer_conversations",
    )
    seller = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="seller_conversations",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    # Denormalised for inbox sorting; updated when a new Message is saved
    last_message_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["listing", "buyer"],
                name="unique_conversation_per_listing_buyer",
            )
        ]
        indexes = [
            models.Index(fields=["buyer"]),
            models.Index(fields=["seller"]),
        ]

    def __str__(self):
        return f"Conversation listing={self.listing_id} buyer={self.buyer_id}"


# ---------------------------------------------------------------------------
# Message
# ---------------------------------------------------------------------------


class Message(models.Model):
    """
    A single message within a Conversation.

    content: plain text only; max 2,000 characters (SR-08/T5).
    is_flagged: set by backend heuristics when the content contains URLs or
                off-app payment phrases (T5).  The mobile app shows a warning
                before opening any link in a flagged message.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    conversation = models.ForeignKey(
        Conversation,
        on_delete=models.CASCADE,
        related_name="messages",
    )
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="sent_messages",
    )

    # T5/SR-08: plain text; never stored as HTML; rendered as Flutter Text()
    content = models.TextField(max_length=2000)

    # T5: set True if content contains links or off-app-payment phrases
    is_flagged = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["conversation", "created_at"]),
            models.Index(fields=["is_flagged"]),
        ]
        ordering = ["conversation", "created_at"]

    def __str__(self):
        return f"Message by {self.sender_id} in {self.conversation_id}"
