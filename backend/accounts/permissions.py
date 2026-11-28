"""
SokoLink permission classes.

Security notes
--------------
T3  / SR-03 : Every API call must be authorized by role AND ownership.
              Non-owners must receive 404 (not 403) to avoid confirming object
              existence.  Views must ALSO scope get_queryset() to the owner:

                  def get_queryset(self):
                      # Mitigates T3: non-owners get 404, not 403
                      return Listing.objects.filter(seller=self.request.user)

              The IsOwner permission class alone is not sufficient — without
              the queryset scoping, get_object() can still expose the PK.
T8  / SR-03 : Moderation endpoints are restricted to users with is_moderator=True.
T1  / SR-01 : Unverified users can register and verify but cannot access the
              marketplace.  IsPhoneVerified enforces this.
"""

from rest_framework.permissions import BasePermission


class IsPhoneVerified(BasePermission):
    """
    Allow access only to users whose phone has been verified (SR-01/T1).
    """

    message = "Verify your phone number to access this resource."

    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.is_phone_verified
        )


class IsModerator(BasePermission):
    """
    Allow access only to users with is_moderator=True (T8/SR-03).
    Always combine with IsAuthenticated (enforced by default REST_FRAMEWORK
    settings).
    """

    message = "Moderator access required."

    def has_permission(self, request, view):
        return bool(
            request.user and request.user.is_authenticated and request.user.is_moderator
        )


class IsAdmin(BasePermission):
    """
    Allow access only to users with is_staff=True (T8/SR-03).
    Admin panel is behind VPN in production (see deployment-checklist.md).
    """

    message = "Admin access required."

    def has_permission(self, request, view):
        return bool(
            request.user and request.user.is_authenticated and request.user.is_staff
        )


class IsOwner(BasePermission):
    """
    Object-level ownership check.

    Returns False for non-owners; views MUST return 404 (not 403) so callers
    cannot confirm whether the object exists (T3/SR-03: prevents IDOR
    enumeration).

    How to enforce 404:
        1. Scope get_queryset() to the owner (see module docstring).
        2. Set permission_classes = [IsAuthenticated, IsOwner].

    Checks the following attributes on the target object:
        - obj == request.user          (the object IS the user)
        - obj.user                      (UserProfile, OtpCode, Device, …)
        - obj.seller                    (Listing, Order)
        - obj.buyer                     (Order, Conversation)
        - obj.reporter                  (Report)
    """

    def has_object_permission(self, request, view, obj):
        if obj == request.user:
            return True
        for attr in ("user", "seller", "buyer", "reporter"):
            if getattr(obj, attr, None) == request.user:
                return True
        return False


class IsOrderParticipant(BasePermission):
    """
    Allow access to the buyer OR the seller of an Order (T3/SR-03).
    Non-participants must receive 404.

    Usage:
        permission_classes = [IsAuthenticated, IsOrderParticipant]
        # get_queryset must filter: Order.objects.filter(
        #     models.Q(buyer=request.user) | models.Q(seller=request.user)
        # )  # Mitigates T3: non-participants get 404
    """

    def has_object_permission(self, request, view, obj):
        return request.user in (obj.buyer, obj.seller)


class IsConversationParticipant(BasePermission):
    """
    Allow access to the buyer OR the seller of a Conversation (T3/SR-03).
    Non-participants must receive 404.

    Usage:
        permission_classes = [IsAuthenticated, IsConversationParticipant]
        # get_queryset must filter: Conversation.objects.filter(
        #     models.Q(buyer=request.user) | models.Q(seller=request.user)
        # )  # Mitigates T3: non-participants get 404
    """

    def has_object_permission(self, request, view, obj):
        return request.user in (obj.buyer, obj.seller)
