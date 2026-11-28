"""
Report.content_type allowlist tests.

Threat : T8 (Privilege escalation / model enumeration via Report API)
Control: Report.clean() restricts content_type to REPORTABLE_CONTENT_TYPES
         (Listing, Message, User, Review).  Attempting to file a report against
         an internal model (AuditLog, Order, …) raises ValidationError (SR-03).

Pass when:
  - Reports targeting Listing, Message, User, and Review each pass clean()
  - Reports targeting AuditLog raise ValidationError
  - Reports targeting Order raise ValidationError
"""

import pytest
from django.core.exceptions import ValidationError

from accounts.models import User
from moderation.models import Report


@pytest.fixture
def reporter(db):
    return User.objects.create_user(
        phone="+250788000099",
        display_name="Reporter",
        password="Testpass1234!",
    )


def _make_report(reporter, app_label, model_name):
    """Helper: build an unsaved Report with the given content type."""
    from django.contrib.contenttypes.models import ContentType

    ct = ContentType.objects.get(app_label=app_label, model=model_name)
    return Report(
        reporter=reporter,
        content_type=ct,
        object_id="00000000-0000-0000-0000-000000000001",
        reason=Report.Reason.SPAM,
    )


@pytest.mark.django_db
def test_report_allows_listing(reporter):
    """Reports targeting Listing are allowed by the allowlist."""
    _make_report(reporter, "listings", "listing").clean()  # must not raise


@pytest.mark.django_db
def test_report_allows_message(reporter):
    """Reports targeting Message are allowed by the allowlist."""
    _make_report(reporter, "messaging", "message").clean()  # must not raise


@pytest.mark.django_db
def test_report_allows_user(reporter):
    """Reports targeting User are allowed by the allowlist."""
    _make_report(reporter, "accounts", "user").clean()  # must not raise


@pytest.mark.django_db
def test_report_allows_review(reporter):
    """Reports targeting Review are allowed by the allowlist."""
    _make_report(reporter, "profiles", "review").clean()  # must not raise


@pytest.mark.django_db
def test_report_rejects_audit_log(reporter):
    """
    Reports targeting AuditLog are rejected.
    Mitigates T8: prevents the Report API probing immutable internal records.
    """
    with pytest.raises(ValidationError, match="may not target"):
        _make_report(reporter, "audit", "auditlog").clean()


@pytest.mark.django_db
def test_report_rejects_order(reporter):
    """
    Reports targeting Order are rejected.
    Mitigates T8: prevents the Report API from probing private order data.
    """
    with pytest.raises(ValidationError, match="may not target"):
        _make_report(reporter, "orders", "order").clean()
