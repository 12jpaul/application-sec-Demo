"""
ST-12 – AuditLog immutability tests.

Threat : T12 (Repudiation of orders/messages)
Control: AuditLog entries are append-only; no update or delete is possible
         through the Django ORM (SR-12).

Pass when:
  - New AuditLog entries can be created.
  - Attempting to update an entry raises IntegrityError.
  - Attempting to delete an individual entry raises PermissionError.
  - Attempting a queryset bulk delete raises PermissionError.
"""

import pytest
from django.db import IntegrityError

from audit.models import AuditLog


@pytest.mark.django_db
def test_st12_audit_log_new_entry_saved():
    """Normal create must succeed (baseline)."""
    log = AuditLog.objects.create(action=AuditLog.Action.LOGIN_SUCCESS)
    assert log.pk is not None
    assert AuditLog.objects.filter(pk=log.pk).exists()


@pytest.mark.django_db
def test_st12_audit_log_instance_update_blocked():
    """
    Calling save() on an existing instance must raise IntegrityError.
    Mitigates T12/SR-12: a compromised process cannot overwrite audit records.
    """
    log = AuditLog.objects.create(action=AuditLog.Action.LOGIN_SUCCESS)
    log.action = AuditLog.Action.LOGIN_FAILURE  # attempt to tamper
    with pytest.raises(IntegrityError, match="immutable"):
        log.save()


@pytest.mark.django_db
def test_st12_audit_log_queryset_update_blocked():
    """
    QuerySet.update() must raise IntegrityError.
    Mitigates T12/SR-12: bulk updates via the ORM are blocked.
    """
    log = AuditLog.objects.create(action=AuditLog.Action.LOGIN_SUCCESS)
    with pytest.raises(IntegrityError, match="immutable"):
        AuditLog.objects.filter(pk=log.pk).update(action=AuditLog.Action.LOGIN_FAILURE)


@pytest.mark.django_db
def test_st12_audit_log_instance_delete_blocked():
    """
    Calling delete() on an individual instance must raise PermissionError.
    Mitigates T12/SR-12: individual entries cannot be erased.
    """
    log = AuditLog.objects.create(action=AuditLog.Action.LOGIN_SUCCESS)
    with pytest.raises(PermissionError, match="cannot be deleted"):
        log.delete()


@pytest.mark.django_db
def test_st12_audit_log_queryset_delete_blocked():
    """
    QuerySet.delete() must raise PermissionError.
    Mitigates T12/SR-12: bulk delete via the ORM is blocked.
    """
    log = AuditLog.objects.create(action=AuditLog.Action.LOGIN_SUCCESS)
    with pytest.raises(PermissionError, match="cannot be deleted"):
        AuditLog.objects.filter(pk=log.pk).delete()
