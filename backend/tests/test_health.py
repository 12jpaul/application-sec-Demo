"""
Tests for the /api/health/ liveness endpoint.
Phase 0 – ensures pytest has at least one test to collect so CI does not fail
with "no tests collected".
"""

import pytest
from django.test import Client


@pytest.mark.django_db
def test_health_returns_200():
    """GET /api/health/ must return HTTP 200."""
    client = Client()
    response = client.get("/api/health/")
    assert response.status_code == 200


@pytest.mark.django_db
def test_health_returns_json_ok():
    """GET /api/health/ must return {"status": "ok"}."""
    client = Client()
    response = client.get("/api/health/")
    data = response.json()
    assert data == {"status": "ok"}


@pytest.mark.django_db
def test_health_unauthenticated():
    """
    /api/health/ must be reachable without a token.
    It is exempt from the IsAuthenticated default permission so load
    balancers can probe it without credentials.
    """
    client = Client()
    response = client.get("/api/health/")
    # Must NOT return 403/401 – the view does not use DRF so default
    # permission classes do not apply here.
    assert response.status_code == 200
