"""Real-execution coverage tests for mobinspect/RBAC/audit.py.

STRICT: no mocks. Drives the real `record` / `record_anon` helpers and
their private accessors against real Django RequestFactory requests and
the real AuditEvent ORM model. The "best-effort, never raises" except
branches are exercised with genuinely unserializable metadata (a `set`
inside the JSONField payload), which really does raise TypeError deep
inside AuditEvent.objects.create() -> no mocking of any call.
"""
import pytest

from django.contrib.auth.models import AnonymousUser
from django.db import transaction
from django.test import RequestFactory

from mobinspect.RBAC import audit
from mobinspect.RBAC.models import AuditEvent


pytestmark = pytest.mark.django_db


# ─────────────────────────────────────────────────────── record() except path
#
# NOTE: on Postgres, a query that raises INSIDE an already-open atomic()
# block marks the connection `needs_rollback` even once the exception is
# caught locally (by record()'s own try/except) -- the block itself must
# still see and clear that flag or every later query in the SAME
# transaction raises TransactionManagementError. record() / record_anon()
# guard against this themselves by running their create() inside a nested
# `transaction.atomic()` savepoint (see audit.py docstrings), so wrapping
# the call in an explicit outer `transaction.atomic()` here both proves
# the exact failure mode this repo used to be exposed to and keeps the
# rest of this test (and the suite's shared seeded data) intact. The
# transaction-poisoning regression tests below assert the fix directly:
# a follow-up query in the SAME outer atomic block must still succeed.
def test_record_swallows_serialization_failure():
    """A `set` inside metadata is not JSON-serializable -> the real
    Postgres INSERT really raises TypeError while encoding the JSONField;
    record() must swallow it (best-effort, never raises) rather than 500
    the request that triggered the audit call."""
    before = AuditEvent.objects.count()
    with transaction.atomic():
        audit.record(
            None, 'cov.audit.unserializable',
            metadata={'bad': {1, 2, 3}},
        )
    # No row was persisted, and no exception escaped.
    assert AuditEvent.objects.count() == before


def test_record_anon_swallows_serialization_failure():
    before = AuditEvent.objects.count()
    with transaction.atomic():
        audit.record_anon(
            None, 'cov.audit.anon.unserializable',
            metadata={'bad': {1, 2, 3}},
        )
    assert AuditEvent.objects.count() == before


# ───────────────────────────────────── transaction-poisoning regression
#
# Real bug (fixed): record()/record_anon() used to call
# `AuditEvent.objects.create(...)` bare inside their try/except. If that
# create() raised a REAL DB error (not just a Python-level TypeError)
# while already nested inside a caller's OPEN `transaction.atomic()`
# block, the except swallowed the Python exception but Django's
# connection still had `needs_rollback` set -- so the very NEXT ORM
# query issued in that same atomic block raised
# TransactionManagementError, breaking the caller even though record()
# itself "never raised". `action` is stored in a `varchar(80)` column
# (see AuditEvent.action) and is NOT length-truncated the way
# `target_id` is, so an over-length action string reaches Postgres
# untouched and trips a genuine `DataError: value too long for type
# character varying(80)` -- a real constraint failure, no mocking.
#
# The fix wraps each create() in its own nested `transaction.atomic()`
# savepoint so a failure there rolls back only that savepoint, leaving
# the caller's outer transaction (and its `needs_rollback` flag) clean.
def test_record_db_error_does_not_poison_callers_transaction():
    before = AuditEvent.objects.count()
    with transaction.atomic():
        # action exceeds the varchar(80) column limit -> real Postgres
        # DataError raised deep inside AuditEvent.objects.create().
        audit.record(None, 'x' * 200)
        # The regression: before the fix, this follow-up query -- still
        # inside the SAME outer atomic block -- would raise
        # TransactionManagementError even though record() swallowed its
        # own exception and logged a warning instead of raising.
        count = AuditEvent.objects.count()
    assert count == before  # the oversized row was never persisted
    assert AuditEvent.objects.count() == before


def test_record_anon_db_error_does_not_poison_callers_transaction():
    before = AuditEvent.objects.count()
    with transaction.atomic():
        audit.record_anon(None, 'y' * 200)
        count = AuditEvent.objects.count()
    assert count == before
    assert AuditEvent.objects.count() == before


# ─────────────────────────────────────────────────────── _request_user
def test_request_user_none_request_returns_none():
    audit.record(None, 'cov.audit.none.request')
    evt = AuditEvent.objects.get(action='cov.audit.none.request')
    assert evt.actor_id is None


def test_request_user_prefers_api_user(django_user_model):
    api_user = django_user_model.objects.create_user(
        username='cov_audit_apiuser', password='x')
    req = RequestFactory().post('/')
    req.api_user = api_user
    audit.record(req, 'cov.audit.api_user.attribution')
    evt = AuditEvent.objects.get(action='cov.audit.api_user.attribution')
    assert evt.actor_id == api_user.id


def test_request_user_falls_back_to_session_user(django_user_model):
    user = django_user_model.objects.create_user(
        username='cov_audit_sessionuser', password='x')
    req = RequestFactory().post('/')
    req.user = user
    audit.record(req, 'cov.audit.session_user.attribution')
    evt = AuditEvent.objects.get(action='cov.audit.session_user.attribution')
    assert evt.actor_id == user.id


def test_request_user_anonymous_session_returns_none():
    req = RequestFactory().post('/')
    req.user = AnonymousUser()
    audit.record(req, 'cov.audit.anon.session')
    evt = AuditEvent.objects.get(action='cov.audit.anon.session')
    assert evt.actor_id is None


# ─────────────────────────────────────────────────────── _client_ip
def test_client_ip_uses_first_forwarded_for_entry():
    req = RequestFactory().post(
        '/', HTTP_X_FORWARDED_FOR='203.0.113.5, 10.0.0.1')
    audit.record(req, 'cov.audit.xff')
    evt = AuditEvent.objects.get(action='cov.audit.xff')
    assert evt.ip_address == '203.0.113.5'


def test_client_ip_falls_back_to_remote_addr():
    req = RequestFactory().post('/', REMOTE_ADDR='198.51.100.9')
    audit.record(req, 'cov.audit.remoteaddr')
    evt = AuditEvent.objects.get(action='cov.audit.remoteaddr')
    assert evt.ip_address == '198.51.100.9'
