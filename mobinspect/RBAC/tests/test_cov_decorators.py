"""Real-execution coverage tests for mobinspect/RBAC/decorators.py.

STRICT: no mocks. Drives the real `require_permission` / `require_role`
decorators directly (wrapping a trivial view) with real
`django.test.RequestFactory` requests and real RBAC-seeded users, mirroring
the style of the sibling `mobinspect/RBAC/tests/test_decorators.py`.

Focus of this file:
  * require_permission's anonymous, non-API redirect-to-login branch,
    including the open-redirect guard on the `next` parameter (a branch
    test_decorators.py does not reach because every URL-routed view in
    this project stacks @login_required OUTSIDE @require_permission, so
    an anonymous request never reaches require_permission's own
    unauthenticated branch through routing -- calling the decorator
    directly, exactly like test_decorators.py already does, reaches it).
  * require_permission's zero-codename guard (raises ValueError) and its
    anonymous + API-flag branch (401 JSON) -- both already pinned in the
    sibling test_decorators.py, mirrored here as well.
  * require_role end to end (dev bypass, anonymous API/non-API,
    superuser bypass, role match, role mismatch -> deny).
"""
import json

import pytest

from django.contrib.auth.models import AnonymousUser
from django.http import JsonResponse
from django.test import RequestFactory, override_settings

from mobinspect.RBAC.decorators import require_permission, require_role


def _allow_view(request):
    return JsonResponse({'ok': True})


# ═══════════════════════════════════ require_permission: anon redirect
@pytest.mark.django_db
def test_anonymous_non_api_redirects_to_login_with_safe_next():
    decorated = require_permission('scan.view')(_allow_view)
    rf = RequestFactory()
    req = rf.get('/some/protected/path')
    req.user = AnonymousUser()
    req.is_api = False

    resp = decorated(req)
    assert resp.status_code == 302
    assert 'next=/some/protected/path' in resp['Location']


def test_require_permission_needs_at_least_one_codename():
    """Empty arg list -> ValueError at decoration time (guards against a
    typo'd `@require_permission()` silently allowing everything)."""
    with pytest.raises(ValueError):
        require_permission()  # no codenames


@pytest.mark.django_db
def test_anonymous_api_request_gets_401_not_redirect():
    """user is None (anonymous) + request.is_api=True -> JSON 401, taking
    the API branch instead of the non-API redirect-to-login branch above."""
    decorated = require_permission('scan.view')(_allow_view)
    rf = RequestFactory()
    req = rf.post('/api/v1/scans')
    req.user = AnonymousUser()
    req.is_api = True

    resp = decorated(req)
    assert resp.status_code == 401
    body = json.loads(resp.content.decode('utf-8'))
    assert body == {'error': 'unauthenticated'}


@pytest.mark.django_db
def test_anonymous_non_api_redirect_sanitizes_unsafe_next():
    """An attacker-controlled `next` that fails the safe-redirect check
    must be replaced with '/' -- never handed back verbatim."""
    decorated = require_permission('scan.view')(_allow_view)
    rf = RequestFactory()
    req = rf.get('/some/path')
    req.user = AnonymousUser()
    req.is_api = False
    # Simulate an open-redirect payload as the "current" full path --
    # a protocol-relative URL whose host does not match allowed_hosts.
    req.get_full_path = lambda: '//evil.example.com/phish'

    resp = decorated(req)
    assert resp.status_code == 302
    assert 'next=/' in resp['Location']
    assert 'evil.example.com' not in resp['Location']


# ═══════════════════════════════════ require_role
def test_require_role_needs_at_least_one_name():
    with pytest.raises(ValueError):
        require_role()


@pytest.mark.django_db
@override_settings(DISABLE_AUTHENTICATION='1')
def test_require_role_dev_bypass(viewer_user):
    decorated = require_role('Administrator')(_allow_view)
    rf = RequestFactory()
    req = rf.get('/x')
    req.user = viewer_user
    req.is_api = False
    resp = decorated(req)
    assert resp.status_code == 200


@pytest.mark.django_db
def test_require_role_anonymous_api_gets_401():
    decorated = require_role('Administrator')(_allow_view)
    rf = RequestFactory()
    req = rf.post('/api/x')
    req.user = AnonymousUser()
    req.is_api = True
    resp = decorated(req)
    assert resp.status_code == 401
    body = json.loads(resp.content.decode('utf-8'))
    assert body == {'error': 'unauthenticated'}


@pytest.mark.django_db
def test_require_role_anonymous_non_api_redirects():
    decorated = require_role('Administrator')(_allow_view)
    rf = RequestFactory()
    req = rf.get('/x')
    req.user = AnonymousUser()
    req.is_api = False
    resp = decorated(req)
    assert resp.status_code == 302


@pytest.mark.django_db
def test_require_role_superuser_bypasses_role_check(superuser):
    """is_superuser short-circuits the role-membership check entirely,
    even holding none of the named roles."""
    decorated = require_role('SomeRoleTheSuperuserDoesNotHold')(_allow_view)
    rf = RequestFactory()
    req = rf.get('/x')
    req.user = superuser
    req.is_api = False
    resp = decorated(req)
    assert resp.status_code == 200


@pytest.mark.django_db
def test_require_role_matching_role_allows(admin_user):
    decorated = require_role('Administrator')(_allow_view)
    rf = RequestFactory()
    req = rf.get('/x')
    req.user = admin_user
    req.is_api = False
    resp = decorated(req)
    assert resp.status_code == 200


@pytest.mark.django_db
def test_require_role_mismatched_role_denies_html(viewer_user):
    decorated = require_role('Administrator')(_allow_view)
    rf = RequestFactory()
    req = rf.get('/x')
    req.user = viewer_user
    req.is_api = False
    resp = decorated(req)
    assert resp.status_code == 403


@pytest.mark.django_db
def test_require_role_mismatched_role_denies_json_for_api(viewer_user):
    decorated = require_role('Administrator')(_allow_view)
    rf = RequestFactory()
    req = rf.post('/api/x')
    req.user = viewer_user
    req.is_api = True
    resp = decorated(req)
    assert resp.status_code == 403
    body = json.loads(resp.content.decode('utf-8'))
    assert body.get('error') == 'forbidden'
