"""
@require_permission decorator tests (H17).

Four behaviors pinned:

  * Allow when the user holds the permission.
  * Deny otherwise — and the denial shape matches the request type
    (HTML 403 page for browser, JSON 403 for API).
  * Honor `request.is_api = True` (set by RestApiAuthMiddleware) when
    formatting the denial — never sniff from URL captures.
  * Honor the dev kill-switch (settings.DISABLE_AUTHENTICATION == '1')
    so local development isn't blocked by missing permission seeds.
    Never set this in production.
"""
import json

import pytest

from django.contrib.auth.models import AnonymousUser
from django.http import JsonResponse
from django.test import RequestFactory, override_settings

from mobinspect.RBAC.decorators import require_permission


# A trivial view that proves it was called by returning a 200.
def _allow_view(request):
    return JsonResponse({'ok': True})


# ─────────────────────────────────────────────────────── allow path
@pytest.mark.django_db
def test_decorator_allows_user_with_permission(analyst_user):
    """Analyst holds 'scan.view' → decorator forwards the request."""
    decorated = require_permission('scan.view')(_allow_view)
    rf = RequestFactory()
    req = rf.get('/some/path')
    req.user = analyst_user
    # Mark non-API so the HTML branch is taken on deny (we expect allow).
    req.is_api = False

    resp = decorated(req)
    assert resp.status_code == 200
    body = json.loads(resp.content.decode('utf-8'))
    assert body == {'ok': True}


# ─────────────────────────────────────────────────────── deny path
@pytest.mark.django_db
def test_decorator_denies_user_without_permission(viewer_user):
    """Viewer lacks 'scan.delete' → decorator returns 403."""
    decorated = require_permission('scan.delete')(_allow_view)
    rf = RequestFactory()
    req = rf.get('/some/path')
    req.user = viewer_user
    req.is_api = False

    resp = decorated(req)
    assert resp.status_code == 403


# ─────────────────────────────────────────────────────── api flag
@pytest.mark.django_db
def test_decorator_returns_json_403_when_api_flag_set(viewer_user):
    """request.is_api = True → JSON body, not the HTML 403 page."""
    decorated = require_permission('scan.delete')(_allow_view)
    rf = RequestFactory()
    req = rf.post('/api/v1/delete_scan')
    req.user = viewer_user
    req.is_api = True  # what RestApiAuthMiddleware sets on success

    resp = decorated(req)
    assert resp.status_code == 403
    # Must be parseable JSON, not an HTML template.
    body = json.loads(resp.content.decode('utf-8'))
    assert body.get('error') == 'forbidden'


@pytest.mark.django_db
def test_decorator_returns_html_403_when_api_flag_unset(viewer_user):
    """Browser request (no is_api flag) → TemplateResponse, not JSON."""
    decorated = require_permission('scan.delete')(_allow_view)
    rf = RequestFactory()
    req = rf.get('/some/path')
    req.user = viewer_user
    # is_api intentionally unset — the decorator must default to HTML.

    resp = decorated(req)
    assert resp.status_code == 403
    # The response is a TemplateResponse; calling .render() materializes
    # the bytes. If we accidentally returned JSON for a browser hit,
    # this would either be JSON or already-rendered HTML — either way
    # the Content-Type tells the truth.
    if hasattr(resp, 'render'):
        resp.render()
    content_type = resp.get('Content-Type', '')
    assert 'application/json' not in content_type, (
        f'Browser-issued denial should not return JSON; got {content_type}')


@pytest.mark.django_db
def test_decorator_returns_401_for_unauth_api(django_user_model):
    """API request from an anonymous client → 401, not 403."""
    decorated = require_permission('scan.view')(_allow_view)
    rf = RequestFactory()
    req = rf.post('/api/v1/scans')
    req.user = AnonymousUser()
    req.is_api = True

    resp = decorated(req)
    assert resp.status_code == 401
    body = json.loads(resp.content.decode('utf-8'))
    assert body.get('error') == 'unauthenticated'


# ─────────────────────────────────────────────────────── dev bypass
@pytest.mark.django_db
@override_settings(DISABLE_AUTHENTICATION='1')
def test_decorator_bypasses_check_when_auth_disabled(viewer_user):
    """DISABLE_AUTHENTICATION='1' short-circuits to the view.

    This is the dev/local kill-switch. Production MUST NEVER set this.
    Pinning the behavior keeps developers honest — if you flip the
    settings value off, this test still passes because it scopes the
    override to a single function.
    """
    # Wrap a permission the user definitely doesn't have, then assert
    # it still passes through.
    decorated = require_permission('admin.user.delete')(_allow_view)
    rf = RequestFactory()
    req = rf.get('/some/path')
    req.user = viewer_user
    req.is_api = False

    resp = decorated(req)
    assert resp.status_code == 200, (
        'DISABLE_AUTHENTICATION=1 must bypass require_permission')


@pytest.mark.django_db
def test_decorator_requires_at_least_one_codename():
    """Empty arg list → ValueError at decoration time.

    Catches a typo like `@require_permission()` that would otherwise
    silently allow everything.
    """
    with pytest.raises(ValueError):
        require_permission()  # no codenames
