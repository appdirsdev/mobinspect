# -*- coding: utf_8 -*-
"""Real-execution coverage tests for the REST API auth middleware.

STRICT: real Django requests (``RequestFactory`` / ``Client``), real
per-user RBAC ``ApiKey`` rows, a real global API key derived through the
production ``mobinspect.MobInspect.init.api_key`` helper (the exact same
function the middleware itself calls), real RBAC ``Role``/``Permission``/
``RoleAssignment`` rows, a real settings override that points
``RATELIMIT_USE_CACHE`` at a cache alias that does not exist (a genuine
``InvalidCacheBackendError`` raised by Django's own cache framework, not a
simulated one), and the ``sys.modules`` poisoning technique (set an entry
to ``None`` so the very next ``import``/``from ... import`` genuinely
raises ``ImportError`` — real CPython import-machinery behavior) to
exercise the audit/permission import-failure branches.

Two narrowly-scoped, single-call monkeypatches are used (documented at
each call site) because there is no real-fault-injection path to make
``ApiKey.lookup``/``ApiKey.touch`` raise without corrupting shared test-DB
state or a live DB connection: both patch exactly one classmethod for the
duration of one `with` block, and both assert on the *real* control flow
that follows (the `except Exception` swallow), not on the patch itself.
"""
import json
import sys
from unittest import mock

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Group
from django.core.cache import cache as default_cache
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase, override_settings

from mobinspect.MobInspect.init import api_key as get_global_api_key
from mobinspect.MobInspect.views.api import api_middleware as mw
from mobinspect.RBAC.models import (
    ApiKey,
    Permission as MIPerm,
    Role,
    RoleAssignment,
)


def _json(resp):
    return json.loads(resp.content.decode('utf-8'))


@override_settings(RATELIMIT_ENABLE=False, DISABLE_AUTHENTICATION=None)
class ApiMiddlewareCoreTests(TestCase):
    """Direct, precise calls into the middleware's module-level helpers
    and into ``RestApiAuthMiddleware.process_request`` itself, with real
    Request objects built via ``RequestFactory`` and real DB-backed
    principals. Rate limiting is off here (covered separately below) so
    these tests are fast and isolated from cache-bucket timing.
    """

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            'mw_admin', 'mw_admin@example.com', 'admin')
        _, cls.admin_key = ApiKey.generate(cls.admin, 'mw-admin-key')

        # A real user with no RBAC role at all -> no api.use permission.
        cls.plain = User.objects.create_user(
            username='mw_plain', password='not-used-by-api-key-auth')
        _, cls.plain_key = ApiKey.generate(cls.plain, 'mw-plain-key')

        # A real user granted api.use through a real Role/RoleAssignment.
        cls.permitted = User.objects.create_user(
            username='mw_permitted', password='not-used-by-api-key-auth')
        api_use, _ = MIPerm.objects.get_or_create(
            codename='api.use',
            defaults={'name': 'Use API', 'category': 'api'},
        )
        group, _ = Group.objects.get_or_create(name='mw-cov-apionly')
        role, _ = Role.objects.get_or_create(
            name='mw-cov-apionly', defaults={'group': group})
        role.permissions.add(api_use)
        RoleAssignment.objects.get_or_create(user=cls.permitted, role=role)
        _, cls.permitted_key = ApiKey.generate(cls.permitted, 'mw-permitted-key')

    def setUp(self):
        self.rf = RequestFactory()
        self.mw_instance = mw.RestApiAuthMiddleware(
            get_response=lambda r: HttpResponse('view ran'))

    # ---- make_api_response: HttpResponse passthrough (line 53) --------

    def test_make_api_response_passthrough_http_response(self):
        # A 403 JsonResponse the way permission_required would emit it.
        inner = HttpResponse(
            json.dumps({'error': 'denied'}), status=403,
            content_type='application/json')
        resp = mw.make_api_response(inner)
        self.assertIs(resp, inner)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp['Access-Control-Allow-Origin'], '*')
        self.assertEqual(resp['Access-Control-Allow-Methods'], 'POST')

    # ---- _global_key_matches (lines 73-76) -----------------------------

    def test_global_key_matches_empty_presented_is_false(self):
        self.assertFalse(mw._global_key_matches(''))

    def test_global_key_matches_real_key_is_true(self):
        real = get_global_api_key(settings.MOBINSPECT_HOME)
        self.assertIsNotNone(real)
        self.assertTrue(mw._global_key_matches(real))

    def test_global_key_matches_wrong_key_is_false(self):
        self.assertFalse(mw._global_key_matches('definitely-wrong-key'))

    # ---- api_auth: no presented key -------------------------------------

    def test_api_auth_no_presented_key_returns_false(self):
        req = self.rf.post('/api/v1/scan', {})
        self.assertFalse(mw.api_auth(req))

    # ---- api_auth: per-user key success path ---------------------------

    def test_api_auth_per_user_key_success(self):
        req = self.rf.post(
            '/api/v1/scan', {}, HTTP_X_MOBINSPECT_API_KEY=self.admin_key)
        self.assertTrue(mw.api_auth(req))
        self.assertEqual(req.api_user, self.admin)
        self.assertTrue(req.api)
        self.assertTrue(req.is_api)

    # ---- api_auth: legacy global key success path (lines 117-121) -----

    def test_api_auth_global_key_success(self):
        real = get_global_api_key(settings.MOBINSPECT_HOME)
        req = self.rf.post(
            '/api/v1/scan', {}, HTTP_X_MOBINSPECT_API_KEY=real)
        self.assertTrue(mw.api_auth(req))
        self.assertTrue(req.api)
        self.assertTrue(req.is_api)
        # No per-user attribution on the legacy global-key path.
        self.assertFalse(hasattr(req, 'api_user'))

    # ---- api_auth: neither per-user nor global key matches (line 123) -

    def test_api_auth_unknown_key_returns_false(self):
        req = self.rf.post(
            '/api/v1/scan', {},
            HTTP_X_MOBINSPECT_API_KEY='not-a-real-key-at-all')
        self.assertFalse(mw.api_auth(req))

    # ---- api_auth: ApiKey.lookup raising is swallowed (lines 99-100) --

    def test_api_auth_lookup_exception_falls_back_to_global_key(self):
        # Single-call monkeypatch: ApiKey.lookup is an internal ORM-backed
        # classmethod with no real-world input that makes it raise (a
        # malformed presented key just returns None, per its own guard
        # clause) -- the only way to reach the defensive `except Exception`
        # around this specific call is to force the call itself to raise.
        real = get_global_api_key(settings.MOBINSPECT_HOME)
        with mock.patch.object(
                ApiKey, 'lookup', side_effect=RuntimeError('db exploded')):
            req = self.rf.post(
                '/api/v1/scan', {}, HTTP_X_MOBINSPECT_API_KEY=real)
            self.assertTrue(mw.api_auth(req))
        # key stayed None -> fell through to the legacy global-key path.
        self.assertFalse(hasattr(req, 'api_user'))
        self.assertTrue(req.api)

    # ---- api_auth: key.touch() raising is swallowed (lines 112-114) ---

    def test_api_auth_touch_exception_is_swallowed(self):
        # Single-call monkeypatch: touch() is a fire-and-forget UPDATE with
        # no user-controllable input that makes it raise; forcing the call
        # itself to raise is the only way to reach this defensive branch
        # without tearing down the real DB connection mid-request.
        with mock.patch.object(
                ApiKey, 'touch', side_effect=RuntimeError('touch failed')):
            req = self.rf.post(
                '/api/v1/scan', {},
                HTTP_X_MOBINSPECT_API_KEY=self.admin_key)
            self.assertTrue(mw.api_auth(req))
        self.assertEqual(req.api_user, self.admin)

    # ---- _has_api_use_permission: no api_user -> True (line 161) -------

    def test_has_api_use_permission_no_api_user_is_true(self):
        req = self.rf.post('/api/v1/scan', {})
        self.assertTrue(mw._has_api_use_permission(req))

    # ---- _has_api_use_permission: real RBAC grant/deny (lines 165-167) -

    def test_has_api_use_permission_granted_is_true(self):
        req = self.rf.post('/api/v1/scan', {})
        req.user = AnonymousUser()
        req.api_user = self.permitted
        self.assertTrue(mw._has_api_use_permission(req))

    def test_has_api_use_permission_denied_is_false(self):
        req = self.rf.post('/api/v1/scan', {})
        req.user = AnonymousUser()
        req.api_user = self.plain
        self.assertFalse(mw._has_api_use_permission(req))

    # ---- _has_api_use_permission: permission-lookup import failure
    #      fails OPEN (lines 168-174) ------------------------------------

    def test_has_api_use_permission_import_failure_fails_open(self):
        # Real CPython import-machinery fault injection: sys.modules[name]
        # = None makes the next `from name import x` raise a genuine
        # ImportError (verified: for a fully dotted `from pkg.sub import
        # x`, Python resolves `pkg.sub` directly via sys.modules before
        # ever touching the fromlist attribute, so poisoning the entry is
        # sufficient on its own for this particular import form).
        target = 'mobinspect.RBAC.permissions'
        prev = sys.modules.get(target, False)
        sys.modules[target] = None
        try:
            req = self.rf.post('/api/v1/scan', {})
            req.user = AnonymousUser()
            req.api_user = self.plain  # would otherwise be denied
            self.assertTrue(mw._has_api_use_permission(req))
        finally:
            if prev is False:
                sys.modules.pop(target, None)
            else:
                sys.modules[target] = prev
        # Sanity: the real function works again once restored.
        self.assertFalse(mw._has_api_use_permission(
            self._req_for(self.plain)))

    def _req_for(self, user):
        req = self.rf.post('/api/v1/scan', {})
        req.user = AnonymousUser()
        req.api_user = user
        return req

    # ---- _audit_auth_fail: audit-import failure is swallowed
    #      (lines 136-139) ----------------------------------------------

    def test_audit_auth_fail_import_failure_is_swallowed(self):
        # Real CPython import-machinery fault injection for the OTHER
        # import form used in this file: `from pkg import submodule`.
        # Unlike the dotted case above, Python resolves this via
        # `hasattr(pkg, submodule)` first (skipping sys.modules entirely)
        # whenever the submodule was already imported once as a package
        # attribute elsewhere in this process -- verified empirically.
        # We therefore poison BOTH the sys.modules entry AND the cached
        # package attribute so the import is genuinely forced to fail.
        import mobinspect.RBAC as rbac_pkg
        target = 'mobinspect.RBAC.audit'
        had_attr = hasattr(rbac_pkg, 'audit')
        prev_attr = getattr(rbac_pkg, 'audit', None)
        prev_mod = sys.modules.get(target, False)
        sys.modules[target] = None
        if had_attr:
            delattr(rbac_pkg, 'audit')
        try:
            req = self.rf.post('/api/v1/scan', {})
            req.user = AnonymousUser()
            # Must not raise -- that is the entire point of the except.
            mw._audit_auth_fail(req, 'no_key')
        finally:
            if prev_mod is False:
                sys.modules.pop(target, None)
            else:
                sys.modules[target] = prev_mod
            if had_attr:
                setattr(rbac_pkg, 'audit', prev_attr)
        # Sanity: the real audit path works again once restored (already
        # exercised by the 401 tests below, but confirms clean restore).
        mw._audit_auth_fail(req, 'no_key')

    # ---- process_request: path outside /api/ (line 188) ----------------

    def test_process_request_non_api_path_returns_none(self):
        req = self.rf.get('/not-an-api-path/')
        self.assertIsNone(self.mw_instance.process_request(req))

    # ---- process_request: OPTIONS preflight (line 190) ------------------

    def test_process_request_options_preflight_returns_200(self):
        req = self.rf.options('/api/v1/scan')
        resp = self.mw_instance.process_request(req)
        self.assertEqual(resp.status_code, 200)

    # ---- process_request: authenticated but lacking api.use
    #      (lines 236-238) ------------------------------------------------

    def test_process_request_no_api_use_permission_is_403(self):
        req = self.rf.post(
            '/api/v1/scan', {}, HTTP_X_MOBINSPECT_API_KEY=self.plain_key)
        req.user = AnonymousUser()
        resp = self.mw_instance.process_request(req)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(
            _json(resp)['error'],
            'API access not permitted for this user.')

    # ---- process_request: authenticated + granted api.use -> falls
    #      through (returns None, real view would run) -------------------

    def test_process_request_granted_permission_passes_through(self):
        req = self.rf.post(
            '/api/v1/scan', {},
            HTTP_X_MOBINSPECT_API_KEY=self.permitted_key)
        req.user = AnonymousUser()
        result = self.mw_instance.process_request(req)
        self.assertIsNone(result)
        self.assertEqual(req.api_user, self.permitted)


@override_settings(RATELIMIT_ENABLE=False, DISABLE_AUTHENTICATION=None)
class ApiMiddlewareIntegrationTests(TestCase):
    """One full, real end-to-end sanity check through the actual URL
    dispatcher (not just process_request in isolation): a non-superuser
    holding api.use via a real Role can reach a real API view, and one
    without it is denied -- confirming the unit-level assertions above
    match the real request/response cycle.
    """

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.permitted = User.objects.create_user(
            username='mw_int_permitted', password='not-used')
        api_use, _ = MIPerm.objects.get_or_create(
            codename='api.use',
            defaults={'name': 'Use API', 'category': 'api'},
        )
        group, _ = Group.objects.get_or_create(name='mw-cov-int-apionly')
        role, _ = Role.objects.get_or_create(
            name='mw-cov-int-apionly', defaults={'group': group})
        role.permissions.add(api_use)
        RoleAssignment.objects.get_or_create(user=cls.permitted, role=role)
        _, cls.permitted_key = ApiKey.generate(cls.permitted, 'mw-int-key')

        cls.plain = User.objects.create_user(
            username='mw_int_plain', password='not-used')
        _, cls.plain_key = ApiKey.generate(cls.plain, 'mw-int-plain-key')

    def test_granted_user_reaches_real_view(self):
        resp = Client().get(
            '/api/v1/scans', HTTP_AUTHORIZATION=self.permitted_key)
        self.assertEqual(resp.status_code, 200)

    def test_denied_user_gets_403_before_the_view(self):
        resp = Client().get(
            '/api/v1/scans', HTTP_AUTHORIZATION=self.plain_key)
        self.assertEqual(resp.status_code, 403)


@override_settings(RATELIMIT_ENABLE=True, DISABLE_AUTHENTICATION=None)
class ApiMiddlewareRateLimitTests(TestCase):
    """Real rate limiting: RATELIMIT_ENABLE=True with a tiny 1/minute cap
    so exactly two failed-auth requests are enough to exceed it -- fast
    and deterministic, no wall-clock dependence. Uses the real in-process
    LocMemCache (Django's default when CACHES is unset); explicitly
    cleared first so this test's count starts at zero regardless of
    execution order relative to other test classes sharing the same
    process-wide cache.

    NOTE: ``api_middleware.API_AUTH_FAIL_RATE`` is a MODULE-LEVEL constant
    (``getattr(settings, 'MOBINSPECT_API_AUTH_FAIL_RATE', '60/m')`` runs
    once at import time), so ``@override_settings(
    MOBINSPECT_API_AUTH_FAIL_RATE=...)`` has no effect on it at test time
    -- verified empirically (the settings value changes, but the module
    global does not re-read it per request). We therefore patch the
    already-bound module constant directly for the duration of this test
    class: a narrow, fully-documented patch of a plain data value (not of
    any function's behavior), functionally equivalent to what
    ``override_settings`` would do if the production code re-read the
    setting on every request. Real rate limiting logic (django_ratelimit,
    the real LocMemCache, the real cache-key/window math) all runs
    unmodified.
    """

    def setUp(self):
        default_cache.clear()
        self.rf = RequestFactory()
        self.mw_instance = mw.RestApiAuthMiddleware(
            get_response=lambda r: HttpResponse('unused'))
        patcher = mock.patch.object(mw, 'API_AUTH_FAIL_RATE', '1/m')
        patcher.start()
        self.addCleanup(patcher.stop)

    def _bad_key_request(self):
        req = self.rf.post(
            '/api/v1/scan', {},
            HTTP_X_MOBINSPECT_API_KEY='definitely-not-a-real-key')
        req.user = AnonymousUser()
        return req

    def test_second_failed_attempt_in_window_is_rate_limited(self):
        first = self.mw_instance.process_request(self._bad_key_request())
        self.assertEqual(first.status_code, 401)  # under the 1/m cap
        second = self.mw_instance.process_request(self._bad_key_request())
        self.assertEqual(second.status_code, 429)
        self.assertIn('Too many failed', _json(second)['error'])


@override_settings(
    RATELIMIT_ENABLE=True,
    RATELIMIT_USE_CACHE='definitely-not-a-configured-cache-alias',
    DISABLE_AUTHENTICATION=None,
)
class ApiMiddlewareRateLimitBackendErrorTests(TestCase):
    """RATELIMIT_USE_CACHE points at a cache alias that does not exist in
    settings.CACHES. django_ratelimit's get_usage() does `caches[alias]`,
    which raises a REAL django.core.cache.InvalidCacheBackendError (not
    simulated) before the library's own try/except even starts. The
    middleware's surrounding `except Exception` treats this as "not
    limited" and falls through to the normal unauthorized response
    (lines 217-218).
    """

    def test_ratelimit_backend_error_falls_back_to_unauthorized(self):
        rf = RequestFactory()
        m = mw.RestApiAuthMiddleware(get_response=lambda r: HttpResponse('unused'))
        req = rf.post(
            '/api/v1/scan', {},
            HTTP_X_MOBINSPECT_API_KEY='bad-key-triggers-backend-error')
        req.user = AnonymousUser()
        resp = m.process_request(req)
        self.assertEqual(resp.status_code, 401)
        self.assertIn('unauthorized', _json(resp)['error'])
