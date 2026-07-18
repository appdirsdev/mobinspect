# -*- coding: utf_8 -*-
"""Real-execution coverage tests for the Android dynamic-analysis REST API.

STRICT: no mocks, no monkeypatch of internal logic, no fake return values.

These tests drive the real wrapper views in
``mobinspect.MobInspect.views.api.api_android_dynamic_analysis`` through the real
Django URL router + REST auth middleware, authenticated with a real
per-user RBAC ``ApiKey`` minted for a real superuser row in a real
(SQLite) test database.

No Android device / emulator is available in this environment, so we only
exercise the *reachable* request-validation and no-device error branches:

  * Missing / partial required params  -> HTTP 422 ("Missing Parameters")
  * Well-formed request but invalid hash / bad action -> the analyzer
    returns an error dict which the wrapper surfaces as HTTP 500 (or a
    403 RBAC pass-through).
  * A disallowed adb subcommand -> the allowlist denial is a *security*
    denial, not a server error, and the wrapper surfaces it as HTTP 403
    (or, if the RBAC `dynamic.adb.shell` gate denies first, also 403).
  * Two pure-filesystem endpoints (frida script listing / frida logs)
    that legitimately return HTTP 200 without any device.

Everything that requires a live device/Frida/adb-reachable emulator is
noted as a ceiling gap and intentionally NOT faked.
"""
import json
import os
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Group
from django.test import Client, RequestFactory, TestCase, override_settings

from mobinspect.MobInspect.views.api import api_android_dynamic_analysis as api_dz
from mobinspect.RBAC.models import (
    ApiKey,
    Permission as MIPerm,
    Role,
    RoleAssignment,
)
from mobinspect.StaticAnalyzer.models import StaticAnalyzerAndroid


# A syntactically valid but unreachable device identifier. Setting this
# via the documented ANALYZER_IDENTIFIER hook (real config, not a mock)
# makes get_device() return deterministically without shelling out to
# `adb devices` on every Environment() construction, so the invalid-param
# branches return fast and deterministically. No connection is ever made
# because every path we hit early-returns before device I/O.
_FAKE_IDENTIFIER = '127.0.0.1:5555'


def setUpModule():
    os.environ['ANALYZER_IDENTIFIER'] = _FAKE_IDENTIFIER


def tearDownModule():
    os.environ.pop('ANALYZER_IDENTIFIER', None)


@override_settings(
    # Exercise the real permission checks (kill-switch off).
    DISABLE_AUTHENTICATION=None,
    # The client hits many endpoints in a tight loop; do not 429.
    RATELIMIT_ENABLE=False,
)
class AndroidDynamicApiTests(TestCase):
    """Reachable request-validation + no-device error branches."""

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            username='dyn_api_admin',
            email='dyn_api_admin@example.com',
            password='not-used-by-api-key-auth',
        )
        # Real per-user RBAC API key (plaintext used in the header).
        _obj, cls.api_key = ApiKey.generate(
            user=cls.admin,
            name='android-dyn-cov',
        )

        # A real, non-privileged user who holds only `api.use` (so the
        # middleware lets the request through to the view) but NOT
        # `scan.*`. Every SCAN-guarded underlying view therefore returns a
        # real RBAC 403 JsonResponse, which exercises the wrapper's
        # `_passthrough` denial branch (no mocks — a genuine RBAC denial).
        cls.viewer = User.objects.create_user(
            username='dyn_api_viewer',
            password='not-used-by-api-key-auth',
        )
        api_use, _ = MIPerm.objects.get_or_create(
            codename='api.use',
            defaults={'name': 'Use API', 'category': 'api'},
        )
        group, _ = Group.objects.get_or_create(name='dyn-cov-apionly')
        role, _ = Role.objects.get_or_create(
            name='dyn-cov-apionly', defaults={'group': group})
        role.permissions.add(api_use)
        RoleAssignment.objects.get_or_create(user=cls.viewer, role=role)
        _obj2, cls.viewer_key = ApiKey.generate(
            user=cls.viewer,
            name='android-dyn-cov-viewer',
        )

    def setUp(self):
        # raise_request_exception=False: if an underlying device-only code
        # path raises instead of returning an error dict, we still get a
        # real 500 HTTP response to assert on (rather than the exception
        # propagating into the test runner). We are NOT suppressing errors
        # in the target module — only observing the real response the
        # framework produces.
        self.client = Client(raise_request_exception=False)

    # ---- helpers -------------------------------------------------------

    def _post(self, path, data=None):
        return self.client.post(
            path,
            data=data or {},
            HTTP_X_MOBINSPECT_API_KEY=self.api_key,
        )

    def _get(self, path, data=None):
        return self.client.get(
            path,
            data=data or {},
            HTTP_X_MOBINSPECT_API_KEY=self.api_key,
        )

    def _authed_post_request(self, path, data=None):
        """Build a real POST request carrying the same auth attributes the
        REST middleware sets on a successful per-user ApiKey auth.

        Used for api_screenshot, which has no URL route in urls.py and so
        cannot be reached through the test Client — we invoke the real view
        function directly. Nothing is mocked: request.api_user is the real
        superuser row and the real permission decorators run against it.
        """
        request = RequestFactory().post(path, data=data or {})
        request.user = AnonymousUser()
        request.api_user = self.admin
        request.api = True
        request.is_api = True
        return request

    def _json(self, resp):
        return json.loads(resp.content.decode('utf-8'))

    def _assert_missing_params(self, resp):
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(self._json(resp).get('error'), 'Missing Parameters')

    # ---- auth is real (sanity) ----------------------------------------

    def test_unauthenticated_is_401(self):
        """No API key -> middleware 401 before the view runs."""
        resp = self.client.post(
            '/api/v1/dynamic/start_analysis', data={'hash': '0' * 32})
        self.assertEqual(resp.status_code, 401)

    # ---- 422 missing-params branch for every guarded endpoint ---------

    def test_start_analysis_missing_hash(self):
        self._assert_missing_params(
            self._post('/api/v1/dynamic/start_analysis'))

    def test_logcat_missing_package(self):
        self._assert_missing_params(self._post('/api/v1/android/logcat'))

    def test_mobinspecty_missing_identifier(self):
        self._assert_missing_params(self._post('/api/v1/android/mobinspecty'))

    def test_screenshot_missing_hash(self):
        # api_screenshot has no URL route; call the real view directly.
        request = self._authed_post_request('/screenshot')
        self._assert_missing_params(api_dz.api_screenshot(request))

    def test_adb_execute_missing_cmd(self):
        self._assert_missing_params(
            self._post('/api/v1/android/adb_command'))

    def test_root_ca_missing_action(self):
        self._assert_missing_params(self._post('/api/v1/android/root_ca'))

    def test_global_proxy_missing_action(self):
        self._assert_missing_params(
            self._post('/api/v1/android/global_proxy'))

    def test_act_tester_missing_params(self):
        self._assert_missing_params(self._post('/api/v1/android/activity'))

    def test_start_activity_missing_params(self):
        self._assert_missing_params(
            self._post('/api/v1/android/start_activity'))

    def test_tls_tester_missing_hash(self):
        self._assert_missing_params(
            self._post('/api/v1/android/tls_tests'))

    def test_stop_analysis_missing_hash(self):
        self._assert_missing_params(
            self._post('/api/v1/dynamic/stop_analysis'))

    def test_instrument_missing_params(self):
        self._assert_missing_params(
            self._post('/api/v1/frida/instrument'))

    def test_api_monitor_missing_hash(self):
        self._assert_missing_params(
            self._post('/api/v1/frida/api_monitor'))

    def test_frida_logs_missing_hash(self):
        self._assert_missing_params(self._post('/api/v1/frida/logs'))

    def test_list_frida_scripts_missing_device(self):
        self._assert_missing_params(
            self._post('/api/v1/frida/list_scripts'))

    def test_get_script_missing_scripts(self):
        # scripts[] absent -> first 422 guard.
        self._assert_missing_params(
            self._post('/api/v1/frida/get_script', {'device': 'android'}))

    def test_get_script_missing_device(self):
        # scripts[] present but device absent -> second 422 guard.
        self._assert_missing_params(
            self._post(
                '/api/v1/frida/get_script', {'scripts[]': ['nope']}))

    def test_get_dependencies_missing_hash(self):
        self._assert_missing_params(
            self._post('/api/v1/frida/get_dependencies'))

    def test_dynamic_report_missing_hash(self):
        self._assert_missing_params(
            self._post('/api/v1/dynamic/report_json'))

    def test_view_file_missing_params(self):
        self._assert_missing_params(
            self._post('/api/v1/dynamic/view_source'))

    # ---- valid request, no device -> error/success surfaced -----------

    def test_start_analysis_invalid_hash_500(self):
        """Well-formed POST, non-MD5 hash -> analyzer 'Invalid Hash'."""
        resp = self._post(
            '/api/v1/dynamic/start_analysis', {'hash': 'not-a-real-hash'})
        self.assertEqual(resp.status_code, 500)
        self.assertIn('error', self._json(resp))

    def test_screenshot_invalid_hash_500(self):
        request = self._authed_post_request(
            '/screenshot', {'hash': 'not-a-real-hash'})
        resp = api_dz.api_screenshot(request)
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(self._json(resp).get('status'), 'failed')

    def test_mobinspecty_command_injection_500(self):
        """Injection markers in identifier -> analyzer 'failed', 500."""
        resp = self._post(
            '/api/v1/android/mobinspecty', {'identifier': 'device;rm -rf /'})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(self._json(resp).get('status'), 'failed')

    def test_adb_execute_disallowed_cmd(self):
        """A subcommand off the allowlist is denied.

        Either the RBAC dynamic.adb.shell gate denies first (403
        pass-through) or the allowlist rejects it (also 403, mapped from
        the underlying {'status': 'denied'} dict). Both are real reachable
        branches of the wrapper and both now converge on 403 -- a security
        denial must never be reported as a 500 server error.
        """
        resp = self._post(
            '/api/v1/android/adb_command',
            {'cmd': 'totally_not_an_allowed_subcommand'})
        self.assertEqual(resp.status_code, 403)

    def test_adb_execute_disallowed_cmd_denied_body_403(self):
        """Regression test for the status-code bug: execute_adb() returns
        {'status': 'denied'} for a non-allowlisted adb subcommand, and the
        wrapper must map that to HTTP 403 (a security denial), not 500.

        The admin user here is a real superuser, so it clears the RBAC
        `dynamic.adb.shell` permission gate for real and reaches the
        allowlist check inside `execute_adb` itself -- this isolates the
        allowlist-denial branch from the RBAC-passthrough branch exercised
        above.
        """
        resp = self._post(
            '/api/v1/android/adb_command',
            {'cmd': 'rm -rf /'})
        self.assertEqual(resp.status_code, 403)
        body = self._json(resp)
        self.assertEqual(body.get('status'), 'denied')

    def test_root_ca_bad_action_500(self):
        resp = self._post(
            '/api/v1/android/root_ca', {'action': 'no-such-action'})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(self._json(resp).get('status'), 'failed')

    def test_global_proxy_no_device_500(self):
        """No reachable device -> Environment version lookup fails -> 500."""
        resp = self._post(
            '/api/v1/android/global_proxy', {'action': 'no-such-action'})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(self._json(resp).get('status'), 'failed')

    def test_act_tester_invalid_hash_500(self):
        resp = self._post(
            '/api/v1/android/activity',
            {'test': 'exported', 'hash': 'not-a-real-hash'})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(self._json(resp).get('status'), 'failed')

    def test_start_activity_invalid_hash_500(self):
        resp = self._post(
            '/api/v1/android/start_activity',
            {'activity': 'MainActivity', 'hash': 'not-a-real-hash'})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(self._json(resp).get('status'), 'failed')

    def test_stop_analysis_invalid_hash_500(self):
        """collect_logs + download_data both reject the bad hash -> 500."""
        resp = self._post(
            '/api/v1/dynamic/stop_analysis', {'hash': 'not-a-real-hash'})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(self._json(resp).get('status'), 'failed')

    def test_instrument_invalid_hash_500(self):
        resp = self._post(
            '/api/v1/frida/instrument',
            {
                'hash': 'not-a-real-hash',
                'default_hooks': '',
                'auxiliary_hooks': '',
                'frida_code': '',
            })
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(self._json(resp).get('status'), 'failed')

    def test_api_monitor_invalid_hash_500(self):
        """live_api rejects bad hash -> no 'data' -> wrapper 500."""
        resp = self._post(
            '/api/v1/frida/api_monitor', {'hash': 'not-a-real-hash'})
        self.assertEqual(resp.status_code, 500)

    def test_get_dependencies_invalid_hash_500(self):
        resp = self._post(
            '/api/v1/frida/get_dependencies', {'hash': 'not-a-real-hash'})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(self._json(resp).get('status'), 'failed')

    def test_dynamic_report_invalid_hash_500(self):
        resp = self._post(
            '/api/v1/dynamic/report_json', {'hash': 'not-a-real-hash'})
        self.assertEqual(resp.status_code, 500)
        self.assertIn('error', self._json(resp))

    def test_view_file_invalid_hash_500(self):
        resp = self._post(
            '/api/v1/dynamic/view_source',
            {'hash': 'not-a-real-hash', 'file': 'x.txt', 'type': 'others'})
        self.assertEqual(resp.status_code, 500)
        self.assertIn('error', self._json(resp))

    # ---- valid request, no device -> legitimate 200 (filesystem) ------

    def test_frida_logs_invalid_hash_200_message(self):
        """frida_logs returns a status/message dict (200) even for a bad
        hash — the wrapper 200 branch keys off resp['message']."""
        resp = self._post('/api/v1/frida/logs', {'hash': 'not-a-real-hash'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn('message', self._json(resp))

    def test_list_frida_scripts_ok_200(self):
        """Listing bundled frida scripts is pure filesystem -> 200 ok."""
        resp = self._post(
            '/api/v1/frida/list_scripts', {'device': 'android'})
        self.assertEqual(resp.status_code, 200)
        body = self._json(resp)
        self.assertEqual(body.get('status'), 'ok')
        self.assertIn('files', body)
        self.assertIsInstance(body['files'], list)

    def test_get_script_content_ok_200(self):
        """Unknown script name -> empty content, status ok, 200."""
        resp = self._post(
            '/api/v1/frida/get_script',
            {'scripts[]': ['does_not_exist'], 'device': 'android'})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self._json(resp).get('status'), 'ok')

    # ---- get_apps: GET entry point, handled gracefully w/o device -----

    def test_get_apps_returns_json(self):
        """GET get_apps runs the analyzer landing view with no device.

        Depending on whether an adb binary is present it either builds a
        context (200) or degrades to an error dict (500); both are real
        reachable branches. Assert we get a well-formed JSON response.
        """
        resp = self._get('/api/v1/dynamic/get_apps')
        self.assertIn(resp.status_code, (200, 500))
        body = self._json(resp)
        self.assertIsInstance(body, dict)
        if resp.status_code == 200:
            self.assertIn('apps', body)
        else:
            self.assertIn('error', body)

    # ---- RBAC denial pass-through branch (real 403, no mocks) ---------

    def _viewer_post(self, path, data=None):
        return self.client.post(
            path,
            data=data or {},
            HTTP_X_MOBINSPECT_API_KEY=self.viewer_key,
        )

    def test_scan_guarded_endpoints_deny_viewer_403(self):
        """A user without scan.* is denied by the real RBAC decorator on
        every SCAN-guarded underlying view; the wrapper must pass that 403
        through untouched (the `_passthrough` branch), not mangle it."""
        cases = [
            ('/api/v1/dynamic/start_analysis', {'hash': 'x'}),
            ('/api/v1/android/logcat', {'package': 'com.example'}),
            ('/api/v1/android/mobinspecty', {'identifier': 'dev'}),
            ('/api/v1/android/adb_command', {'cmd': 'shell pm list packages'}),
            ('/api/v1/android/root_ca', {'action': 'install'}),
            ('/api/v1/android/global_proxy', {'action': 'set'}),
            ('/api/v1/android/activity', {'test': 'exported', 'hash': 'x'}),
            ('/api/v1/android/start_activity',
             {'activity': 'Main', 'hash': 'x'}),
            ('/api/v1/android/tls_tests', {'hash': 'x'}),
            ('/api/v1/dynamic/stop_analysis', {'hash': 'x'}),
            ('/api/v1/frida/instrument', {
                'hash': 'x', 'default_hooks': '',
                'auxiliary_hooks': '', 'frida_code': ''}),
            ('/api/v1/frida/get_dependencies', {'hash': 'x'}),
            # report.view_report is gated by a DIFFERENT real RBAC
            # permission (`scan.view`, checked via RBAC.decorators
            # .require_permission) than the Permissions.SCAN Django-perm
            # used by every other row above. The viewer role here only
            # holds `api.use`, so it lacks `scan.view` too -> real 403.
            ('/api/v1/dynamic/report_json', {'hash': 'x'}),
        ]
        # NOTE (verified by reading source, not guessed): the frida
        # endpoints list_scripts/get_script/logs and the api_monitor
        # endpoint are intentionally ABSENT from `cases` above.
        # `DynamicAnalyzer.views.common.frida.views.list_frida_scripts`,
        # `.get_script_content`, `.frida_logs`, and
        # `DynamicAnalyzer.views.android.tests_frida.live_api` are each
        # decorated with `@login_required` ONLY (no
        # `@permission_required(Permissions.SCAN)` / `@require_permission`
        # gate). `login_required` short-circuits to a direct call whenever
        # `api=True`, so a viewer holding only `api.use` is never denied by
        # these views -- they are real, reachable 200s for any
        # authenticated API caller, not 403s. Asserting 403 for them would
        # be testing behavior the code does not have.
        for path, data in cases:
            with self.subTest(path=path):
                resp = self._viewer_post(path, data)
                self.assertEqual(
                    resp.status_code, 403,
                    msg=f'{path} -> {resp.status_code}: {resp.content!r}')

    def test_get_apps_denies_viewer_403(self):
        """GET entry point is also SCAN-guarded -> 403 for the viewer."""
        resp = self.client.get(
            '/api/v1/dynamic/get_apps',
            HTTP_X_MOBINSPECT_API_KEY=self.viewer_key)
        self.assertEqual(resp.status_code, 403)

    def test_screenshot_denies_viewer_403(self):
        """api_screenshot (unrouted) also passes an RBAC 403 through."""
        request = RequestFactory().post('/screenshot', {'hash': 'x'})
        request.user = AnonymousUser()
        request.api_user = self.viewer
        request.api = True
        request.is_api = True
        resp = api_dz.api_screenshot(request)
        self.assertEqual(resp.status_code, 403)

    # ---- api_logcat: real 'invalid package' dict-error branch ---------

    def test_logcat_invalid_package_name_dict_error_500(self):
        """api=True path: POST['package'] fails strict_package_check.

        ``dynamic_analyzer.logcat`` reads ``request.GET.get('package')``
        first (empty for a plain POST), falls through to
        ``request.POST['package']``, and since ``'bad package name'``
        contains spaces it fails ``strict_package_check`` ->
        ``print_n_send_error_response(request, 'Invalid package name',
        True)`` returns a plain ``{'error': ...}`` dict (no device touched).
        This exercises the wrapper's ``isinstance(lcat, dict)`` /
        ``'error' in lcat`` branch that a device-touching success path
        can never reach in this environment.
        """
        resp = self._post(
            '/api/v1/android/logcat', {'package': 'bad package name'})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(self._json(resp).get('error'), 'Invalid package name')

    # ---- api_adb_execute: real non-device 'ok' branch ------------------

    def test_adb_execute_devices_subcommand_ok_200(self):
        """'devices' is on the adb allowlist and needs no target device.

        ``execute_adb`` always sets ``data = {'status': 'ok', ...}`` after
        the subprocess call completes, regardless of the adb command's own
        exit status/output -- it never inspects the return code. Running
        the real (locally installed) adb binary with the 'devices'
        subcommand is fast, deterministic, and touches no device/network;
        it is the only way to reach this real 'ok' branch without faking
        a device.
        """
        resp = self._post('/api/v1/android/adb_command', {'cmd': 'devices'})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self._json(resp).get('status'), 'ok')

    # ---- api_root_ca: real non-device 'ok' branch ----------------------

    def test_root_ca_install_action_ok_200(self):
        """install_mobinspect_ca() never raises and never checks device
        reachability -- ``Environment.adb_command`` swallows any
        subprocess failure internally and returns None. `mobinspect_ca`
        unconditionally sets ``{'status': 'ok', 'message': 'installed'}``
        after calling it, so this is a real, deterministic, non-device
        success branch.
        """
        resp = self._post('/api/v1/android/root_ca', {'action': 'install'})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self._json(resp).get('status'), 'ok')

    # ---- api_act_tester / api_start_activity: real 'ok' branch ---------
    #
    # activity_tester()/start_activity() call Environment.launch_n_capture,
    # which only performs Environment.adb_command calls (each swallows its
    # own subprocess failure and returns None -- never raises) followed by
    # Environment.screen_shot(), which itself bails out early via
    # is_device_connected() returning False without further adb calls. So
    # with a *real* StaticAnalyzerAndroid row (no device needed), the
    # whole call chain completes without exception -> 'ok'.

    @override_settings(ACTIVITY_TESTER_SLEEP=0)
    def test_act_tester_ok_200(self):
        StaticAnalyzerAndroid.objects.create(
            MD5='6d94299ea98f417af40b53054b86d4de',
            PACKAGE_NAME='com.example.testapp',
            EXPORTED_ACTIVITIES="['com.example.testapp.MainActivity']",
            ACTIVITIES="['com.example.testapp.MainActivity']",
        )
        resp = self._post(
            '/api/v1/android/activity',
            {'test': 'exported', 'hash': '6d94299ea98f417af40b53054b86d4de'})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self._json(resp).get('status'), 'ok')

    @override_settings(ACTIVITY_TESTER_SLEEP=0)
    def test_start_activity_ok_200(self):
        StaticAnalyzerAndroid.objects.create(
            MD5='a4c84d0abe307ee0df1484189aa7d50c',
            PACKAGE_NAME='com.example.testapp',
        )
        resp = self._post(
            '/api/v1/android/start_activity',
            {'activity': 'MainActivity', 'hash': 'a4c84d0abe307ee0df1484189aa7d50c'})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self._json(resp).get('status'), 'ok')

    # ---- api_stop_analysis 'ok' branch: CEILING GAP, not a test --------
    #
    # download_data() alone (called second, after collect_logs) would
    # unconditionally end 'ok' via safe Environment.adb_command() calls.
    # But collect_logs() runs FIRST and calls
    # ``env.adb_command(['logcat', '-d', package + ':V', '*:*'])`` --
    # empirically (verified live against this host's real adb binary and
    # a fake ANALYZER_IDENTIFIER), ``adb -s <fake> logcat -d ...`` BLOCKS
    # indefinitely instead of failing fast (unlike ``adb -s <fake>
    # devices``, which returns immediately). ``Environment.adb_command``
    # sets no subprocess timeout, so this hangs the whole request. There
    # is no safe way to reach api_stop_analysis's 200 branch without a
    # real device on this host; forcing it here would make the suite
    # flaky/hanging. Left uncovered -- see suspected-bug notes.

    # ---- api_get_script_content: real path-traversal 'failed' branch --

    def test_get_script_content_path_traversal_500(self):
        """A `scripts[]` entry escaping the frida_scripts/others directory
        is rejected by the real ``is_safe_path`` check inside
        ``get_script_content`` -- pure filesystem logic, no device.
        """
        resp = self._post(
            '/api/v1/frida/get_script',
            {'scripts[]': ['../../../../etc/passwd'], 'device': 'android'})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(self._json(resp).get('status'), 'failed')

    # ---- api_frida_logs: real 'failed'/500 branch ----------------------

    def test_frida_logs_read_error_500(self):
        """Force frida_logs() into its except-branch (no 'data'/'message'
        key) using a real, deterministic filesystem condition: create a
        *directory* at the exact path frida_logs expects a file, so
        ``Path.read_text()`` raises ``IsADirectoryError`` for real (no
        mocking of any MobInspect logic -- only real on-disk state).
        """
        apphash = 'c6fc87884124ed580c7b9c0df4282538'
        apk_dir = Path(settings.UPLD_DIR) / apphash
        conflict_dir = apk_dir / 'mobinspect_frida_out.txt'
        conflict_dir.mkdir(parents=True, exist_ok=True)
        try:
            resp = self._post('/api/v1/frida/logs', {'hash': apphash})
            self.assertEqual(resp.status_code, 500)
            body = self._json(resp)
            self.assertNotIn('data', body)
            self.assertNotIn('message', body)
        finally:
            conflict_dir.rmdir()

    # ---- api_api_monitor: real 'ok' branch (pure filesystem) -----------

    def test_api_monitor_ok_200_with_real_file(self):
        """live_api()'s stream branch reads a real
        ``mobinspect_api_monitor.txt`` file and returns ``{'data': [...]}``
        when it parses -- pure filesystem, no device. The file format is
        newline-free JSON objects each followed by a trailing comma (the
        real writer's format); the reader strips the final character
        before wrapping in ``[...]``.
        """
        apphash = '93b908a919dd82e7e92c896141038f72'
        apk_dir = Path(settings.UPLD_DIR) / apphash
        apk_dir.mkdir(parents=True, exist_ok=True)
        apimon_file = apk_dir / 'mobinspect_api_monitor.txt'
        apimon_file.write_text('{},', encoding='utf-8')
        try:
            resp = self._post(
                '/api/v1/frida/api_monitor', {'hash': apphash})
            self.assertEqual(resp.status_code, 200)
            self.assertIn('data', self._json(resp))
        finally:
            apimon_file.unlink()

    # ---- api_dynamic_view_file: real 'ok' branch (pure filesystem) -----

    def test_view_file_ok_200(self):
        """device.view_file() with type='others' just reads a real file
        under DYNAMIC_DeviceData and returns a rendering context -- no
        device required.
        """
        apphash = '12d3a269d7c627e6762eccd8c732abe1'
        data_dir = Path(settings.UPLD_DIR) / apphash / 'DYNAMIC_DeviceData'
        data_dir.mkdir(parents=True, exist_ok=True)
        target = data_dir / 'note.txt'
        target.write_text('hello from a real file', encoding='utf-8')
        try:
            resp = self._post(
                '/api/v1/dynamic/view_source',
                {'hash': apphash, 'file': 'note.txt', 'type': 'others'})
            self.assertEqual(resp.status_code, 200)
            self.assertIn('data', self._json(resp))
        finally:
            target.unlink()

    # ---- api_dynamic_report: real 'ok' branch (pure filesystem) --------

    def test_dynamic_report_ok_200(self):
        """view_report() only needs a resolvable package (real
        StaticAnalyzerAndroid row) and a real ``logcat.txt`` marker file
        to skip the "no artifacts yet" branch; every downstream analysis
        helper (droidmon/apimon/dependency/trackers/screenshots) degrades
        to empty results when its own supporting files are absent, so the
        whole real call chain completes -- no device required.
        """
        checksum = 'd55aafef8d9402bcce5f8bfb11ea99e5'
        StaticAnalyzerAndroid.objects.create(
            MD5=checksum,
            PACKAGE_NAME='com.example.testapp',
        )
        app_dir = Path(settings.UPLD_DIR) / checksum
        app_dir.mkdir(parents=True, exist_ok=True)
        logcat_file = app_dir / 'logcat.txt'
        logcat_file.write_text('', encoding='utf-8')
        try:
            resp = self._post(
                '/api/v1/dynamic/report_json', {'hash': checksum})
            self.assertEqual(resp.status_code, 200)
            self.assertNotIn('error', self._json(resp))
        finally:
            logcat_file.unlink()
