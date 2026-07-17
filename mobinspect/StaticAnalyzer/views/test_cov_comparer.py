# -*- coding: utf_8 -*-
"""Real-execution unit tests for mobinspect.StaticAnalyzer.views.comparer.

STRICT: no mocks. Real DB rows via the Django ORM, real RequestFactory
requests with a real superuser, and assertions on the real diff context.
"""
from copy import deepcopy

from django.test import TestCase, RequestFactory
from django.contrib.auth.models import User

from mobinspect.StaticAnalyzer.models import StaticAnalyzerAndroid
from mobinspect.StaticAnalyzer.views.comparer import (
    diff_apkid,
    diff_browsable_activities,
    generic_compare,
)


FIRST_HASH = 'a' * 32
SECOND_HASH = 'b' * 32
ERR_HASH_1 = 'c' * 32
ERR_HASH_2 = 'd' * 32


def _first_app_row(md5=FIRST_HASH):
    return {
        'MD5': md5,
        'FILE_NAME': 'first.apk',
        'APP_NAME': 'First',
        'APP_TYPE': 'apk',
        'SIZE': '1 MB',
        'SHA1': '1' * 40,
        'SHA256': '1' * 64,
        'PACKAGE_NAME': 'com.test.first',
        'MAIN_ACTIVITY': '.Main',
        'EXPORTED_ACTIVITIES': '',
        'VERSION_NAME': '1.0',
        'VERSION_CODE': '1',
        'ICON_PATH': 'first/icon.png',
        'ACTIVITIES': str(['.Main', '.First']),
        'SERVICES': str(['.SvcA']),
        'PROVIDERS': str([]),
        'RECEIVERS': str(['.RcvA']),
        'BROWSABLE_ACTIVITIES': str({
            'act.common': {
                'schemes': ['https://', 'custom://'],
                'mime_types': ['text/plain'],
                'hosts': ['a.com'],
                'ports': ['80'],
                'paths': ['/p1'],
                'path_prefixs': ['/pre'],
                'path_patterns': ['.*'],
            },
            'act.first_only': {
                'schemes': ['first://'],
                'mime_types': [],
                'hosts': [],
                'ports': [],
                'paths': [],
                'path_prefixs': [],
                'path_patterns': [],
            },
        }),
        'PERMISSIONS': str({
            'android.permission.INTERNET': {'status': 'dangerous'},
            'android.permission.CAMERA': {'status': 'dangerous'},
        }),
        'ANDROID_API': str({
            'api_call': {'files': {}},
            'api_first': {'files': {}},
        }),
        'CERTIFICATE_ANALYSIS': str({
            'certificate_info':
                'Some header\nSubject: CN=First, O=Test\nTrailer',
        }),
        'URLS': str([
            {'urls': [
                'http://common.example.com',
                'http://firstonly.example.com/' + ('x' * 120),
            ]},
        ]),
        'APKID': str({
            'classes.dex': {
                'compiler': ['r8'],
                'anti_vm': ['Build.MODEL check'],
            },
        }),
        'EXPORTED_COUNT': str({
            'exported_activities': 1,
            'exported_services': 0,
            'exported_receivers': 1,
            'exported_providers': 0,
        }),
    }


def _second_app_row(md5=SECOND_HASH):
    return {
        'MD5': md5,
        'FILE_NAME': 'second.apk',
        'APP_NAME': 'Second',
        'APP_TYPE': 'apk',
        'SIZE': '2 MB',
        'SHA1': '2' * 40,
        'SHA256': '2' * 64,
        'PACKAGE_NAME': 'com.test.second',
        'MAIN_ACTIVITY': '.Main',
        'EXPORTED_ACTIVITIES': '',
        'VERSION_NAME': '2.0',
        'VERSION_CODE': '2',
        'ICON_PATH': '',
        'ACTIVITIES': str(['.Main']),
        'SERVICES': str([]),
        'PROVIDERS': str(['.PrvB']),
        'RECEIVERS': str([]),
        'BROWSABLE_ACTIVITIES': str({
            'act.common': {
                'schemes': ['https://'],
                'mime_types': ['text/plain'],
                'hosts': ['a.com', 'b.com'],
                'ports': ['80'],
                'paths': ['/p1'],
                'path_prefixs': ['/pre'],
                'path_patterns': ['.*'],
            },
            'act.second_only': {
                'schemes': ['second://'],
                'mime_types': [],
                'hosts': [],
                'ports': [],
                'paths': [],
                'path_prefixs': [],
                'path_patterns': [],
            },
        }),
        'PERMISSIONS': str({
            'android.permission.INTERNET': {'status': 'dangerous'},
            'android.permission.ACCESS_FINE_LOCATION': {'status': 'dangerous'},
        }),
        'ANDROID_API': str({
            'api_call': {'files': {}},
            'api_second': {'files': {}},
        }),
        # No 'Subject:' line -> exercises the 'No subject' else branch.
        'CERTIFICATE_ANALYSIS': str({
            'certificate_info': 'No subject present in this certificate info',
        }),
        'URLS': str([
            {'urls': [
                'http://common.example.com',
                'http://secondonly.example.com',
            ]},
        ]),
        'APKID': str({
            'classes.dex': {
                'compiler': ['r8'],
                'packer': ['UPX'],
            },
        }),
        'EXPORTED_COUNT': str({
            'exported_activities': 0,
            'exported_services': 0,
            'exported_receivers': 0,
            'exported_providers': 1,
        }),
    }


class GenericCompareTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_superuser(
            username='cmpadmin', email='c@t.in', password='pass12345')

    def setUp(self):
        self.factory = RequestFactory()

    def _request(self):
        req = self.factory.get('/compare/')
        req.user = self.user
        return req

    def test_compare_context_full_diff(self):
        StaticAnalyzerAndroid.objects.create(**_first_app_row())
        StaticAnalyzerAndroid.objects.create(**_second_app_row())

        ctx = generic_compare(
            self._request(), FIRST_HASH, SECOND_HASH, api=True)

        # It returns the raw context dict when api=True.
        self.assertIsInstance(ctx, dict)
        self.assertEqual(ctx['title'], 'Compare report')

        # Static per-app fields.
        self.assertEqual(ctx['first_app']['name_ver'], 'com.test.first - 1.0')
        self.assertEqual(ctx['second_app']['name_ver'], 'com.test.second - 2.0')
        self.assertEqual(ctx['first_app']['md5'], FIRST_HASH)
        self.assertEqual(ctx['first_app']['file_name'], 'first.apk')
        self.assertEqual(ctx['first_app']['size'], '1 MB')

        # Certificate subject: first matches, second falls to 'No subject'.
        self.assertEqual(
            ctx['first_app']['cert_subject'],
            'Subject: CN=First, O=Test')
        self.assertEqual(ctx['second_app']['cert_subject'], 'No subject')

        # Permissions diff (tuple sections).
        perm_common = [k for k, _ in ctx['permissions']['common']]
        perm_first = [k for k, _ in ctx['permissions']['only_first']]
        perm_second = [k for k, _ in ctx['permissions']['only_second']]
        self.assertIn('android.permission.INTERNET', perm_common)
        self.assertIn('android.permission.CAMERA', perm_first)
        self.assertIn('android.permission.ACCESS_FINE_LOCATION', perm_second)

        # android_api diff.
        api_common = [k for k, _ in ctx['android_api']['common']]
        api_first = [k for k, _ in ctx['android_api']['only_first']]
        api_second = [k for k, _ in ctx['android_api']['only_second']]
        self.assertEqual(api_common, ['api_call'])
        self.assertEqual(api_first, ['api_first'])
        self.assertEqual(api_second, ['api_second'])

        # browsable_activities top-level diff (tuple section).
        ba_common = [k for k, _ in ctx['browsable_activities']['common']]
        ba_first = [k for k, _ in ctx['browsable_activities']['only_first']]
        ba_second = [k for k, _ in ctx['browsable_activities']['only_second']]
        self.assertIn('act.common', ba_common)
        self.assertIn('act.first_only', ba_first)
        self.assertIn('act.second_only', ba_second)

        # Sub-key diffing of the common browsable activity.
        cba = ctx['common_browsable_activities']['act.common']
        self.assertEqual(cba['schemes']['common'], ['https://'])
        self.assertEqual(cba['schemes']['only_first'], ['custom://'])
        self.assertEqual(cba['hosts']['only_second'], ['b.com'])

        # URLs diff (non-tuple section). The long first-only url is escaped
        # and chunked with <br /> every 70 chars, so it is not equal to the
        # common one and lands in only_first.
        self.assertIn('http://common.example.com', ctx['urls']['common'])
        self.assertTrue(any(
            'firstonly' in u for u in ctx['urls']['only_first']))
        self.assertTrue(any('<br />' in u for u in ctx['urls']['only_first']))
        self.assertTrue(any(
            'secondonly' in u for u in ctx['urls']['only_second']))

        # APKID diff.
        self.assertFalse(ctx['apkid_error'])
        self.assertEqual(ctx['apkid']['common']['compiler'], ['r8'])
        self.assertEqual(ctx['apkid']['only_first']['anti_vm'],
                         ['Build.MODEL check'])
        self.assertEqual(ctx['apkid']['only_second']['packer'], ['UPX'])

    def test_missing_app_returns_error(self):
        # Only create the first app; second hash is absent.
        StaticAnalyzerAndroid.objects.create(**_first_app_row())
        resp = generic_compare(
            self._request(), FIRST_HASH, SECOND_HASH, api=True)
        self.assertIsInstance(resp, dict)
        self.assertIn('error', resp)
        self.assertIn('android', resp['error'].lower())

    def test_apkid_error_short_circuits(self):
        row1 = _first_app_row(ERR_HASH_1)
        row2 = _second_app_row(ERR_HASH_2)
        # APKID with an 'error' key must short-circuit diff_apkid.
        row1['APKID'] = str({'error': 'APKID scan failed'})
        StaticAnalyzerAndroid.objects.create(**row1)
        StaticAnalyzerAndroid.objects.create(**row2)

        ctx = generic_compare(
            self._request(), ERR_HASH_1, ERR_HASH_2, api=True)
        self.assertTrue(ctx['apkid_error'])
        # Buckets stay empty because the function returned early.
        self.assertEqual(ctx['apkid']['common'], {})
        self.assertEqual(ctx['apkid']['only_first'], {})
        self.assertEqual(ctx['apkid']['only_second'], {})

    def test_render_path_returns_http_response(self):
        StaticAnalyzerAndroid.objects.create(**_first_app_row())
        StaticAnalyzerAndroid.objects.create(**_second_app_row())
        resp = generic_compare(
            self._request(), FIRST_HASH, SECOND_HASH, api=False)
        # Real template render -> HttpResponse (status 200).
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'com.test.first', resp.content)


class DiffApkidUnitTests(TestCase):
    """Directly drive diff_apkid on hand-built contexts (no DB needed)."""

    def _base_ctx(self, first_apkid, second_apkid):
        return {
            'first_app': {'apkid': deepcopy(first_apkid)},
            'second_app': {'apkid': deepcopy(second_apkid)},
            'apkid': {},
        }

    def test_flatten_across_multiple_dex(self):
        first = {
            'a.dex': {'compiler': ['r8'], 'packer': ['UPX']},
            'b.dex': {'compiler': ['dexguard'], 'anti_vm': ['emu']},
        }
        second = {
            'a.dex': {'compiler': ['r8']},
        }
        ctx = self._base_ctx(first, second)
        diff_apkid(ctx)
        self.assertFalse(ctx['apkid_error'])
        # 'r8' common; 'dexguard' only first.
        self.assertIn('r8', ctx['apkid']['common']['compiler'])
        self.assertIn('dexguard', ctx['apkid']['only_first']['compiler'])
        self.assertIn('UPX', ctx['apkid']['only_first']['packer'])
        self.assertIn('emu', ctx['apkid']['only_first']['anti_vm'])

    def test_error_in_second_sets_flag(self):
        first = {'a.dex': {'compiler': ['r8']}}
        second = {'error': 'boom'}
        ctx = self._base_ctx(first, second)
        diff_apkid(ctx)
        self.assertTrue(ctx['apkid_error'])
        self.assertEqual(ctx['apkid']['common'], {})


class DiffBrowsableActivitiesUnitTests(TestCase):
    """Directly drive diff_browsable_activities (no DB needed)."""

    def test_common_activity_subkey_diff(self):
        context = {
            'browsable_activities': {
                'common': [('act.x', {})],
            },
            'common_browsable_activities': {},
        }
        first_app = {
            'browsable_activities': {
                'act.x': {
                    'schemes': ['s1', 's2'],
                    'mime_types': [],
                    'hosts': ['h1'],
                    'ports': [],
                    'paths': [],
                    'path_prefixs': [],
                    'path_patterns': [],
                },
            },
        }
        second_app = {
            'browsable_activities': {
                'act.x': {
                    'schemes': ['s2'],
                    'mime_types': [],
                    'hosts': ['h1', 'h2'],
                    'ports': [],
                    'paths': [],
                    'path_prefixs': [],
                    'path_patterns': [],
                },
            },
        }
        diff_browsable_activities(context, first_app, second_app)
        cba = context['common_browsable_activities']['act.x']
        self.assertEqual(cba['schemes']['common'], ['s2'])
        self.assertEqual(cba['schemes']['only_first'], ['s1'])
        self.assertEqual(cba['hosts']['common'], ['h1'])
        self.assertEqual(cba['hosts']['only_second'], ['h2'])
