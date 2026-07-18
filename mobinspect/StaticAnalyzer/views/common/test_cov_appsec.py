# -*- coding: utf_8 -*-
"""Real-execution coverage tests for common/appsec.py.

Strategy: appsec.py is a pure data-transformation + dashboard-rendering
module shared by Android and iOS. Most branches are exercised with
``from_ctx=True`` and realistic, fully-shaped context dicts (mirroring the
shape ``get_context_from_db_entry`` produces) passed straight into the real
functions -- the same crafted-dict convention already used by sibling tests
such as ``ios/test_cov_ipa.py::GetScanSubjectTests``. The DB-integration
paths (appsec_dashboard: not-found / render / exception) use a real
StaticAnalyzerIOS row created via the ORM and a real admin RequestFactory
request, matching ``ios/test_cov_ipa.py`` conventions.
"""
import os

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import (
    Client,
    RequestFactory,
    SimpleTestCase,
    TestCase,
    override_settings,
)

from mobinspect.RBAC.models import ApiKey
from mobinspect.StaticAnalyzer.models import StaticAnalyzerAndroid, StaticAnalyzerIOS
from mobinspect.StaticAnalyzer.views.common.appsec import (
    appsec_dashboard,
    common_fields,
    get_android_dashboard,
    get_ios_dashboard,
)


SAMPLES_DIR = os.path.normpath(
    os.path.join(settings.BASE_DIR, '..', 'test_files'))


def _base_data(**overrides):
    """A fully-shaped context dict, same keys get_context_from_db_entry sets."""
    d = {
        'code_analysis': {'findings': {}},
        'permissions': {},
        'file_analysis': [],
        'domains': {},
        'firebase_urls': [],
        'trackers': {},
        'secrets': [],
        'md5': 'a' * 32,
        'app_name': 'App',
        'file_name': 'app.ipa',
        'macho_analysis': {},
    }
    d.update(overrides)
    return d


class CommonFieldsTests(SimpleTestCase):
    """Direct real-function calls covering common_fields() branches."""

    def test_dangerous_permission_uses_reason_fallback(self):
        # meta.get('info') falsy -> falls back to meta.get('reason') (line 76).
        findings = {'high': [], 'warning': [], 'info': [], 'secure': [],
                    'hotspot': []}
        data = _base_data(permissions={
            'android.permission.CAMERA': {
                'status': 'dangerous',
                'description': 'Camera access',
                'info': None,
                'reason': 'Needed to fall back on',
            },
        })
        common_fields(findings, data)
        self.assertEqual(len(findings['hotspot']), 1)
        self.assertIn('Needed to fall back on', findings['hotspot'][0]['description'])

    def test_cert_file_via_finding_key(self):
        # file_analysis entry (dict) with 'Cert' in 'finding' -> cfp/break
        # (lines 100-101).
        findings = {'high': [], 'warning': [], 'info': [], 'secure': [],
                    'hotspot': []}
        data = _base_data(file_analysis=[
            {'finding': 'Found hardcoded Cert file', 'files': ['res/a.cer']},
        ])
        common_fields(findings, data)
        self.assertEqual(len(findings['hotspot']), 1)
        self.assertIn('certificate/key file', findings['hotspot'][0]['title'])

    def test_malicious_domain_and_ofac_all_geolocation_branches(self):
        # bad == 'yes' -> high finding (line 125).
        # ofac True with 3 different geolocation shapes hits every branch
        # of the country_long/region/city elif chain (lines 131-138).
        findings = {'high': [], 'warning': [], 'info': [], 'secure': [],
                    'hotspot': []}
        data = _base_data(domains={
            'evil1.example': {
                'bad': 'yes', 'ofac': True,
                'geolocation': {'country_long': 'Iran'},
            },
            'evil2.example': {
                'bad': 'no', 'ofac': True,
                'geolocation': {'region': 'Some Region'},
            },
            'evil3.example': {
                'bad': 'no', 'ofac': True,
                'geolocation': {'city': 'Some City'},
            },
        })
        common_fields(findings, data)
        self.assertEqual(len(findings['high']), 1)
        self.assertIn('Malicious domain found', findings['high'][0]['title'])
        self.assertEqual(len(findings['hotspot']), 3)
        countries = {h['title'] for h in findings['hotspot']}
        self.assertTrue(any('Iran' in c for c in countries))
        self.assertTrue(any('Some Region' in c for c in countries))
        self.assertTrue(any('Some City' in c for c in countries))

    def test_firebase_urls_appended(self):
        # firebase_urls loop appends a finding (line 147).
        findings = {'high': [], 'warning': [], 'info': [], 'secure': [],
                    'hotspot': []}
        data = _base_data(firebase_urls=[
            {'severity': 'info', 'title': 'Firebase URL found',
             'description': 'https://x.firebaseio.com'},
        ])
        common_fields(findings, data)
        self.assertEqual(len(findings['info']), 1)
        self.assertEqual(findings['info'][0]['section'], 'firebase')

    def test_trackers_high_count(self):
        # t > 4 -> 'high' (EFR_01 default off) (lines 158-159).
        findings = {'high': [], 'warning': [], 'info': [], 'secure': [],
                    'hotspot': []}
        data = _base_data(trackers={
            'trackers': ['t1', 't2', 't3', 't4', 't5'],
            'total_trackers': 5,
        })
        common_fields(findings, data)
        self.assertEqual(findings['trackers'], 5)
        self.assertEqual(len(findings['high']), 1)

    def test_trackers_low_count(self):
        # 0 < t <= 4 -> 'warning' (EFR_01 default off) (lines 168-169).
        findings = {'high': [], 'warning': [], 'info': [], 'secure': [],
                    'hotspot': []}
        data = _base_data(trackers={
            'trackers': ['t1'],
            'total_trackers': 1,
        })
        common_fields(findings, data)
        self.assertEqual(findings['trackers'], 1)
        self.assertEqual(len(findings['warning']), 1)


class GetAndroidDashboardTests(SimpleTestCase):

    def test_from_ctx_none_data_early_return(self):
        # adb(context) returning falsy (empty queryset) -> early
        # `return findings` (line 230).
        findings = get_android_dashboard(
            StaticAnalyzerAndroid.objects.none(), from_ctx=False)
        self.assertEqual(findings['high'], [])
        self.assertIsNone(findings['total_trackers'])

    def test_network_security_and_manifest_branches(self):
        data = _base_data(
            network_security={'network_findings': [
                {'severity': 'warning', 'scope': ['a.com', 'b.com'],
                 'description': 'Cleartext traffic allowed. Fix it now.'},
                {'severity': 'info', 'scope': ['c.com'],
                 'description': 'No period here'},
            ]},
            manifest_analysis={'manifest_findings': [
                {'severity': 'info', 'title': 'Skip me', 'description': 'x'},
                {'severity': 'warning',
                 'title': '<strong>Bad</strong> exported<br>more detail',
                 'description': 'full desc'},
            ]},
            version_name='1.2.3',
        )
        findings = get_android_dashboard(data, from_ctx=True)
        # network: one finding with '.' split (title_parts>1), one without.
        net_titles = [f['title'] for f in findings['warning'] + findings['info']
                      if f['section'] == 'network']
        self.assertTrue(any('Cleartext traffic allowed' == t for t in net_titles))
        self.assertTrue(any('No period here' == t for t in net_titles))
        manifest_titles = [f['title'] for f in findings['warning']
                           if f['section'] == 'manifest']
        self.assertIn('Bad exported', manifest_titles)
        self.assertEqual(findings['version_name'], '1.2.3')


class GetIosDashboardTests(SimpleTestCase):

    def test_from_ctx_none_data_early_return(self):
        # idb(context) returning falsy (empty queryset) -> early
        # `return findings` (line 297).
        findings = get_ios_dashboard(
            StaticAnalyzerIOS.objects.none(), from_ctx=False)
        self.assertEqual(findings['high'], [])

    def test_binary_analysis_good_severity_branch(self):
        # cd['severity'] == 'good' -> sev = 'secure' (line 312).
        data = _base_data(
            binary_analysis={'findings': {
                'NSAllowsArbitraryLoads': {
                    'severity': 'good', 'detailed_desc': 'Not present',
                },
            }},
        )
        findings = get_ios_dashboard(data, from_ctx=True)
        secure_titles = [f['title'] for f in findings['secure']]
        self.assertIn('NSAllowsArbitraryLoads', secure_titles)

    def test_binary_analysis_non_good_severity_passthrough(self):
        # cd['severity'] != 'good' -> sev = cd['severity'] as-is (line 314).
        data = _base_data(
            binary_analysis={'findings': {
                'NSAllowsArbitraryLoadsInWebContent': {
                    'severity': 'warning', 'detailed_desc': 'Present',
                },
            }},
        )
        findings = get_ios_dashboard(data, from_ctx=True)
        warning_titles = [f['title'] for f in findings['warning']]
        self.assertIn('NSAllowsArbitraryLoadsInWebContent', warning_titles)

    def test_macho_analysis_high_warning_branches(self):
        # nx/pie/arc/rpath all in {'high','warning'} (lines 325,332,350,357).
        data = _base_data(
            macho_analysis={
                'nx': {'severity': 'high', 'description': 'no nx'},
                'pie': {'severity': 'warning', 'description': 'no pie'},
                'stack_canary': {'severity': 'good', 'description': 'ok'},
                'arc': {'severity': 'high', 'description': 'no arc'},
                'rpath': {'severity': 'warning', 'description': 'rpath set'},
                'symbol': {'severity': 'good', 'description': 'stripped'},
            },
        )
        findings = get_ios_dashboard(data, from_ctx=True)
        macho_findings = (findings['high'] + findings['warning'])
        macho_titles = {f['title'] for f in macho_findings
                        if f['section'] == 'macho'}
        self.assertIn('NX bit is not set properly for this application',
                      macho_titles)
        self.assertIn('PIE flag is not configured securely'
                      ' for this application binary', macho_titles)
        self.assertIn(
            'Application binary is not compiled with ARC flag', macho_titles)
        self.assertIn('Application binary has rpath set', macho_titles)


@override_settings(DISABLE_AUTHENTICATION=None)
class AppsecDashboardViewTests(TestCase):
    """DB + HTTP-layer branches of appsec_dashboard()."""

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            'appsec_admin', 'appsec_admin@example.com', 'admin')

    def _admin_request(self):
        rf = RequestFactory()
        request = rf.get('/')
        request.user = self.admin
        request.api_user = self.admin
        return request

    def test_not_found_api_false_error_render(self):
        # Valid-format md5 with no matching row, api=False ->
        # print_n_send_error_response -> render(..., status=500)
        # (lines 398-399).
        resp = appsec_dashboard(self._admin_request(), 'f' * 32, api=False)
        self.assertEqual(resp.status_code, 500)

    def test_invalid_hash_format_api_false_error_render(self):
        # is_md5(checksum) is False (bad format, not just "not found") ->
        # the early print_n_send_error_response('Invalid Hash', ...) call
        # (line 382), api=False -> real error template, status 500.
        resp = appsec_dashboard(self._admin_request(), 'not-a-valid-md5', api=False)
        self.assertEqual(resp.status_code, 500)

    def test_render_success_and_exception_branch(self):
        # A real StaticAnalyzerIOS row whose MACHO_ANALYSIS is missing
        # required nested keys ('pie' et al) triggers a genuine KeyError
        # inside get_ios_dashboard, propagating up to appsec_dashboard's
        # own except block (lines 442-449) -- no monkeypatching involved,
        # a real malformed-but-legally-stored DB row.
        checksum = '9' * 32
        StaticAnalyzerIOS.objects.create(
            MD5=checksum,
            FILE_NAME='broken.ipa',
            APP_NAME='Broken',
            MACHO_ANALYSIS={'nx': {'severity': 'good', 'description': 'ok'}},
        )
        resp = appsec_dashboard(self._admin_request(), checksum, api=True)
        self.assertIsInstance(resp, dict)
        self.assertIn('error', resp)

    def test_exception_branch_api_false_error_render(self):
        # Same malformed-macho fault, api=False -> print_n_send_error_response
        # renders the real error template (line 449).
        checksum = '8' * 32
        StaticAnalyzerIOS.objects.create(
            MD5=checksum,
            FILE_NAME='broken2.ipa',
            APP_NAME='Broken2',
            MACHO_ANALYSIS={'nx': {'severity': 'good', 'description': 'ok'}},
        )
        resp = appsec_dashboard(self._admin_request(), checksum, api=False)
        self.assertEqual(resp.status_code, 500)

    def test_render_success_html(self):
        # Real ios.ipa scan -> appsec_dashboard renders the real
        # template end-to-end (api=False, line 438).
        User = get_user_model()
        admin2 = User.objects.create_superuser(
            'appsec_admin2', 'appsec_admin2@example.com', 'admin')
        _, api_key = ApiKey.generate(admin2, 'appsec-key')
        client = Client()
        path = os.path.join(SAMPLES_DIR, 'ios.ipa')
        with open(path, 'rb') as fh:
            upload = SimpleUploadedFile(
                'ios.ipa', fh.read(), content_type='application/octet-stream')
        with override_settings(ASYNC_ANALYSIS=False, RATELIMIT_ENABLE=False):
            up = client.post('/api/v1/upload', {'file': upload},
                             HTTP_AUTHORIZATION=api_key)
            assert up.status_code == 200, up.content
            md5 = up.json()['hash']
            sc = client.post('/api/v1/scan', {'hash': md5},
                             HTTP_AUTHORIZATION=api_key)
            assert sc.status_code == 200, sc.content
        rf = RequestFactory()
        request = rf.get('/')
        request.user = admin2
        request.api_user = admin2
        resp = appsec_dashboard(request, md5, api=False)
        self.assertEqual(resp.status_code, 200)
