# -*- coding: utf_8 -*-
"""Real-execution unit tests for mobsf.StaticAnalyzer.views.windows.windows.

STRICT: no mocks. A real windows.appx is uploaded to the real UPLD_DIR via
the production `handle_uploaded_file`/`add_to_recent_scan` helpers, then a real
static scan is driven through `staticanalyzer_windows`. Pure parsers
(parse_binskim*, get_short_desc) are exercised with real crafted dict inputs.

Binskim/Binscope local execution and the Windows-VM xmlrpc path require a
configured Windows host/VM and are intentionally left as a ceiling-gap.
"""
import os
import tempfile

from lxml import etree

from django.conf import settings
from django.test import TestCase, RequestFactory
from django.contrib.auth.models import User

from mobsf.MobSF.views.scanning import (
    add_to_recent_scan,
    handle_uploaded_file,
)
from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerWindows,
)
from mobsf.StaticAnalyzer.views.windows.windows import (
    _parse_xml,
    get_short_desc,
    parse_binskim,
    parse_binskim_old,
    parse_binskim_sarif,
    parse_xml_metadata,
    staticanalyzer_windows,
)


REPO_ROOT = settings.BASE_DIR.parent if hasattr(
    settings.BASE_DIR, 'parent') else os.path.dirname(settings.BASE_DIR)
APPX = os.path.join(str(REPO_ROOT), 'test_files', 'windows.appx')


def _upload_appx():
    """Upload the real appx via the production helper. Returns md5."""
    with open(APPX, 'rb') as handle:
        md5 = handle_uploaded_file(handle, '.appx')
    add_to_recent_scan({
        'analyzer': 'static_analyzer_windows',
        'status': 'success',
        'hash': md5,
        'scan_type': 'appx',
        'file_name': 'windows.appx',
    })
    return md5


class WindowsRealScanTests(TestCase):
    """Drive a real APPX static scan end to end."""

    @classmethod
    def setUpTestData(cls):
        cls.admin = User.objects.create_superuser(
            username='winadmin', email='w@t.in', password='pass12345')
        cls.md5 = _upload_appx()

    def setUp(self):
        self.factory = RequestFactory()

    def _req(self, method='get', data=None):
        if method == 'post':
            req = self.factory.post('/scan/', data or {})
        else:
            req = self.factory.get('/scan/', data or {})
        req.user = self.admin
        return req

    def test_fresh_scan_api_builds_report_and_db(self):
        ctx = staticanalyzer_windows(self._req(), self.md5, api=True)
        self.assertIsInstance(ctx, dict)
        self.assertEqual(ctx['title'], 'Static Analysis')
        self.assertEqual(ctx['md5'], self.md5)
        self.assertEqual(ctx['file_name'], 'windows.appx')
        # sha256 was computed for real.
        self.assertEqual(len(ctx['sha256']), 64)
        # Files were unzipped from the appx.
        self.assertTrue(len(ctx['files']) > 0)
        # VM not configured -> the VM info warning is present in results.
        self.assertTrue(any(
            r.get('rule_id') == 'VM' for r in ctx['binary_analysis']))
        # The scan persisted a StaticAnalyzerWindows row.
        self.assertTrue(
            StaticAnalyzerWindows.objects.filter(MD5=self.md5).exists())
        self.assertIsNone(ctx['virus_total'])

    def test_cached_db_path_api(self):
        # First scan populates the DB.
        staticanalyzer_windows(self._req(), self.md5, api=True)
        # Second call (no rescan) must read from the DB entry.
        ctx = staticanalyzer_windows(self._req(), self.md5, api=True)
        self.assertIsInstance(ctx, dict)
        self.assertEqual(ctx['md5'], self.md5)
        self.assertEqual(ctx['file_name'], 'windows.appx')
        self.assertIn('logs', ctx)

    def test_rescan_api_updates_db(self):
        staticanalyzer_windows(self._req(), self.md5, api=True)
        ctx = staticanalyzer_windows(
            self._req(method='post', data={'re_scan': '1'}),
            self.md5, api=True)
        self.assertIsInstance(ctx, dict)
        self.assertEqual(ctx['md5'], self.md5)
        self.assertTrue(
            StaticAnalyzerWindows.objects.filter(MD5=self.md5).exists())

    def test_render_path_non_api(self):
        # Populate DB first, then render the HTML template (api=False).
        staticanalyzer_windows(self._req(), self.md5, api=True)
        resp = staticanalyzer_windows(self._req(), self.md5, api=False)
        self.assertEqual(resp.status_code, 200)

    def test_invalid_hash(self):
        resp = staticanalyzer_windows(self._req(), 'not-an-md5', api=True)
        # api error response is a plain dict {'error': msg}.
        self.assertEqual(resp['error'], 'Invalid Hash')

    def test_not_uploaded(self):
        resp = staticanalyzer_windows(self._req(), 'a' * 32, api=True)
        self.assertIn('not uploaded', resp['error'])

    def test_unsupported_file_type(self):
        md5 = 'b' * 32
        RecentScansDB.objects.create(
            MD5=md5, SCAN_TYPE='apk', FILE_NAME='x.apk',
            ANALYZER='static_analyzer')
        resp = staticanalyzer_windows(self._req(), md5, api=True)
        self.assertIn('not supported', resp['error'])

    def test_permission_denied(self):
        # A non-staff user without the scan permission drives the else
        # branch (fresh scan) and is denied.
        viewer = User.objects.create_user(
            username='winviewer', password='pass12345')
        md5 = _upload_appx()
        # Ensure no cached analysis exists for a clean else-branch.
        StaticAnalyzerWindows.objects.filter(MD5=md5).delete()
        req = self.factory.get('/scan/')
        req.user = viewer
        # Permission denial hardcodes api=False -> HTML 500 response.
        resp = staticanalyzer_windows(req, md5, api=True)
        self.assertEqual(resp.status_code, 500)
        self.assertIn(b'Permission Denied', resp.content)

    def test_exception_branch_missing_file(self):
        # RecentScansDB says appx but no file on disk -> file_size raises,
        # caught by the outer handler which returns an error response.
        md5 = 'c' * 32
        RecentScansDB.objects.create(
            MD5=md5, SCAN_TYPE='appx', FILE_NAME='ghost.appx',
            ANALYZER='static_analyzer_windows')
        resp = staticanalyzer_windows(self._req(), md5, api=True)
        # api=True -> dict carrying the repr() of the raised exception.
        self.assertIn('error', resp)


class BinskimParserUnitTests(TestCase):
    """Pure parser functions with real crafted SARIF/old dict inputs."""

    def test_get_short_desc(self):
        rules = [{'id': 'BA2001', 'shortDescription': {'text': 'desc-1'}}]
        self.assertEqual(get_short_desc(rules, 'BA2001'), 'desc-1')
        self.assertIsNone(get_short_desc(rules, 'MISSING'))

    def test_parse_binskim_routes_to_old(self):
        # Presence of runs[0]['rules'] routes to the old parser.
        output = {
            'runs': [{
                'rules': {
                    'BA2001': {'shortDescription': 'Old desc'},
                },
                'results': [
                    {'level': 'pass', 'ruleId': 'BA2001'},
                    {'level': 'error', 'ruleId': 'BA2001',
                     'formattedRuleMessage': {
                         'arguments': ['a', 'b', 'c', 'd']}},
                ],
                'configurationNotifications': [
                    {'ruleId': 'CFG1', 'message': 'config note'},
                ],
            }],
        }
        bad = {'results': [], 'warnings': []}
        out = parse_binskim(bad, output)
        statuses = {r['status'] for r in out['results']}
        self.assertIn('Secure', statuses)
        self.assertIn('Insecure', statuses)
        # Insecure entry carries the joined info from >2 arguments.
        insecure = [r for r in out['results'] if r['status'] == 'Insecure'][0]
        self.assertEqual(insecure['info'], 'b, c')
        self.assertEqual(len(out['warnings']), 1)
        self.assertEqual(out['warnings'][0]['rule_id'], 'CFG1')

    def test_parse_binskim_old_no_results_warns(self):
        output = {'runs': [{'rules': {}}]}
        out = parse_binskim_old(
            {'results': [], 'warnings': []}, output)
        self.assertEqual(out['warnings'][0]['rule_id'], 'No Binskim-Results')

    def test_parse_binskim_old_short_args(self):
        output = {
            'runs': [{
                'rules': {'R1': {'shortDescription': 'd'}},
                'results': [
                    {'level': 'error', 'ruleId': 'R1',
                     'formattedRuleMessage': {'arguments': ['only']}},
                ],
            }],
        }
        out = parse_binskim_old({'results': [], 'warnings': []}, output)
        self.assertEqual(out['results'][0]['info'], '')

    def test_parse_binskim_routes_to_sarif(self):
        # No runs[0]['rules'] -> KeyError -> sarif parser.
        output = {
            'runs': [{
                'tool': {'driver': {'rules': [
                    {'id': 'BA2002',
                     'shortDescription': {'text': 'Sarif desc'}},
                ]}},
                'results': [
                    {'level': 'pass', 'ruleId': 'BA2002',
                     'message': {'arguments': []}},
                    {'level': 'error', 'ruleId': 'BA2002',
                     'message': {'arguments': ['x', 'y', 'z', 'w']}},
                ],
            }],
        }
        out = parse_binskim({'results': [], 'warnings': []}, output)
        statuses = {r['status'] for r in out['results']}
        self.assertIn('Secure', statuses)
        self.assertIn('Insecure', statuses)
        insecure = [r for r in out['results'] if r['status'] == 'Insecure'][0]
        self.assertEqual(insecure['info'], 'y, z')
        self.assertEqual(insecure['desc'], 'Sarif desc')

    def test_parse_binskim_sarif_no_results_warns(self):
        output = {
            'runs': [{
                'tool': {'driver': {'rules': []}},
            }],
        }
        out = parse_binskim_sarif({'results': [], 'warnings': []}, output)
        self.assertEqual(out['warnings'][0]['rule_id'], 'No Binskim-Results')

    def test_parse_binskim_sarif_short_args(self):
        output = {
            'runs': [{
                'tool': {'driver': {'rules': [
                    {'id': 'R2', 'shortDescription': {'text': 'd2'}}]}},
                'results': [
                    {'level': 'error', 'ruleId': 'R2',
                     'message': {'arguments': ['one']}},
                ],
            }],
        }
        out = parse_binskim_sarif({'results': [], 'warnings': []}, output)
        self.assertEqual(out['results'][0]['info'], '')


class XmlParserUnitTests(TestCase):
    """Real lxml-driven manifest parsing."""

    def test_parse_xml_metadata_all_names(self):
        xml = etree.fromstring(
            b'<Metadata>'
            b'<Item Name="cl.exe" Version="19.0"/>'
            b'<Item Name="VisualStudio" Version="17.0"/>'
            b'<Item Name="VisualStudioEdition" Value="Community"/>'
            b'<Item Name="OperatingSystem" Version="10.0"/>'
            b'<Item Name="Microsoft.Build.AppxPackage.dll" Version="1.2"/>'
            b'<Item Name="ProjectGUID" Value="{GUID}"/>'
            b'<Item Name="OptimizingToolset" Value="LTCG"/>'
            b'<Item Name="TargetRuntime" Value="Native"/>'
            b'</Metadata>')
        xml_dic = {
            'compiler_version': '', 'visual_studio_version': '',
            'visual_studio_edition': '', 'target_os': '',
            'appx_dll_version': '', 'proj_guid': '',
            'opti_tool': '', 'target_run': '',
        }
        out = parse_xml_metadata(xml_dic, xml)
        self.assertEqual(out['compiler_version'], '19.0')
        self.assertEqual(out['visual_studio_version'], '17.0')
        self.assertEqual(out['visual_studio_edition'], 'Community')
        self.assertEqual(out['target_os'], '10.0')
        self.assertEqual(out['appx_dll_version'], '1.2')
        self.assertEqual(out['proj_guid'], '{GUID}')
        self.assertEqual(out['opti_tool'], 'LTCG')
        self.assertEqual(out['target_run'], 'Native')

    def test_parse_xml_malformed_manifest_handled(self):
        # A malformed AppxManifest.xml drives the exception handler; the
        # function still returns the default (empty) dict without raising.
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'AppxManifest.xml'), 'wb') as fh:
                fh.write(b'<not-valid-xml <<<')
            out = _parse_xml('e' * 32, tmp)
        self.assertEqual(out['version'], '')
        self.assertEqual(out['app_name'], '')
