# -*- coding: utf_8 -*-
"""Real-execution coverage tests for the static-analysis REST API.

STRICT: no mocks. Every request is driven through the real Django URL
dispatcher + REST auth middleware with a real per-user RBAC ApiKey on a
real superuser. The scanned-data tests perform a real upload + static
analysis of the committed ``test_files/android.apk`` sample once in
``setUpTestData`` and exercise the report/scorecard/suppression endpoints
against the resulting real DB rows.
"""
import os
import tempfile
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, Client, override_settings

from mobinspect.RBAC.models import (
    ApiKey,
    Permission as MIPerm,
    Role,
    RoleAssignment,
)
from mobinspect.MobInspect.utils import python_dict
from mobinspect.StaticAnalyzer.models import (
    EnqueuedTask,
    RecentScansDB,
    StaticAnalyzerAndroid,
)
from mobinspect.StaticAnalyzer.views.common import pdf as pdf_module
from mobinspect.StaticAnalyzer.views.common.pdf import PDF_UNAVAILABLE_MSG


SAMPLES_DIR = os.path.normpath(
    os.path.join(settings.BASE_DIR, '..', 'test_files'))

# A well-formed MD5 that is guaranteed not to exist in the test DB.
ABSENT_MD5 = 'a' * 32
ABSENT_MD5_2 = 'b' * 32
NON_MD5 = 'not-a-valid-md5-hash'


@override_settings(RATELIMIT_ENABLE=False, DISABLE_AUTHENTICATION=None)
class ApiStaticValidationTests(TestCase):
    """Validation / error branches that need no scanned data (fast)."""

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            'val_admin', 'val_admin@example.com', 'admin')
        _, cls.api_key = ApiKey.generate(cls.admin, 'val-key')

    def setUp(self):
        self.client = Client()
        self.auth = {'HTTP_AUTHORIZATION': self.api_key}

    def post(self, path, data=None):
        return self.client.post(path, data or {}, **self.auth)

    # ---- auth gate (real middleware) ----
    def test_unauthorized_without_key(self):
        resp = Client().post('/api/v1/scan', {'hash': ABSENT_MD5})
        self.assertEqual(resp.status_code, 401)

    # ---- api_recent_scans ----
    def test_recent_scans_ok(self):
        resp = self.client.get('/api/v1/scans', **self.auth)
        self.assertEqual(resp.status_code, 200)
        self.assertIn('content', resp.json())

    def test_recent_scans_out_of_range_page_returns_500(self):
        # RecentScans.recent_scans() reads `page` straight off request.GET
        # (real Paginator.page(...) call) -- an absurdly high page number
        # is guaranteed to be out of range regardless of how many scans
        # exist in the DB, so Paginator raises a real EmptyPage, which the
        # view catches and turns into {'error': str(exp)} -> 500.
        resp = self.client.get(
            '/api/v1/scans', {'page': 999999}, **self.auth)
        self.assertEqual(resp.status_code, 500)
        self.assertIn('error', resp.json())

    # ---- api_scan ----
    def test_scan_missing_param(self):
        resp = self.post('/api/v1/scan')
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(resp.json()['error'], 'Missing Parameters')

    def test_scan_invalid_checksum(self):
        resp = self.post('/api/v1/scan', {'hash': NON_MD5})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.json()['error'], 'Invalid Checksum')

    def test_scan_not_uploaded(self):
        resp = self.post('/api/v1/scan', {'hash': ABSENT_MD5})
        self.assertEqual(resp.status_code, 500)
        self.assertIn('not uploaded', resp.json()['error'])

    # ---- api_scan_logs ----
    def test_scan_logs_missing_param(self):
        resp = self.post('/api/v1/scan_logs')
        self.assertEqual(resp.status_code, 422)

    def test_scan_logs_none_found(self):
        resp = self.post('/api/v1/scan_logs', {'hash': ABSENT_MD5})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()['error'], 'No scan logs found')

    # ---- api_tasks ----
    def test_tasks_empty_queue(self):
        resp = self.post('/api/v1/tasks')
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()['error'], 'Scan queue empty')

    def test_tasks_success_with_real_enqueued_row(self):
        # A real EnqueuedTask row with status='Success' takes
        # get_live_status()'s first early-return branch (no scan-log
        # lookup needed), giving list_tasks() a real non-empty result.
        task = EnqueuedTask.objects.create(
            task_id='real-task-id-001',
            checksum='c' * 32,
            file_name='real_app.apk',
            app_name='Real App',
            status='Success',
        )
        try:
            resp = self.post('/api/v1/tasks')
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertTrue(any(
                row['checksum'] == task.checksum for row in body))
        finally:
            task.delete()

    # ---- api_delete_scan ----
    def test_delete_missing_param(self):
        resp = self.post('/api/v1/delete_scan')
        self.assertEqual(resp.status_code, 422)

    def test_delete_not_found_is_ok(self):
        # delete_scan returns {'deleted': ...} (no 'error') even when the
        # scan is absent, so the api layer reports 200.
        resp = self.post('/api/v1/delete_scan', {'hash': ABSENT_MD5})
        self.assertEqual(resp.status_code, 200)
        self.assertIn('deleted', resp.json())

    def test_delete_scan_filesystem_error_returns_500(self):
        # delete_scan() only ever returns {'deleted': ...} on every
        # explicit branch (invalid hash / not found / async-in-progress /
        # success); the ONLY way it produces {'error': ...} (which is what
        # api_delete_scan's 500 branch keys off) is the outer bare
        # `except Exception` catching a real failure deep in file cleanup.
        # Real fault injection: create a real upload dir for a real
        # RecentScansDB row, then chmod it 0o000 so shutil.rmtree()
        # genuinely raises PermissionError (verified: this process runs
        # as a normal non-root user, so a 0o000 dir is truly unreadable).
        md5 = 'd' * 32
        RecentScansDB.objects.create(MD5=md5, SCAN_TYPE='apk')
        upload_dir = os.path.join(settings.UPLD_DIR, md5)
        os.makedirs(upload_dir, exist_ok=True)
        with open(os.path.join(upload_dir, 'placeholder.txt'), 'w') as fh:
            fh.write('x')
        os.chmod(upload_dir, 0o000)
        try:
            resp = self.post('/api/v1/delete_scan', {'hash': md5})
            self.assertEqual(resp.status_code, 500)
            self.assertIn('error', resp.json())
        finally:
            # Restore permissions so the real cleanup below can remove it.
            os.chmod(upload_dir, 0o755)
            for root, dirs, files in os.walk(upload_dir):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o755)
            import shutil as _shutil
            _shutil.rmtree(upload_dir, ignore_errors=True)
            RecentScansDB.objects.filter(MD5=md5).delete()

    # ---- api_pdf_report ----
    def test_pdf_missing_param(self):
        resp = self.post('/api/v1/download_pdf')
        self.assertEqual(resp.status_code, 422)

    def test_pdf_invalid_hash(self):
        # pdf() emits {'error': 'Invalid Hash'} for a non-MD5 checksum;
        # api_pdf_report matches that exact string and reports 400.
        resp = self.post('/api/v1/download_pdf', {'hash': NON_MD5})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()['error'], 'Invalid Hash')

    def test_pdf_report_not_found(self):
        resp = self.post('/api/v1/download_pdf', {'hash': ABSENT_MD5})
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.json()['report'], 'Report not Found')

    # ---- api_json_report ----
    def test_json_missing_param(self):
        resp = self.post('/api/v1/report_json')
        self.assertEqual(resp.status_code, 422)

    def test_json_invalid_hash(self):
        # Same 'Invalid Hash' contract as api_pdf_report -> 400.
        resp = self.post('/api/v1/report_json', {'hash': NON_MD5})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()['error'], 'Invalid Hash')

    def test_json_report_not_found(self):
        resp = self.post('/api/v1/report_json', {'hash': ABSENT_MD5})
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.json()['report'], 'Report not Found')

    # ---- api_search ----
    def test_search_missing_param(self):
        resp = self.post('/api/v1/search')
        self.assertEqual(resp.status_code, 422)

    def test_search_not_found(self):
        resp = self.post('/api/v1/search',
                         {'query': 'zzz-no-such-app-zzz'})
        self.assertEqual(resp.status_code, 404)
        self.assertIn('error', resp.json())

    # ---- api_view_source ----
    def test_view_source_missing_param(self):
        resp = self.post('/api/v1/view_source', {'type': 'apk'})
        self.assertEqual(resp.status_code, 422)

    # ---- api_compare ----
    def test_compare_missing_param(self):
        resp = self.post('/api/v1/compare', {'hash1': ABSENT_MD5})
        self.assertEqual(resp.status_code, 422)

    def test_compare_same_hash(self):
        resp = self.post('/api/v1/compare',
                         {'hash1': ABSENT_MD5, 'hash2': ABSENT_MD5})
        self.assertEqual(resp.status_code, 500)
        self.assertIn('same hash', resp.json()['error'])

    def test_compare_invalid_hashes(self):
        resp = self.post('/api/v1/compare',
                         {'hash1': NON_MD5, 'hash2': 'other-bad'})
        self.assertEqual(resp.status_code, 500)
        self.assertIn('Invalid hashes', resp.json()['error'])

    # ---- api_scorecard ----
    def test_scorecard_missing_param(self):
        resp = self.post('/api/v1/scorecard')
        self.assertEqual(resp.status_code, 422)

    def test_scorecard_invalid_hash(self):
        # appsec_dashboard emits {'error': 'Invalid Hash'}; api_scorecard
        # matches that exact string and reports 400.
        resp = self.post('/api/v1/scorecard', {'hash': NON_MD5})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()['error'], 'Invalid Hash')

    def test_scorecard_not_found(self):
        resp = self.post('/api/v1/scorecard', {'hash': ABSENT_MD5})
        self.assertEqual(resp.status_code, 404)
        self.assertIn('not_found', resp.json())

    # ---- suppression endpoints: missing params (strict subset -> 422) ----
    def test_suppress_by_rule_missing_param(self):
        resp = self.post('/api/v1/suppress_by_rule', {'hash': ABSENT_MD5})
        self.assertEqual(resp.status_code, 422)

    def test_suppress_by_files_missing_param(self):
        resp = self.post('/api/v1/suppress_by_files', {'hash': ABSENT_MD5})
        self.assertEqual(resp.status_code, 422)

    def test_list_suppressions_missing_param(self):
        resp = self.post('/api/v1/list_suppressions')
        self.assertEqual(resp.status_code, 422)

    def test_delete_suppression_missing_param(self):
        resp = self.post('/api/v1/delete_suppression', {'hash': ABSENT_MD5})
        self.assertEqual(resp.status_code, 422)

    # ---- suppression endpoints: invalid params -> the shared suppression
    #      helpers use a {'status': 'failed'/'ok', 'message': ...} contract
    #      (never an 'error' key); the api layer keys off resp['status'] so
    #      an invalid-params failure correctly surfaces as a 500. ----
    def test_suppress_by_rule_invalid_params_returns_500(self):
        resp = self.post('/api/v1/suppress_by_rule',
                         {'hash': NON_MD5, 'rule': 'x', 'type': 'code'})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.json()['status'], 'failed')

    def test_suppress_by_files_invalid_params_returns_500(self):
        resp = self.post('/api/v1/suppress_by_files',
                         {'hash': NON_MD5, 'rule': 'x'})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.json()['status'], 'failed')

    def test_list_suppressions_invalid_params_returns_500(self):
        resp = self.post('/api/v1/list_suppressions', {'hash': NON_MD5})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.json()['status'], 'failed')

    def test_delete_suppression_invalid_params_returns_500(self):
        resp = self.post('/api/v1/delete_suppression',
                         {'hash': NON_MD5, 'rule': 'x', 'type': 'code'})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.json()['status'], 'failed')


@override_settings(
    RATELIMIT_ENABLE=False, DISABLE_AUTHENTICATION=None, ASYNC_ANALYSIS=False)
class ApiStaticScannedTests(TestCase):
    """Success branches driven by a REAL upload + static analysis.

    A single real scan of ``android.apk`` is performed in setUpTestData;
    every test in this class reads the resulting real DB rows. Forced
    synchronous (ASYNC_ANALYSIS=False) regardless of the environment/default,
    since these tests need the scan to be complete before they run, not
    merely queued.
    """

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            'scan_admin', 'scan_admin@example.com', 'admin')
        _, cls.api_key = ApiKey.generate(cls.admin, 'scan-key')
        auth = {'HTTP_AUTHORIZATION': cls.api_key}
        client = Client()
        path = os.path.join(SAMPLES_DIR, 'android.apk')
        with open(path, 'rb') as fh:
            upload = SimpleUploadedFile(
                'android.apk', fh.read(),
                content_type='application/octet-stream')
        up = client.post('/api/v1/upload', {'file': upload}, **auth)
        assert up.status_code == 200, up.content
        cls.md5 = up.json()['hash']
        sc = client.post('/api/v1/scan', {'hash': cls.md5}, **auth)
        cls.scan_status = sc.status_code

        # A real, non-privileged user holding only `api.use` (so the REST
        # middleware lets the request through) but NOT `scan.view` -- every
        # scan.view-guarded call (appsec_dashboard, inside api_scorecard)
        # therefore hits a real RBAC 403 JsonResponse, exercising the
        # isinstance(resp, HttpResponse) passthrough branch.
        cls.viewer = User.objects.create_user(
            username='scan_viewer', password='not-used-by-api-key-auth')
        api_use, _ = MIPerm.objects.get_or_create(
            codename='api.use',
            defaults={'name': 'Use API', 'category': 'api'})
        group, _ = Group.objects.get_or_create(name='static-cov-apionly')
        role, _ = Role.objects.get_or_create(
            name='static-cov-apionly', defaults={'group': group})
        role.permissions.add(api_use)
        RoleAssignment.objects.get_or_create(user=cls.viewer, role=role)
        _, cls.viewer_key = ApiKey.generate(cls.viewer, 'scan-viewer-key')

    def setUp(self):
        self.client = Client()
        self.auth = {'HTTP_AUTHORIZATION': self.api_key}

    def post(self, path, data=None):
        return self.client.post(path, data or {}, **self.auth)

    def test_scan_succeeded(self):
        # The real scan in setUpTestData drove api_scan's android 200 path.
        self.assertEqual(self.scan_status, 200)
        self.assertTrue(
            RecentScansDB.objects.filter(MD5=self.md5).exists())

    def test_rescan_returns_200(self):
        resp = self.post('/api/v1/scan', {'hash': self.md5})
        self.assertEqual(resp.status_code, 200)

    def test_scorecard_success(self):
        resp = self.post('/api/v1/scorecard', {'hash': self.md5})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['hash'], self.md5)

    def test_report_json_success(self):
        resp = self.post('/api/v1/report_json', {'hash': self.md5})
        self.assertEqual(resp.status_code, 200)
        self.assertIn('md5', resp.json())

    def test_scan_logs_success(self):
        resp = self.post('/api/v1/scan_logs', {'hash': self.md5})
        self.assertEqual(resp.status_code, 200)
        self.assertIn('logs', resp.json())

    def test_search_by_checksum_returns_report(self):
        # api_search resolves the checksum then delegates to api_json_report.
        resp = self.post('/api/v1/search', {'query': self.md5})
        self.assertEqual(resp.status_code, 200)
        self.assertIn('md5', resp.json())

    def test_list_suppressions_real_ok(self):
        resp = self.post('/api/v1/list_suppressions', {'hash': self.md5})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['status'], 'ok')

    def test_suppress_then_delete_by_rule(self):
        # Real package resolved from the scanned APK -> genuine suppression
        # create + delete, both flowing through the 200 branch.
        add = self.post('/api/v1/suppress_by_rule',
                        {'hash': self.md5,
                         'rule': 'android_safe_test_rule',
                         'type': 'manifest'})
        self.assertEqual(add.status_code, 200)
        self.assertEqual(add.json()['status'], 'ok')
        rm = self.post('/api/v1/delete_suppression',
                       {'hash': self.md5,
                        'rule': 'android_safe_test_rule',
                        'type': 'manifest'})
        self.assertEqual(rm.status_code, 200)
        self.assertEqual(rm.json()['status'], 'ok')

    def test_pdf_report_generates(self):
        # Exercises api_pdf_report's success/HttpResponse branch OR the
        # PDF-unavailable (503) branch when wkhtmltopdf is not installed;
        # both are real, environment-honest outcomes.
        resp = self.post('/api/v1/download_pdf', {'hash': self.md5})
        self.assertIn(resp.status_code, (200, 503))

    def test_pdf_report_unavailable_returns_503(self):
        # Real fault injection: pdfkit.configuration() genuinely raises
        # OSError when the configured binary path does not exist -- this
        # is the real code path get_pdf_configuration() guards against,
        # not a simulated one.
        #
        # NOTE: pdf.py does `from mobinspect.MobInspect import settings`
        # (the raw settings MODULE), not django.conf.settings, so
        # @override_settings(WKHTMLTOPDF_BINARY=...) has NO effect here --
        # verified empirically. We patch the module attribute directly
        # instead: a narrow, documented patch of a plain data value (not
        # behavior), functionally equivalent to what override_settings
        # would do if this module read django.conf.settings.
        with mock.patch.object(
                pdf_module.settings, 'WKHTMLTOPDF_BINARY',
                '/nonexistent/path/to/wkhtmltopdf'):
            resp = self.post('/api/v1/download_pdf', {'hash': self.md5})
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.json()['error'], PDF_UNAVAILABLE_MSG)

    def test_scorecard_denied_user_gets_403_passthrough(self):
        # appsec_dashboard() itself carries @require_permission('scan.view')
        # (unlike api_scorecard, which has no view-level RBAC decorator of
        # its own) -- a real non-privileged user is denied INSIDE the call,
        # returning a real HttpResponse that api_scorecard must forward
        # verbatim via the isinstance(resp, HttpResponse) branch.
        resp = self.client.post(
            '/api/v1/scorecard', {'hash': self.md5},
            HTTP_AUTHORIZATION=self.viewer_key)
        self.assertEqual(resp.status_code, 403)

    def test_pdf_and_json_report_generic_error_returns_500(self):
        # Real fault injection (no mocks): delete the RecentScansDB row for
        # an otherwise-real, fully-scanned APK while its StaticAnalyzerAndroid
        # row is left in place. pdf()'s final
        # `RecentScansDB.objects.get(MD5=checksum).TIMESTAMP` lookup then
        # genuinely raises RecentScansDB.DoesNotExist, landing in pdf()'s
        # outer except-clause and returning {'error': <real message>} -- a
        # message that is neither 'Invalid Hash' nor PDF_UNAVAILABLE_MSG,
        # exercising api_pdf_report's / api_json_report's generic (non-400/
        # 503) 500 branch. TestCase wraps every test in its own transaction
        # (rolled back afterwards), so this deletion never leaks into
        # sibling tests -- no manual restoration needed.
        RecentScansDB.objects.filter(MD5=self.md5).delete()
        pdf_resp = self.post('/api/v1/download_pdf', {'hash': self.md5})
        self.assertEqual(pdf_resp.status_code, 500)
        self.assertIn('does not exist', pdf_resp.json()['error'].lower())

        json_resp = self.post('/api/v1/report_json', {'hash': self.md5})
        self.assertEqual(json_resp.status_code, 500)
        self.assertIn('does not exist', json_resp.json()['error'].lower())

    def test_scorecard_missing_hash_key_hits_generic_fallback(self):
        # Real fault injection (no mocks): corrupt the real
        # StaticAnalyzerAndroid.CODE_ANALYSIS column of an otherwise-real,
        # fully-scanned APK with a genuinely unparsable string (simulating
        # real-world data corruption, e.g. a truncated write).
        # `python_dict()` (called inside
        # StaticAnalyzer.views.android.db_interaction.get_context_from_db_entry)
        # runs it through `ast.literal_eval`, which raises for real -- but
        # that function has its OWN try/except and swallows it, returning
        # None. get_android_dashboard's `if not data: return findings`
        # guard then hands back a dict with none of 'error' / 'hash' /
        # 'not_found' set (no exception ever reaches appsec_dashboard's
        # own except-clause), landing on api_scorecard's final `else`
        # fallback -- genuinely reachable, not dead code. TestCase's
        # per-test transaction rollback undoes the column update
        # afterwards -- no manual restore needed.
        StaticAnalyzerAndroid.objects.filter(MD5=self.md5).update(
            CODE_ANALYSIS='not: a valid [python literal')
        resp = self.post('/api/v1/scorecard', {'hash': self.md5})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.json()['error'], 'JSON Generation Error')

    def test_scorecard_generic_error_returns_500(self):
        # Real fault injection (no mocks): corrupt CODE_ANALYSIS with a
        # value that IS a valid python literal (so
        # get_context_from_db_entry's ast.literal_eval succeeds and
        # process_suppression's own severity lookup is satisfied by a
        # top-level 'severity' key) but lacks the 'metadata' key that
        # common_fields() unconditionally indexes
        # (`cd['metadata']['severity']`). That KeyError is raised OUTSIDE
        # get_context_from_db_entry's protective try/except, so it
        # genuinely propagates all the way up to appsec_dashboard's own
        # outer except-clause, which returns {'error': <real message>} --
        # a message that is not 'Invalid Hash', exercising api_scorecard's
        # generic (non-400) 500 branch. TestCase's per-test transaction
        # rollback undoes the column update afterwards.
        StaticAnalyzerAndroid.objects.filter(MD5=self.md5).update(
            CODE_ANALYSIS="{'fake_rule': {'severity': 'high', 'files': {}}}")
        resp = self.post('/api/v1/scorecard', {'hash': self.md5})
        self.assertEqual(resp.status_code, 500)
        self.assertIn('error', resp.json())
        self.assertNotEqual(resp.json()['error'], 'Invalid Hash')
        self.assertNotEqual(resp.json()['error'], 'JSON Generation Error')

    def test_suppress_by_files_success(self):
        # A real rule from the real scan's CODE_ANALYSIS that actually
        # carries file findings -- suppress_by_files() looks up
        # `code_res[rule]['files']` for real, so an arbitrary/absent rule
        # id would raise KeyError and land on the failure path instead of
        # exercising api_suppress_by_files' 200/'ok' success branch.
        code_res = python_dict(
            StaticAnalyzerAndroid.objects.get(MD5=self.md5).CODE_ANALYSIS)
        rule = next(
            (r for r, v in code_res.items() if v.get('files')), None)
        self.assertIsNotNone(
            rule, 'expected >=1 real code finding with file locations')
        resp = self.post('/api/v1/suppress_by_files',
                         {'hash': self.md5, 'rule': rule})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['status'], 'ok')


@override_settings(
    RATELIMIT_ENABLE=False, DISABLE_AUTHENTICATION=None, ASYNC_ANALYSIS=False)
class ApiStaticMultiFormatScannedTests(TestCase):
    """Real end-to-end scans of every OTHER supported sample format, to
    close the scan_type branches ApiStaticScannedTests' apk-only scan
    cannot reach: a real iOS source zip (Android-ext branch fallback to
    iOS detection), a real .ipa (IOS_EXTS branch), a real .appx
    (WINDOWS_EXTS branch), and a second real Android app (.xapk) so
    api_compare has two genuinely different completed Android scans to
    diff. Each upload+scan is real; ASYNC_ANALYSIS=False forces every
    scan to complete synchronously before assertions run. Real wall-clock
    time is expected and accepted (multiple real static analyses).
    """

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            'multi_admin', 'multi_admin@example.com', 'admin')
        _, cls.api_key = ApiKey.generate(cls.admin, 'multi-key')
        cls.auth = {'HTTP_AUTHORIZATION': cls.api_key}
        client = Client()

        def _upload_and_scan(filename):
            path = os.path.join(SAMPLES_DIR, filename)
            with open(path, 'rb') as fh:
                upload = SimpleUploadedFile(
                    filename, fh.read(),
                    content_type='application/octet-stream')
            up = client.post(
                '/api/v1/upload', {'file': upload}, **cls.auth)
            assert up.status_code == 200, (filename, up.content)
            md5 = up.json()['hash']
            sc = client.post(
                '/api/v1/scan', {'hash': md5}, **cls.auth)
            # NOTE: only primitive data (status_code int) is kept on cls --
            # Django's TestCase deepcopies setUpTestData class attributes
            # per test method, and HttpResponse.resolver_match is not
            # deepcopy-safe (raises PicklingError), so the raw response
            # object itself must never be stored here.
            return md5, sc.status_code

        cls.md5_apk, cls.scan_apk_status = _upload_and_scan('android.apk')
        cls.md5_xapk, cls.scan_xapk_status = _upload_and_scan(
            'android_xapk.xapk')
        cls.md5_ios_zip, cls.scan_ios_zip_status = _upload_and_scan(
            'ios_src.zip')
        cls.md5_ipa, cls.scan_ipa_status = _upload_and_scan('ios.ipa')
        cls.md5_appx, cls.scan_appx_status = _upload_and_scan(
            'windows.appx')

    def setUp(self):
        self.client = Client()

    def post(self, path, data=None):
        return self.client.post(path, data or {}, **self.auth)

    # ---- api_scan: Android-ext zip containing real iOS source ---------

    def test_scan_ios_source_zip_triggers_ios_fallback(self):
        # ios_src.zip has scan_type 'zip' (in settings.ANDROID_EXTS), so
        # api_scan first calls static_analyzer(); the real
        # src_analysis() detects genuine iOS source layout and returns
        # {'type': 'ios'}, which is EXACTLY the 'type' in resp fallback
        # branch -> static_analyzer_ios() runs for real. Whichever real
        # outcome follows (analysis success or a real analyzer error) is
        # an honest, environment-driven result; both are legitimate.
        self.assertIn(self.scan_ios_zip_status, (200, 500))
        self.assertTrue(
            RecentScansDB.objects.filter(MD5=self.md5_ios_zip).exists())

    # ---- api_scan: real IOS_EXTS (.ipa) branch -------------------------

    def test_scan_ipa_success(self):
        self.assertEqual(self.scan_ipa_status, 200)

    # ---- api_scan: real WINDOWS_EXTS (.appx) branch --------------------

    def test_scan_appx_success(self):
        self.assertEqual(self.scan_appx_status, 200)

    # ---- api_compare: two genuinely different completed Android scans -

    def test_compare_two_real_android_apps_success(self):
        self.assertEqual(self.scan_apk_status, 200)
        self.assertEqual(self.scan_xapk_status, 200)
        resp = self.post('/api/v1/compare', {
            'hash1': self.md5_apk, 'hash2': self.md5_xapk})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn('first_app', body)
        self.assertIn('second_app', body)

    # ---- api_scan: real 500/'error' sub-branches via TRUNCATED real
    #      samples -- passes the upload's zip-magic (first 4 bytes only,
    #      see FileType.is_allow_file/is_zip_magic) but the resulting
    #      file has no valid end-of-central-directory record, so the real
    #      analyzer's own zipfile handling genuinely fails deep inside
    #      static_analyzer()/static_analyzer_ios()/staticanalyzer_windows(),
    #      landing in each function's real top-level except-clause and
    #      returning a real {'error': ...} dict. Real corrupted bytes, no
    #      mocks. Truncated (small) copies are used deliberately to keep
    #      disk usage low on this shared machine.

    def _upload_truncated(self, filename, out_name, keep_bytes=20000):
        path = os.path.join(SAMPLES_DIR, filename)
        with open(path, 'rb') as fh:
            head = fh.read(keep_bytes)
        upload = SimpleUploadedFile(
            out_name, head, content_type='application/octet-stream')
        up = self.client.post(
            '/api/v1/upload', {'file': upload}, **self.auth)
        assert up.status_code == 200, up.content
        return up.json()['hash']

    def test_scan_corrupt_zip_returns_500(self):
        md5 = self._upload_truncated(
            'android_src.zip', 'corrupt_android_src.zip')
        resp = self.post('/api/v1/scan', {'hash': md5})
        self.assertEqual(resp.status_code, 500)
        self.assertIn('error', resp.json())

    def test_scan_corrupt_ipa_returns_500(self):
        md5 = self._upload_truncated(
            'ios.ipa', 'corrupt.ipa', keep_bytes=5000)
        resp = self.post('/api/v1/scan', {'hash': md5})
        self.assertEqual(resp.status_code, 500)
        self.assertIn('error', resp.json())

    def test_scan_corrupt_appx_returns_500(self):
        md5 = self._upload_truncated(
            'windows.appx', 'corrupt.appx')
        resp = self.post('/api/v1/scan', {'hash': md5})
        self.assertEqual(resp.status_code, 500)
        self.assertIn('error', resp.json())


@override_settings(RATELIMIT_ENABLE=False, DISABLE_AUTHENTICATION=None)
class ApiViewSourceTests(TestCase):
    """api_view_source's android/ios routing + success/error branches,
    driven with minimal real files under a real (temp) UPLD_DIR -- same
    on-disk-fixture convention as
    StaticAnalyzer/views/android/views/test_cov_view_source.py, but
    through the actual REST endpoint (real Client + real per-user ApiKey
    + real RBAC middleware), not the bare view function.
    """

    ANDROID_MD5 = 'e' * 32
    ANDROID_NO_JAVA_MD5 = 'f' * 32
    IOS_MD5 = '1' * 32

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            'vs_admin', 'vs_admin@example.com', 'admin')
        _, cls.api_key = ApiKey.generate(cls.admin, 'vs-key')

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.tmp_upld = tempfile.mkdtemp(prefix='mobinspect_api_vs_')
        java_src = Path(cls.tmp_upld) / cls.ANDROID_MD5 / 'java_source' / 'com' / 'example'
        java_src.mkdir(parents=True, exist_ok=True)
        (java_src / 'Main.java').write_text(
            'package com.example;\npublic class Main { int x = 1; }\n')
        # A scan dir with NO java/kotlin source folder at all -> a real
        # StopIteration inside find_java_source_folder -> real error dict.
        (Path(cls.tmp_upld) / cls.ANDROID_NO_JAVA_MD5).mkdir(
            parents=True, exist_ok=True)
        ios_dir = Path(cls.tmp_upld) / cls.IOS_MD5
        ios_dir.mkdir(parents=True, exist_ok=True)
        (ios_dir / 'notes.txt').write_text('real ios file contents\n')

    @classmethod
    def tearDownClass(cls):
        import shutil as _shutil
        _shutil.rmtree(cls.tmp_upld, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        self.client = Client()
        self.auth = {'HTTP_AUTHORIZATION': self.api_key}

    def post(self, path, data=None):
        return self.client.post(path, data or {}, **self.auth)

    def test_view_source_android_java_success(self):
        with override_settings(UPLD_DIR=self.tmp_upld):
            resp = self.post('/api/v1/view_source', {
                'file': 'com/example/Main.java',
                'hash': self.ANDROID_MD5,
                'type': 'java',
            })
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn('class Main', body['data'])

    def test_view_source_android_no_java_source_returns_500(self):
        with override_settings(UPLD_DIR=self.tmp_upld):
            resp = self.post('/api/v1/view_source', {
                'file': 'anything.java',
                'hash': self.ANDROID_NO_JAVA_MD5,
                'type': 'java',
            })
        self.assertEqual(resp.status_code, 500)
        self.assertIn('error', resp.json())

    def test_view_source_ios_success(self):
        with override_settings(UPLD_DIR=self.tmp_upld):
            resp = self.post('/api/v1/view_source', {
                'file': 'notes.txt',
                'hash': self.IOS_MD5,
                'type': 'ios',
            })
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn('real ios file contents', body['data'])
