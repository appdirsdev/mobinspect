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

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, Client, override_settings

from mobinspect.RBAC.models import ApiKey
from mobinspect.StaticAnalyzer.models import RecentScansDB


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

    # ---- api_pdf_report ----
    def test_pdf_missing_param(self):
        resp = self.post('/api/v1/download_pdf')
        self.assertEqual(resp.status_code, 422)

    def test_pdf_invalid_hash(self):
        resp = self.post('/api/v1/download_pdf', {'hash': NON_MD5})
        self.assertEqual(resp.status_code, 500)

    def test_pdf_report_not_found(self):
        resp = self.post('/api/v1/download_pdf', {'hash': ABSENT_MD5})
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.json()['report'], 'Report not Found')

    # ---- api_json_report ----
    def test_json_missing_param(self):
        resp = self.post('/api/v1/report_json')
        self.assertEqual(resp.status_code, 422)

    def test_json_invalid_hash(self):
        resp = self.post('/api/v1/report_json', {'hash': NON_MD5})
        self.assertEqual(resp.status_code, 500)

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
        # appsec_dashboard returns error 'Invalid Hash' (not the exact
        # 'Invalid scan hash' string), so the api layer falls to 500.
        resp = self.post('/api/v1/scorecard', {'hash': NON_MD5})
        self.assertEqual(resp.status_code, 500)

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

    # ---- suppression endpoints: invalid params -> function returns a
    #      dict without an 'error' key, so the api layer reports 200. ----
    def test_suppress_by_rule_invalid_params_ok(self):
        resp = self.post('/api/v1/suppress_by_rule',
                         {'hash': NON_MD5, 'rule': 'x', 'type': 'code'})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['status'], 'failed')

    def test_suppress_by_files_invalid_params_ok(self):
        resp = self.post('/api/v1/suppress_by_files',
                         {'hash': NON_MD5, 'rule': 'x'})
        self.assertEqual(resp.status_code, 200)

    def test_list_suppressions_invalid_params_ok(self):
        resp = self.post('/api/v1/list_suppressions', {'hash': NON_MD5})
        self.assertEqual(resp.status_code, 200)

    def test_delete_suppression_invalid_params_ok(self):
        resp = self.post('/api/v1/delete_suppression',
                         {'hash': NON_MD5, 'rule': 'x', 'type': 'code'})
        self.assertEqual(resp.status_code, 200)


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
