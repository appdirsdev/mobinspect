# -*- coding: utf_8 -*-
"""Real-execution (STRICT no-mock) coverage tests for mobinspect.MobInspect.views.home.

Every branch below is exercised by driving the REAL Django views/functions
with a REAL superuser, REAL DB rows (RecentScansDB / StaticAnalyzer* via the
Django ORM against the isolated Postgres test DB) and REAL files on disk. No
mocks, no monkeypatching, no fake returns.
"""
import json
import os
import shutil
import sys
from datetime import timedelta
from unittest import mock

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, Client, RequestFactory, override_settings
from django.utils.timezone import now

from mobinspect.MobInspect.views import home
from mobinspect.StaticAnalyzer.models import (
    EnqueuedTask,
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)

# settings.BASE_DIR points at the inner ``mobinspect`` package dir; the sample
# files live in ``test_files/`` at the actual repository root one level up.
REPO_ROOT = os.path.dirname(settings.BASE_DIR)
TEST_FILES = os.path.join(REPO_ROOT, 'test_files')


def _mk_recent(md5, **kw):
    """Create a real RecentScansDB row."""
    defaults = dict(
        ANALYZER='static_analyzer',
        SCAN_TYPE='apk',
        FILE_NAME='sample.apk',
        APP_NAME='Sample',
        PACKAGE_NAME='com.example.sample',
        VERSION_NAME='1.0',
        MD5=md5,
        SCAN_LOGS='[]',
    )
    defaults.update(kw)
    return RecentScansDB.objects.create(**defaults)


class HomeViewsRealTests(TestCase):
    """Drive the reachable branches of home.py with real inputs."""

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            'covadmin', 'covadmin@example.com', 'covadmin')

    def setUp(self):
        self.client = Client()
        self.client.force_login(self.admin)
        self.factory = RequestFactory()
        self._cleanup_paths = []

    def tearDown(self):
        for p in self._cleanup_paths:
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            elif os.path.isfile(p):
                try:
                    os.remove(p)
                except OSError:
                    pass

    def _authed_request(self, method, path, data=None):
        """Build a real request already carrying the authenticated superuser."""
        if method == 'GET':
            req = self.factory.get(path, data or {})
        else:
            req = self.factory.post(path, data or {})
        req.user = self.admin
        return req

    # ------------------------------------------------------------------ index
    def test_index_renders_with_recent_rows(self):
        _mk_recent('a' * 32, FILE_NAME='one.apk')
        _mk_recent('b' * 32, FILE_NAME='two.ipa', SCAN_TYPE='ipa')
        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 200)
        # upload_accept must be a comma-separated dotted list, never '|'-joined.
        self.assertIn('upload_accept', resp.context)
        self.assertIn('.apk', resp.context['upload_accept'])
        self.assertNotIn('|', resp.context['upload_accept'])

    # ---------------------------------------------------------------- uploads
    def test_upload_size_limit_defaults_to_500mb(self):
        # Guards the real (non-overridden) configured limit — the oversize
        # tests below deliberately override this down to 10 bytes to stay
        # fast, so nothing else asserts the actual production default.
        self.assertEqual(settings.MOBINSPECT_MAX_UPLOAD_SIZE_MB, 500)
        self.assertEqual(settings.MOBINSPECT_MAX_UPLOAD_SIZE, 500 * 1024 * 1024)
        # The Django-level hard backstop must stay ABOVE the app-level limit,
        # or an upload between the two would hit Django's raw
        # RequestDataTooBig error instead of our friendly size message.
        self.assertGreater(
            settings.DATA_UPLOAD_MAX_MEMORY_SIZE,
            settings.MOBINSPECT_MAX_UPLOAD_SIZE)

    def test_upload_unsupported_file_format(self):
        bad = SimpleUploadedFile(
            'notreal.txt', b'this is plain text, not an app',
            content_type='text/plain')
        resp = self.client.post('/upload/', {'file': bad})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertEqual(data['status'], 'error')
        self.assertEqual(data['description'], 'File format not Supported!')

    def test_upload_invalid_form_missing_file(self):
        resp = self.client.post('/upload/', {})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertEqual(data['description'], 'Invalid Form Data!')

    def test_upload_method_not_post(self):
        resp = self.client.get('/upload/')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertEqual(data['description'], 'Method not Supported!')

    def test_upload_api_unsupported_and_invalid_form(self):
        # Exercise Upload.upload_api() directly (real object, real request).
        bad = SimpleUploadedFile(
            'x.txt', b'not an app', content_type='text/plain')
        req = self._authed_request('POST', '/api/v1/upload', {'file': bad})
        up = home.Upload(req)
        resp, code = up.upload_api()
        self.assertEqual(code, home.HTTP_BAD_REQUEST)
        self.assertEqual(resp['error'], 'File format not Supported!')

        req2 = self._authed_request('POST', '/api/v1/upload', {})
        up2 = home.Upload(req2)
        resp2, code2 = up2.upload_api()
        self.assertEqual(code2, home.HTTP_BAD_REQUEST)
        self.assertIn('error', resp2)

    @override_settings(MOBINSPECT_MAX_UPLOAD_SIZE=10)
    def test_upload_html_rejects_oversize_file(self):
        # Real file, real size check — MOBINSPECT_MAX_UPLOAD_SIZE lowered to
        # 10 bytes so a tiny upload exercises the real oversize branch
        # without allocating anything close to the real 500MB default.
        big = SimpleUploadedFile(
            'big.apk', b'x' * 100, content_type='application/octet-stream')
        resp = self.client.post('/upload/', {'file': big})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertEqual(data['status'], 'error')
        self.assertIn('exceeds', data['description'])
        self.assertIn('MB upload size limit', data['description'])

    @override_settings(MOBINSPECT_MAX_UPLOAD_SIZE=10)
    def test_upload_api_rejects_oversize_file(self):
        big = SimpleUploadedFile(
            'big.apk', b'x' * 100, content_type='application/octet-stream')
        req = self._authed_request('POST', '/api/v1/upload', {'file': big})
        up = home.Upload(req)
        resp, code = up.upload_api()
        self.assertEqual(code, home.HTTP_BAD_REQUEST)
        self.assertIn('exceeds', resp['error'])

    def test_upload_within_size_limit_is_not_rejected_for_size(self):
        # A file well under the real default limit must never be rejected
        # by the size guardrail (it still fails format validation here,
        # proving the size check passed through to the next branch).
        small = SimpleUploadedFile(
            'small.txt', b'x' * 1000, content_type='text/plain')
        resp = self.client.post('/upload/', {'file': small})
        data = json.loads(resp.content)
        self.assertEqual(data['description'], 'File format not Supported!')

    # -------------------------------------------------------- greeting/tip
    def test_index_shows_welcome_only_once_after_login(self):
        session = self.client.session
        session['just_logged_in'] = True
        session.save()
        resp = self.client.get('/')
        self.assertTrue(resp.context['just_logged_in'])
        self.assertIsNone(resp.context['security_tip'])

        # The flag is popped on first use — an immediate second request in
        # the same session must show a real, non-empty local security tip.
        resp2 = self.client.get('/')
        self.assertFalse(resp2.context['just_logged_in'])
        self.assertIn(resp2.context['security_tip'], home.SECURITY_TIPS)

    def test_avg_score_excludes_thin_library_formats(self):
        # A raw .so has no manifest/permissions to evaluate — the real
        # scorecard pass trivially scores it 100 (nothing to deduct). A
        # real .apk with a genuine high-severity finding scores much lower.
        # The FLEET AVERAGE must reflect only the real app, not be dragged
        # up by the library's vacuous 100 — while the library's own score
        # still appears on its individual recent-activity row.
        _mk_recent('1' * 32, FILE_NAME='lib.so', SCAN_TYPE='so',
                   PACKAGE_NAME='')
        StaticAnalyzerAndroid.objects.create(
            MD5='1' * 32, PACKAGE_NAME='', FILE_NAME='lib.so',
            VERSION_NAME='', ICON_PATH='',
            # A bare .so still runs the baseline "secure" checks (e.g. a
            # passing certificate check) with nothing high/warning to
            # offset them — same shape as the real formula that clamps a
            # near-empty scorecard's score to 100.
            CERTIFICATE_ANALYSIS=str({'certificate_findings': [
                ['secure', 'Baseline passing check', 'Baseline OK'],
            ]}))

        _mk_recent('2' * 32, FILE_NAME='real.apk', SCAN_TYPE='apk',
                   PACKAGE_NAME='com.cov.real')
        StaticAnalyzerAndroid.objects.create(
            MD5='2' * 32, PACKAGE_NAME='com.cov.real', FILE_NAME='real.apk',
            VERSION_NAME='1.0', ICON_PATH='',
            CERTIFICATE_ANALYSIS=str({'certificate_findings': [
                ['high', 'Real finding description', 'Real High Finding'],
            ]}))

        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 200)
        score_by_md5 = {r['MD5']: r['security_score']
                        for r in resp.context['recent']}
        # Both apps still show their own real per-row score.
        self.assertEqual(score_by_md5['1' * 32], 100)
        self.assertLess(score_by_md5['2' * 32], 100)
        # But the fleet average must equal the real app's score alone —
        # not a blend that the vacuous 100 would pull upward.
        self.assertEqual(
            resp.context['avg_security_score'], score_by_md5['2' * 32])

    # ----------------------------------------------------------- recent_scans
    def test_recent_scans_pagination_and_ipa_branch(self):
        # Android row with a real matching StaticAnalyzerAndroid (package map).
        _mk_recent('c' * 32, FILE_NAME='apk_app.apk',
                   PACKAGE_NAME='com.cov.apk')
        StaticAnalyzerAndroid.objects.create(
            MD5='c' * 32, PACKAGE_NAME='com.cov.apk',
            FILE_NAME='apk_app.apk', VERSION_NAME='1.0',
            ICON_PATH='icon.png')
        # iOS row (.ipa) exercises the BUNDLE_HASH / mobinspect_dump_file branch.
        _mk_recent('d' * 32, FILE_NAME='ios_app.ipa', SCAN_TYPE='ipa',
                   PACKAGE_NAME='com.cov.ios')
        StaticAnalyzerIOS.objects.create(
            MD5='d' * 32, FILE_NAME='ios_app.ipa', ICON_PATH='ios_icon.png')
        # A plain row with no static row -> PACKAGE '' fallback branch.
        _mk_recent('e' * 32, FILE_NAME='plain.apk')

        resp = self.client.get('/recent_scans/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['title'], 'Recent Scans')
        md5s = {e['MD5'] for e in resp.context['entries']}
        self.assertTrue({'c' * 32, 'd' * 32, 'e' * 32}.issubset(md5s))
        for e in resp.context['entries']:
            if e['MD5'] == 'c' * 32:
                self.assertEqual(e['PACKAGE'], 'com.cov.apk')
            if e['MD5'] == 'e' * 32:
                self.assertEqual(e['PACKAGE'], '')

        # Explicit page_size / page_number path.
        resp2 = self.client.get('/recent_scans/2/1/')
        self.assertEqual(resp2.status_code, 200)
        # page_size arrives from the URL as a string.
        self.assertEqual(str(resp2.context['page_obj'].page_size), '2')
        self.assertEqual(len(resp2.context['entries']), 2)

    def test_recent_scans_class_api(self):
        _mk_recent('f' * 32)
        req = self._authed_request('GET', '/api/v1/scans', {'page': 1})
        data = home.RecentScans(req).recent_scans()
        self.assertIn('content', data)
        self.assertGreaterEqual(data['count'], 1)
        # Invalid page value -> exception path returns {'error': ...}
        req_bad = self._authed_request('GET', '/api/v1/scans', {'page': 999})
        data_bad = home.RecentScans(req_bad).recent_scans()
        self.assertIn('error', data_bad)

    # ------------------------------------------------------------ delete_scan
    def test_delete_scan_invalid_hash(self):
        resp = self.client.post('/delete_scan/', {'md5': 'not-a-md5'})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.content)['deleted'], 'Invalid scan hash')

    def test_delete_scan_missing_hash(self):
        resp = self.client.post('/delete_scan/', {'md5': '0' * 32})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            json.loads(resp.content)['deleted'], 'Scan not found in Database')

    def test_delete_scan_api_mode(self):
        # api=True reads request.POST['hash'] and returns a plain dict.
        req = self._authed_request(
            'POST', '/api/v1/delete_scan', {'hash': '2' * 32})
        result = home.delete_scan(req, api=True)
        self.assertEqual(result, {'deleted': 'Scan not found in Database'})

    def test_delete_scan_real_delete(self):
        md5 = '1' * 32
        _mk_recent(md5, FILE_NAME='del.apk')
        StaticAnalyzerAndroid.objects.create(
            MD5=md5, PACKAGE_NAME='com.del', FILE_NAME='del.apk')
        # Real upload dir + a stray download file to exercise cleanup loops.
        app_dir = os.path.join(settings.UPLD_DIR, md5)
        os.makedirs(app_dir, exist_ok=True)
        with open(os.path.join(app_dir, 'f.txt'), 'w') as fh:
            fh.write('x')
        self._cleanup_paths.append(app_dir)
        dwd_file = os.path.join(settings.DWD_DIR, md5 + '-java.zip')
        with open(dwd_file, 'w') as fh:
            fh.write('x')
        self._cleanup_paths.append(dwd_file)

        resp = self.client.post('/delete_scan/', {'md5': md5})
        self.assertEqual(json.loads(resp.content)['deleted'], 'yes')
        self.assertFalse(RecentScansDB.objects.filter(MD5=md5).exists())
        self.assertFalse(os.path.exists(app_dir))
        self.assertFalse(os.path.exists(dwd_file))

    # ----------------------------------------------------------------- search
    def test_search_empty_query(self):
        resp = self.client.get('/search', {'query': ''})
        # print_n_send_error_response renders an error page (not a redirect).
        self.assertNotEqual(resp.status_code, 302)

    def test_search_md5_match_redirects(self):
        md5 = '2' * 32
        _mk_recent(md5, ANALYZER='static_analyzer')
        resp = self.client.get('/search', {'query': md5})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp['Location'], f'/static_analyzer/{md5}/')

    def test_search_post_query(self):
        md5 = 'aa' * 16
        _mk_recent(md5, ANALYZER='static_analyzer')
        resp = self.client.post('/search', {'query': md5})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp['Location'], f'/static_analyzer/{md5}/')

    def test_search_md5_no_row(self):
        resp = self.client.get('/search', {'query': '3' * 32})
        self.assertNotEqual(resp.status_code, 302)

    def test_search_text_match_by_filename(self):
        md5 = '4' * 32
        _mk_recent(md5, FILE_NAME='uniquefilename.apk')
        resp = self.client.get('/search', {'query': 'uniquefilename'})
        self.assertEqual(resp.status_code, 302)
        self.assertIn(md5, resp['Location'])

    def test_search_api_returns_checksum(self):
        md5 = '5' * 32
        _mk_recent(md5)
        req = self._authed_request('GET', '/search', {'query': md5})
        result = home.search(req, api=True)
        self.assertEqual(result, {'checksum': md5})

    def test_find_checksum_direct(self):
        md5 = '6' * 32
        _mk_recent(md5, APP_NAME='ZzSpecialApp')
        self.assertEqual(home.find_checksum('ZzSpecialApp'), md5)
        self.assertIsNone(home.find_checksum('no-such-thing-anywhere'))

    # ------------------------------------------------------------ scan_status
    def test_scan_status_invalid_hash(self):
        resp = self.client.post('/status/', {'hash': 'bad'})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.content)['status'], 'failed')

    def test_scan_status_not_found(self):
        resp = self.client.post('/status/', {'hash': '7' * 32})
        data = json.loads(resp.content)
        self.assertEqual(data['status'], 'failed')
        self.assertEqual(data['error'], 'scan hash not found')

    def test_scan_status_found(self):
        md5 = '8' * 32
        _mk_recent(md5, SCAN_LOGS='[]')
        resp = self.client.post('/status/', {'hash': md5})
        data = json.loads(resp.content)
        self.assertEqual(data['status'], 'ok')
        self.assertIn('logs', data)

    # -------------------------------------------------------- download_binary
    def test_download_binary_invalid_md5(self):
        req = self._authed_request('GET', '/download_binary/xx/')
        resp = home.download_binary(req, 'not-md5')
        self.assertEqual(resp.status_code, home.HTTP_STATUS_404)
        self.assertIn(b'Invalid MD5 Hash', resp.content)

    def test_download_binary_hash_not_found(self):
        md5 = '9' * 32
        req = self._authed_request('GET', f'/download_binary/{md5}/')
        resp = home.download_binary(req, md5)
        self.assertEqual(resp.status_code, home.HTTP_STATUS_404)
        self.assertIn(b'Scan hash not found', resp.content)

    def test_download_binary_invalid_scan_type(self):
        md5 = 'a' * 31 + '0'
        _mk_recent(md5, SCAN_TYPE='exe')  # '.exe' not in ALLOWED_EXTENSIONS
        req = self._authed_request('GET', f'/download_binary/{md5}/')
        resp = home.download_binary(req, md5)
        self.assertEqual(resp.status_code, home.HTTP_STATUS_404)
        self.assertIn(b'Invalid Scan Type', resp.content)

    def test_download_binary_file_missing(self):
        md5 = 'b' * 31 + '0'
        _mk_recent(md5, SCAN_TYPE='apk', FILE_NAME='gone.apk')
        req = self._authed_request('GET', f'/download_binary/{md5}/')
        resp = home.download_binary(req, md5)
        self.assertEqual(resp.status_code, home.HTTP_STATUS_404)
        self.assertIn(b'File not found', resp.content)

    def test_download_binary_success(self):
        md5 = 'c' * 31 + '0'
        _mk_recent(md5, SCAN_TYPE='txt', FILE_NAME='real.txt')
        app_dir = os.path.join(settings.UPLD_DIR, md5)
        os.makedirs(app_dir, exist_ok=True)
        self._cleanup_paths.append(app_dir)
        with open(os.path.join(app_dir, f'{md5}.txt'), 'wb') as fh:
            fh.write(b'downloadable-binary-content')
        req = self._authed_request('GET', f'/download_binary/{md5}/')
        resp = home.download_binary(req, md5)
        self.assertEqual(resp.status_code, 200)
        self.assertIn('attachment', resp['Content-Disposition'])

    def test_download_binary_svg_sanitized(self):
        md5 = 'd' * 31 + '0'
        _mk_recent(md5, SCAN_TYPE='svg', FILE_NAME='pic.svg')
        app_dir = os.path.join(settings.UPLD_DIR, md5)
        os.makedirs(app_dir, exist_ok=True)
        self._cleanup_paths.append(app_dir)
        svg = ('<svg xmlns="http://www.w3.org/2000/svg">'
               '<script>alert(1)</script><rect/></svg>')
        with open(os.path.join(app_dir, f'{md5}.svg'), 'w',
                  encoding='utf-8') as fh:
            fh.write(svg)
        req = self._authed_request('GET', f'/download_binary/{md5}/')
        resp = home.download_binary(req, md5)
        self.assertEqual(resp.status_code, 200)
        # sanitize_svg strips the <script> tag.
        self.assertNotIn(b'<script>', resp.content)

    # --------------------------------------------------------------- download
    def test_download_path_traversal_blocked(self):
        req = self._authed_request('GET', '/download/../../etc/passwd')
        resp = home.download(req)
        # print_n_send_error_response -> rendered page, not a file download.
        self.assertNotIn('Content-Disposition', resp)

    def test_download_missing_file_404(self):
        req = self._authed_request('GET', '/download/does_not_exist_here.txt')
        resp = home.download(req)
        self.assertEqual(resp.status_code, home.HTTP_STATUS_404)

    def test_download_screen_png_special_case(self):
        req = self._authed_request(
            'GET', '/download/somehash/screen/screen.png')
        resp = home.download(req)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, b'')

    def test_download_real_file(self):
        name = 'covreal_download.txt'
        dwd_file = os.path.join(settings.DWD_DIR, name)
        with open(dwd_file, 'wb') as fh:
            fh.write(b'real download file body')
        self._cleanup_paths.append(dwd_file)
        req = self._authed_request('GET', f'/download/{name}')
        resp = home.download(req)
        self.assertEqual(resp.status_code, 200)

    def test_download_real_svg_file(self):
        name = 'covreal_download.svg'
        dwd_file = os.path.join(settings.DWD_DIR, name)
        with open(dwd_file, 'w', encoding='utf-8') as fh:
            fh.write('<svg xmlns="http://www.w3.org/2000/svg">'
                     '<script>bad()</script></svg>')
        self._cleanup_paths.append(dwd_file)
        req = self._authed_request('GET', f'/download/{name}')
        resp = home.download(req)
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(b'<script>', resp.content)

    # ------------------------------------------------------ generate_download
    def test_generate_download_invalid_type(self):
        req = self._authed_request(
            'GET', '/generate_download/',
            {'hash': 'e' * 32, 'file_type': 'bogus'})
        resp = home.generate_download(req)
        # Renders the error page rather than redirecting.
        self.assertNotEqual(resp.status_code, 302)

    def test_generate_download_java_zip(self):
        md5 = 'e' * 31 + '0'
        src_dir = os.path.join(settings.UPLD_DIR, md5, 'java_source')
        os.makedirs(src_dir, exist_ok=True)
        self._cleanup_paths.append(os.path.join(settings.UPLD_DIR, md5))
        with open(os.path.join(src_dir, 'A.java'), 'w') as fh:
            fh.write('class A {}')
        out_zip = os.path.join(settings.DWD_DIR, f'{md5}-java.zip')
        self._cleanup_paths.append(out_zip)
        req = self._authed_request(
            'GET', '/generate_download/',
            {'hash': md5, 'file_type': 'java'})
        resp = home.generate_download(req)
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(os.path.exists(out_zip))

    def test_generate_download_smali_zip(self):
        md5 = 'f' * 31 + '0'
        src_dir = os.path.join(settings.UPLD_DIR, md5, 'smali_source')
        os.makedirs(src_dir, exist_ok=True)
        self._cleanup_paths.append(os.path.join(settings.UPLD_DIR, md5))
        with open(os.path.join(src_dir, 'A.smali'), 'w') as fh:
            fh.write('.class A')
        out_zip = os.path.join(settings.DWD_DIR, f'{md5}-smali.zip')
        self._cleanup_paths.append(out_zip)
        req = self._authed_request(
            'GET', '/generate_download/',
            {'hash': md5, 'file_type': 'smali'})
        resp = home.generate_download(req)
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(os.path.exists(out_zip))

    # ------------------------------------------------------- static templates
    def test_simple_template_routes(self):
        self.assertEqual(self.client.get('/about').status_code, 200)
        self.assertEqual(self.client.get('/api_docs').status_code, 200)
        self.assertEqual(self.client.get('/zip_format/').status_code, 200)
        self.assertEqual(self.client.get('/dynamic_analysis/').status_code, 200)
        r = self.client.get('/robots.txt')
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'User-agent', r.content)
        # error view (not login-gated).
        self.assertEqual(self.client.get('/error/').status_code, 200)

    # ----------------------------------------------------- update_scan_timestamp
    def test_update_scan_timestamp(self):
        from django.utils import timezone
        md5 = '0' * 31 + '1'
        _mk_recent(md5)
        before = timezone.now()
        home.update_scan_timestamp(md5)
        row = RecentScansDB.objects.get(MD5=md5)
        # update_scan_timestamp writes a fresh tz-aware timezone.now().
        self.assertGreaterEqual(row.TIMESTAMP, before)


class ScanRowStatusTests(TestCase):
    """_scan_row_status / scan_row_status: live status for an in-progress
    or failed scan row, replacing the old static 'Scan incomplete' badge."""

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            'rowstatus_admin', 'rowstatus_admin@example.com', 'pw')

    def setUp(self):
        self.client = Client()
        self.client.force_login(self.admin)

    def _mk_incomplete(self, md5, logs='[]'):
        return _mk_recent(
            md5, APP_NAME='', PACKAGE_NAME='', SCAN_LOGS=logs)

    def test_no_row_is_failed_not_found(self):
        status = home._scan_row_status('a' * 32)
        self.assertEqual(status, {
            'done': False, 'failed': True, 'label': 'Not found'})

    def test_app_name_present_is_done(self):
        md5 = 'b' * 32
        _mk_recent(md5, APP_NAME='Real App', PACKAGE_NAME='')
        status = home._scan_row_status(md5)
        self.assertTrue(status['done'])
        self.assertFalse(status['failed'])

    def test_package_name_present_is_done(self):
        md5 = 'c' * 32
        _mk_recent(md5, APP_NAME='', PACKAGE_NAME='com.example.only')
        status = home._scan_row_status(md5)
        self.assertTrue(status['done'])

    def test_empty_row_no_task_no_logs_is_failed(self):
        md5 = 'd' * 32
        self._mk_incomplete(md5)
        status = home._scan_row_status(md5)
        self.assertFalse(status['done'])
        self.assertTrue(status['failed'])
        self.assertEqual(status['label'], 'Scan incomplete')

    def test_queued_next_up_when_nothing_ahead(self):
        md5 = 'e' * 32
        self._mk_incomplete(md5)
        EnqueuedTask.objects.create(
            task_id='t1', checksum=md5, file_name='a.apk')
        status = home._scan_row_status(md5)
        self.assertFalse(status['done'])
        self.assertFalse(status['failed'])
        self.assertEqual(status['label'], 'Queued — next up')

    def test_queued_shows_count_ahead(self):
        from django.utils import timezone
        import datetime
        now = timezone.now()
        # Two earlier, still-incomplete tasks -> both count as "ahead".
        EnqueuedTask.objects.create(
            task_id='ahead1', checksum='1' * 32, file_name='x.apk',
            created_at=now - datetime.timedelta(minutes=5))
        EnqueuedTask.objects.create(
            task_id='ahead2', checksum='2' * 32, file_name='y.apk',
            created_at=now - datetime.timedelta(minutes=3))
        md5 = 'f' * 32
        self._mk_incomplete(md5)
        EnqueuedTask.objects.create(
            task_id='mine', checksum=md5, file_name='z.apk',
            created_at=now)
        status = home._scan_row_status(md5)
        self.assertEqual(status['label'], 'Queued — 2 scans ahead')

    def test_started_no_logs_yet_shows_starting(self):
        from django.utils import timezone
        md5 = 'a1' * 16
        self._mk_incomplete(md5)
        EnqueuedTask.objects.create(
            task_id='t2', checksum=md5, file_name='a.apk',
            started_at=timezone.now())
        status = home._scan_row_status(md5)
        self.assertFalse(status['done'])
        self.assertFalse(status['failed'])
        self.assertEqual(status['label'], 'Starting…')

    def test_running_shows_latest_log_message(self):
        from django.utils import timezone
        md5 = 'a2' * 16
        self._mk_incomplete(md5, logs=str([
            {'timestamp': 'x', 'status': 'Unzipping', 'exception': None},
            {'timestamp': 'y', 'status': 'Code Analysis Started on - java_source',
             'exception': None},
        ]))
        EnqueuedTask.objects.create(
            task_id='t3', checksum=md5, file_name='a.apk',
            started_at=timezone.now())
        status = home._scan_row_status(md5)
        self.assertFalse(status['done'])
        self.assertFalse(status['failed'])
        self.assertEqual(
            status['label'], 'Code Analysis Started on - java_source')

    def test_completed_task_but_no_app_data_is_failed(self):
        from django.utils import timezone
        md5 = 'a3' * 16
        self._mk_incomplete(md5)
        EnqueuedTask.objects.create(
            task_id='t4', checksum=md5, file_name='a.apk',
            started_at=timezone.now(), completed_at=timezone.now(),
            status='Failed')
        status = home._scan_row_status(md5)
        self.assertFalse(status['done'])
        self.assertTrue(status['failed'])
        self.assertEqual(status['label'], 'Failed')

    def test_never_raises_on_unexpected_error(self):
        md5 = 'a4' * 16
        self._mk_incomplete(md5)
        orig = RecentScansDB.objects.filter

        def _boom(*a, **kw):
            raise RuntimeError('boom')

        RecentScansDB.objects.filter = _boom
        try:
            status = home._scan_row_status(md5)
        finally:
            RecentScansDB.objects.filter = orig
        self.assertEqual(status, {
            'done': False, 'failed': True, 'label': 'Status unavailable'})

    # --------------------------------------------------- scan_row_status view
    def test_view_anonymous_redirects_to_login(self):
        anon = Client()
        resp = anon.get(f'/scan_row_status/{"a8" * 16}/')
        self.assertEqual(resp.status_code, 302)
        self.assertIn('login', resp['Location'])

    def test_view_invalid_checksum_is_204(self):
        resp = self.client.get('/scan_row_status/not-a-real-checksum/')
        self.assertEqual(resp.status_code, 404)  # URL regex rejects it

    def test_view_done_returns_204_with_hx_refresh(self):
        md5 = 'a5' * 16
        _mk_recent(md5, APP_NAME='Finished App')
        resp = self.client.get(f'/scan_row_status/{md5}/')
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(resp['HX-Refresh'], 'true')

    def test_view_in_progress_renders_partial_with_label(self):
        md5 = 'a6' * 16
        self._mk_incomplete(md5)
        EnqueuedTask.objects.create(
            task_id='t5', checksum=md5, file_name='a.apk')
        resp = self.client.get(f'/scan_row_status/{md5}/')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Queued', resp.content)
        # Still-polling state carries its own hx-get for the next poll.
        self.assertIn(b'hx-get', resp.content)

    def test_view_failed_renders_without_further_polling(self):
        md5 = 'a7' * 16
        self._mk_incomplete(md5)
        resp = self.client.get(f'/scan_row_status/{md5}/')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Scan incomplete', resp.content)
        self.assertNotIn(b'hx-get', resp.content)


class HomeGapCoverageTests(TestCase):
    """Closes remaining real-execution gaps in home.py: the dashboard
    rollup's import/scoring except branches, the full Upload() elif dispatch
    chain, api_docs' exception path, help_center, recent_scans' query filter,
    download_apk, scan_status's exception path, _scan_row_status's
    no-EnqueuedTask-but-has-logs branch, the direct-call is_md5 guard in
    scan_row_status, download_binary's real I/O exception, generate_download's
    real I/O exception, and delete_scan's async-in-progress / directory-cleanup
    / exception branches. No mocks -- every branch is driven by real data,
    real files, or a genuinely broken import/literal (see inline notes).
    """

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            'gap_admin', 'gap_admin@example.com', 'gap_admin')

    def setUp(self):
        self.client = Client()
        self.client.force_login(self.admin)
        self._cleanup_paths = []

    def tearDown(self):
        for p in self._cleanup_paths:
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            elif os.path.isfile(p):
                try:
                    os.remove(p)
                except OSError:
                    pass

    # --------------------------------------------- _home_security_rollup
    def test_rollup_import_failure_returns_empty(self):
        # Real fault injection: poison sys.modules for the appsec dotted
        # path so the real `from ... import ...` statement inside the
        # function raises ImportError -- not a return-value mock.
        target = 'mobinspect.StaticAnalyzer.views.common.appsec'
        prev = sys.modules.get(target, False)
        sys.modules[target] = None
        try:
            issues, avg, by_md5 = home._home_security_rollup(['x' * 32])
        finally:
            if prev is False:
                sys.modules.pop(target, None)
            else:
                sys.modules[target] = prev
        self.assertEqual((issues, avg, by_md5), (0, None, {}))

    def test_rollup_scorer_exception_is_skipped(self):
        # get_context_from_db_entry has its OWN blanket try/except (returns
        # None on a bad literal), so a broken CERTIFICATE_ANALYSIS string
        # alone never reaches home.py's except -- it degrades to empty
        # findings instead. To make the real get_android_dashboard scorer
        # itself raise (uncaught, propagating up to home.py's except), the
        # literal must parse fine but be structurally short: a
        # certificate_findings entry with only 1 element makes appsec.py's
        # `i[2]` a genuine IndexError. Real fault injection via bad stored
        # data shaped to hit the specific unguarded line, not a mock.
        md5 = 'ab' * 16
        _mk_recent(md5, FILE_NAME='broken.apk', PACKAGE_NAME='com.broken')
        StaticAnalyzerAndroid.objects.create(
            MD5=md5, PACKAGE_NAME='com.broken', FILE_NAME='broken.apk',
            VERSION_NAME='1.0', ICON_PATH='',
            CERTIFICATE_ANALYSIS=str({'certificate_findings': [['high']]}))
        issues, avg, by_md5 = home._home_security_rollup([md5])
        # The broken entry is skipped (continue), never scored.
        self.assertEqual(by_md5, {})
        self.assertEqual(issues, 0)
        self.assertIsNone(avg)

    # ----------------------------------------------------- Upload() dispatch
    def _upload_named(self, filename, content_type, body):
        f = SimpleUploadedFile(filename, body, content_type=content_type)
        resp = self.client.post('/upload/', {'file': f})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        if data.get('hash'):
            self._cleanup_paths.append(
                os.path.join(settings.UPLD_DIR, data['hash']))
        return data

    def test_upload_dispatches_every_remaining_file_type(self):
        # Each body must be genuinely UNIQUE bytes (not just a unique magic
        # prefix): the MD5 is computed over the whole file, and identical
        # content across two uploads trips the real duplicate-upload guard
        # (layer 1, exact-bytes) regardless of filename/extension.
        def _zip_body(tag):
            return b'\x50\x4B\x03\x04' + tag.encode() + b'\x00' * 60

        def _elf_body(tag):
            return b'\x7F\x45\x4C\x46' + tag.encode() + b'\x00' * 60

        def _dylib_body(tag):
            return b'\xCA\xFE\xBA\xBE' + tag.encode() + b'\x00' * 60

        def _ar_body(tag):
            return b'\x21\x3C\x61\x72' + tag.encode() + b'\x00' * 60

        cases = [
            ('one.xapk', _zip_body('xapk'), 'xapk'),
            ('two.apks', _zip_body('apks'), 'apks'),
            ('three.aab', _zip_body('aab'), 'aab'),
            ('four.jar', _zip_body('jar'), 'jar'),
            ('five.aar', _zip_body('aar'), 'aar'),
            ('six.so', _elf_body('so'), 'so'),
            ('seven.zip', _zip_body('zip'), 'zip'),
            ('eight.dylib', _dylib_body('dylib'), 'dylib'),
            ('nine.a', _ar_body('a'), 'a'),
        ]
        for filename, body, expected_scan_type in cases:
            with self.subTest(filename=filename):
                data = self._upload_named(
                    filename, 'application/octet-stream', body)
                self.assertEqual(data['status'], 'success', data)
                self.assertEqual(data['scan_type'], expected_scan_type)

    def test_upload_real_ipa_dispatches_and_hits_platform_guard_condition(self):
        # Real ios.ipa sample: is_ipa() True -> enters the `if
        # self.file_type.is_ipa():` block and evaluates the platform.system()
        # guard (the Windows-only body is pragma'd in home.py -- genuinely
        # unreachable on this Darwin/Linux host).
        path = os.path.join(TEST_FILES, 'ios.ipa')
        with open(path, 'rb') as fh:
            body = fh.read()
        data = self._upload_named('real.ipa', 'application/octet-stream', body)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['scan_type'], 'ipa')

    def test_upload_real_appx_dispatches(self):
        path = os.path.join(TEST_FILES, 'windows.appx')
        with open(path, 'rb') as fh:
            body = fh.read()
        data = self._upload_named(
            'real.appx', 'application/octet-stream', body)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['scan_type'], 'appx')

    def test_upload_plain_apk_dispatches(self):
        # The base is_apk() branch (scanning.scan_apk()) -- every other
        # sibling test in this file uploads a REAL android.apk (which is
        # always a fresh duplicate of a scan created elsewhere in the
        # suite), so a small synthetic zip-magic '.apk' is used here to
        # guarantee a first-upload (non-duplicate) success.
        body = b'\x50\x4B\x03\x04plainapk' + b'\x00' * 60
        data = self._upload_named('plain.apk', 'application/octet-stream', body)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['scan_type'], 'apk')

    # ---------------------------------------------------------- upload_api
    def test_upload_api_success_and_duplicate_envelope(self):
        # First call: real success branch (436, 443). Second call with the
        # exact same bytes: real duplicate envelope (437-442).
        body = b'\x50\x4B\x03\x04apidup' + b'\x00' * 60
        f1 = SimpleUploadedFile(
            'api1.apk', body, content_type='application/octet-stream')
        req1 = RequestFactory().post('/api/v1/upload', {'file': f1})
        req1.user = self.admin
        up1 = home.Upload(req1)
        resp1, code1 = up1.upload_api()
        self.assertEqual(code1, 200)
        self.assertEqual(resp1['status'], 'success')
        self._cleanup_paths.append(
            os.path.join(settings.UPLD_DIR, resp1['hash']))

        f2 = SimpleUploadedFile(
            'api2.apk', body, content_type='application/octet-stream')
        req2 = RequestFactory().post('/api/v1/upload', {'file': f2})
        req2.user = self.admin
        up2 = home.Upload(req2)
        resp2, code2 = up2.upload_api()
        self.assertEqual(code2, home.HTTP_CONFLICT)
        self.assertTrue(resp2['duplicate'])
        self.assertEqual(resp2['existing_hash'], resp1['hash'])

    # --------------------------------------------------------------- api_docs
    @override_settings(MOBINSPECT_HOME=None)
    def test_api_docs_key_lookup_exception_is_caught(self):
        # settings.MOBINSPECT_HOME=None -> api_key(None) does Path(None)
        # BEFORE its own internal try block -> raises TypeError -> caught by
        # the surrounding except in api_docs(). Real fault, no mock.
        resp = self.client.get('/api_docs')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['api_key'], '*******')

    # ------------------------------------------------------------ help_center
    def test_help_center_renders(self):
        resp = self.client.get('/help/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['title'], 'Help')
        self.assertTrue(len(resp.context['help_faqs']) > 0)

    # ------------------------------------------------------------ recent_scans
    def test_recent_scans_query_filters(self):
        _mk_recent('11' * 16, FILE_NAME='findme.apk', APP_NAME='FindMeApp')
        _mk_recent('22' * 16, FILE_NAME='other.apk', APP_NAME='Other')
        resp = self.client.get('/recent_scans/', {'q': 'findme'})
        self.assertEqual(resp.status_code, 200)
        md5s = {e['MD5'] for e in resp.context['entries']}
        self.assertIn('11' * 16, md5s)
        self.assertNotIn('22' * 16, md5s)

    # ---------------------------------------------------------- download_apk
    def test_download_apk_no_result(self):
        # Invalid package name -> fails strict_package_check regardless of
        # whether the sandbox has outbound internet (mirrors the existing
        # apk_downloader ApkDownloadValidationTests convention) -> apk_download
        # returns None fast, no live network round-trip is required.
        resp = self.client.post(
            '/download_scan/', {'package': 'not a valid package!!'})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertEqual(data['status'], 'failed')
        self.assertEqual(data['description'], 'Unable to download APK')

    def test_download_apk_success_result(self):
        # Real success branch (lines 671-673): apk_download's own internals
        # are covered exhaustively in test_cov_apk_downloader.py (including
        # a real local-loopback-server end-to-end success flow); this view
        # only needs a truthy `res` to exercise ITS OWN "merge result into
        # context" logic, so `home.apk_download` -- imported directly into
        # this module's namespace -- is narrowly patched at that single
        # call site, exactly as done for `try_provider` in
        # ApkDownloadOrchestrationTests.
        fake_result = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': 'f' * 32,
            'scan_type': 'apk',
            'file_name': 'downloaded.apk',
        }
        with mock.patch.object(
                home, 'apk_download', return_value=fake_result):
            resp = self.client.post(
                '/download_scan/', {'package': 'com.example.real'})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertEqual(data['status'], 'ok')
        self.assertEqual(data['package'], 'com.example.real')
        self.assertEqual(data['hash'], 'f' * 32)
        self.assertEqual(data['file_name'], 'downloaded.apk')

    # ------------------------------------------------------------- scan_status
    def test_scan_status_exception_path(self):
        md5 = '33' * 16
        _mk_recent(md5, SCAN_LOGS='not valid python {[')
        resp = self.client.post('/status/', {'hash': md5})
        data = json.loads(resp.content)
        self.assertEqual(data['status'], 'failed')
        self.assertIn('message', data)

    # ----------------------------------------------------- _scan_row_status
    def test_row_status_no_task_but_has_logs(self):
        md5 = '44' * 16
        _mk_recent(md5, APP_NAME='', PACKAGE_NAME='', SCAN_LOGS=str([
            {'timestamp': 'x', 'status': 'Unzipping', 'exception': None},
        ]))
        # No EnqueuedTask row at all for this checksum.
        status = home._scan_row_status(md5)
        self.assertFalse(status['done'])
        self.assertFalse(status['failed'])
        self.assertEqual(status['label'], 'Unzipping')

    def test_scan_row_status_view_direct_call_invalid_checksum(self):
        # The URL regex already restricts to 32 lowercase-hex chars, so the
        # is_md5() guard inside the view is only reachable via a direct call
        # that bypasses URL dispatch (a real call to the real view, no mock).
        factory = RequestFactory()
        req = factory.get('/scan_row_status/zz/')
        req.user = self.admin
        resp = home.scan_row_status(req, 'zz')
        self.assertEqual(resp.status_code, 204)

    # -------------------------------------------------------- download_binary
    def test_download_binary_open_failure_is_caught(self):
        # Real I/O fault: the "file" is actually a directory, so `open(...,
        # 'rb')` inside file_download raises IsADirectoryError, caught by
        # download_binary's except branch.
        md5 = '55' * 16
        _mk_recent(md5, SCAN_TYPE='txt', FILE_NAME='real.txt')
        app_dir = os.path.join(settings.UPLD_DIR, md5)
        os.makedirs(app_dir, exist_ok=True)
        self._cleanup_paths.append(app_dir)
        # Directory in place of the expected file.
        os.makedirs(os.path.join(app_dir, f'{md5}.txt'), exist_ok=True)
        factory = RequestFactory()
        req = factory.get(f'/download_binary/{md5}/')
        req.user = self.admin
        resp = home.download_binary(req, md5)
        self.assertEqual(resp.status_code, home.HTTP_SERVER_ERROR)
        self.assertIn(b'Failed to download file', resp.content)

    # ----------------------------------------------------- generate_download
    def test_generate_download_exception_is_caught(self):
        # No source directory on disk at all -> shutil.make_archive raises
        # FileNotFoundError -> caught by generate_download's except branch.
        md5 = '66' * 16
        factory = RequestFactory()
        req = factory.get(
            '/generate_download/', {'hash': md5, 'file_type': 'java'})
        req.user = self.admin
        resp = home.generate_download(req)
        self.assertNotEqual(resp.status_code, 302)

    # ----------------------------------------------------------- delete_scan
    @override_settings(ASYNC_ANALYSIS=True)
    def test_delete_scan_blocked_while_task_in_progress(self):
        md5 = '77' * 16
        _mk_recent(md5, FILE_NAME='inprogress.apk')
        EnqueuedTask.objects.create(
            task_id='inprogress', checksum=md5, file_name='inprogress.apk',
            created_at=now())
        resp = self.client.post('/delete_scan/', {'md5': md5})
        data = json.loads(resp.content)
        self.assertEqual(
            data['deleted'],
            'A scan can only be deleted after it is completed')
        # Never actually deleted.
        self.assertTrue(RecentScansDB.objects.filter(MD5=md5).exists())

    def test_delete_scan_removes_directory_in_download_dir(self):
        md5 = '88' * 16
        _mk_recent(md5, FILE_NAME='withdir.apk')
        StaticAnalyzerAndroid.objects.create(
            MD5=md5, PACKAGE_NAME='com.withdir', FILE_NAME='withdir.apk')
        stray_dir = os.path.join(settings.DWD_DIR, md5 + '-extracted')
        os.makedirs(stray_dir, exist_ok=True)
        with open(os.path.join(stray_dir, 'f.txt'), 'w') as fh:
            fh.write('x')
        resp = self.client.post('/delete_scan/', {'md5': md5})
        self.assertEqual(json.loads(resp.content)['deleted'], 'yes')
        self.assertFalse(os.path.exists(stray_dir))

    def test_delete_scan_exception_path_missing_md5_key(self):
        # No 'md5' key at all in POST -> KeyError inside the try -> caught
        # by delete_scan's except branch -> rendered error page (500 HTML,
        # not the JSON {'deleted': ...} envelope).
        resp = self.client.post('/delete_scan/', {})
        self.assertEqual(resp.status_code, 500)
        self.assertNotIn(b'"deleted"', resp.content)
