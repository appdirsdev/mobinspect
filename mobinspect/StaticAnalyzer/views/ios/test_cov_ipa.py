# -*- coding: utf_8 -*-
"""Real-execution coverage tests for mobinspect.StaticAnalyzer.views.ios.ipa.

STRICT: no mocks / no monkeypatch of internal logic. A single REAL upload +
static analysis of the committed ``test_files/ios.ipa`` sample is performed
once in ``setUpTestData`` (driving the full IPA pipeline: extract, plist,
binary, strings, firebase/trackers, DB save, dynamic context). The remaining
branch tests craft real inputs (malformed zips, bad paths, real RBAC users)
and call the real module functions with real assertions.
"""
import os
import zipfile
import tempfile
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, SimpleTestCase, Client, RequestFactory, override_settings

from django.utils import timezone

from mobinspect.RBAC.models import ApiKey
from mobinspect.StaticAnalyzer.models import (
    EnqueuedTask,
    RecentScansDB,
    StaticAnalyzerIOS,
)
from mobinspect.StaticAnalyzer.views.ios.ipa import (
    extract_and_check_ipa,
    generate_dynamic_context,
    generate_dynamic_ios_context,
    get_scan_subject,
    initialize_app_dic,
    ios_analysis,
    ios_analysis_task,
    ipa_analysis,
    ipa_analysis_task,
)
from mobinspect.StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry,
)


SAMPLES_DIR = os.path.normpath(
    os.path.join(settings.BASE_DIR, '..', 'test_files'))


def build_app_dic(checksum, app_dir=None, app_path=None, file_name='ios.ipa'):
    """Replicate the app_dict that static_analyzer_ios builds."""
    app_dirp = Path(app_dir) if app_dir else (Path(settings.UPLD_DIR) / checksum)
    d = {
        'directory': Path(settings.BASE_DIR),
        'file_name': file_name,
        'md5_hash': checksum,
        'app_dirp': app_dirp,
        'app_dir': app_dirp.as_posix() + '/',
        'tools_dir': (Path(settings.BASE_DIR)
                      / 'StaticAnalyzer' / 'tools' / 'ios').as_posix(),
        'icon_path': '',
    }
    if app_path:
        d['app_path'] = app_path
    return d


# --------------------------------------------------------------------------
# Pure function: get_scan_subject (all branches, no I/O)
# --------------------------------------------------------------------------
class GetScanSubjectTests(SimpleTestCase):

    def test_app_name_and_pkg(self):
        app_dic = {'infoplist': {'id': 'com.x.y'}}
        bin_dict = {'bin_path': Path('/a/b/MyApp')}
        self.assertEqual(
            get_scan_subject(app_dic, bin_dict), 'MyApp (com.x.y)')

    def test_pkg_only(self):
        app_dic = {'infoplist': {'id': 'com.only.pkg'}}
        bin_dict = {}
        self.assertEqual(get_scan_subject(app_dic, bin_dict), 'com.only.pkg')

    def test_app_name_only(self):
        app_dic = {'infoplist': {}}
        bin_dict = {'bin_path': Path('/a/b/JustBin')}
        self.assertEqual(get_scan_subject(app_dic, bin_dict), 'JustBin')

    def test_neither_default(self):
        self.assertEqual(get_scan_subject({}, {}), 'iOS App')

    def test_failed_subject_wrapped(self):
        # pkg_name == 'Failed' -> subject becomes 'Failed' -> '(Failed)'
        app_dic = {'infoplist': {'id': 'Failed'}}
        bin_dict = {}
        self.assertEqual(get_scan_subject(app_dic, bin_dict), '(Failed)')

    def test_bin_path_none_value(self):
        # bin_path key present but falsy -> app_name stays None
        app_dic = {'infoplist': {'id': 'com.z'}}
        bin_dict = {'bin_path': None}
        self.assertEqual(get_scan_subject(app_dic, bin_dict), 'com.z')


# --------------------------------------------------------------------------
# initialize_app_dic (pure)
# --------------------------------------------------------------------------
class InitializeAppDicTests(SimpleTestCase):

    def test_sets_file_and_path(self):
        d = {'md5_hash': 'a' * 32, 'app_dirp': Path('/tmp/x')}
        checksum = initialize_app_dic(d, 'ipa')
        self.assertEqual(checksum, 'a' * 32)
        self.assertEqual(d['app_file'], f"{'a' * 32}.ipa")
        self.assertTrue(d['app_path'].endswith(f"{'a' * 32}.ipa"))


# --------------------------------------------------------------------------
# extract_and_check_ipa False branch (no Payload dir) - crafted real zip
# --------------------------------------------------------------------------
class ExtractAndCheckIpaTests(TestCase):

    def test_malformed_no_payload_returns_false(self):
        tmp = tempfile.mkdtemp()
        zip_path = os.path.join(tmp, 'bad.ipa')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('Contents/readme.txt', 'hello')
        app_dic = build_app_dic('c' * 32, app_dir=tmp, app_path=zip_path)
        self.assertFalse(extract_and_check_ipa('c' * 32, app_dic))

    def test_valid_payload_returns_true(self):
        tmp = tempfile.mkdtemp()
        zip_path = os.path.join(tmp, 'good.ipa')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('Payload/App.app/Info.plist', 'x')
        app_dic = build_app_dic('d' * 32, app_dir=tmp, app_path=zip_path)
        self.assertTrue(extract_and_check_ipa('d' * 32, app_dic))
        self.assertIn('bin_dir', app_dic)
        self.assertTrue(app_dic['bin_dir'].lower().find('payload') != -1)


# --------------------------------------------------------------------------
# ipa_analysis_task exception branch (bad path) + Permission denied branch
# without any real scan (fast).
# --------------------------------------------------------------------------
@override_settings(DISABLE_AUTHENTICATION=None, ASYNC_ANALYSIS=False)
class IpaFastBranchTests(TestCase):

    def test_task_exception_branch_returns_err(self):
        # app_path points to a non-existent file -> get_size_and_hashes
        # raises inside ipa_analysis_task -> (None, repr(exp)).
        app_dic = build_app_dic(
            'e' * 32,
            app_dir=tempfile.mkdtemp(),
            app_path='/nonexistent/does/not/exist.ipa')
        context, err = ipa_analysis_task('e' * 32, app_dic, rescan=False)
        self.assertIsNone(context)
        self.assertIsInstance(err, str)
        self.assertTrue(len(err) > 0)

    def test_malformed_ipa_analysis_error_response(self):
        # A zip without Payload -> ipa_analysis_task returns malformed msg,
        # ipa_analysis returns print_n_send_error_response (api dict).
        checksum = 'f' * 32
        tmp = tempfile.mkdtemp()
        zip_path = os.path.join(tmp, f'{checksum}.ipa')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('Contents/x.txt', 'y')
        app_dic = build_app_dic(checksum, app_dir=tmp, app_path=zip_path)
        rf = RequestFactory()
        request = rf.get('/')
        User = get_user_model()
        staff = User.objects.create_superuser(
            'malf_admin', 'malf@example.com', 'admin')
        request.user = staff
        result = ipa_analysis(request, app_dic, rescan=False, api=True)
        # api=True -> print_n_send_error_response returns {'error': msg}
        self.assertIsInstance(result, dict)
        self.assertIn('error', result)
        self.assertIn('Payload', result['error'])

    def test_permission_denied_branch(self):
        checksum = '0' * 32
        tmp = tempfile.mkdtemp()
        app_dic = build_app_dic(
            checksum, app_dir=tmp,
            app_path=os.path.join(tmp, f'{checksum}.ipa'))
        rf = RequestFactory()
        request = rf.get('/')
        User = get_user_model()
        # non-staff user with no scan permission
        viewer = User.objects.create_user(
            'viewer_u', 'viewer@example.com', 'pass')
        request.user = viewer
        request.api_user = None
        # api=False so has_permission denial -> render 500 error page
        resp = ipa_analysis(request, app_dic, rescan=False, api=False)
        self.assertEqual(resp.status_code, 500)


# --------------------------------------------------------------------------
# FULL real IPA scan + report/dynamic-context branches.
# --------------------------------------------------------------------------
@override_settings(
    RATELIMIT_ENABLE=False, DISABLE_AUTHENTICATION=None, ASYNC_ANALYSIS=False)
class IpaRealScanTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            'ipa_admin', 'ipa_admin@example.com', 'admin')
        _, cls.api_key = ApiKey.generate(cls.admin, 'ipa-key')
        auth = {'HTTP_AUTHORIZATION': cls.api_key}
        client = Client()
        path = os.path.join(SAMPLES_DIR, 'ios.ipa')
        with open(path, 'rb') as fh:
            upload = SimpleUploadedFile(
                'ios.ipa', fh.read(),
                content_type='application/octet-stream')
        up = client.post('/api/v1/upload', {'file': upload}, **auth)
        assert up.status_code == 200, up.content
        cls.md5 = up.json()['hash']
        sc = client.post('/api/v1/scan', {'hash': cls.md5}, **auth)
        cls.scan_status = sc.status_code

    def _admin_request(self):
        rf = RequestFactory()
        request = rf.get('/')
        request.user = self.admin
        request.api_user = self.admin
        return request

    def test_scan_created_ios_db_entry(self):
        self.assertEqual(self.scan_status, 200)
        self.assertTrue(
            StaticAnalyzerIOS.objects.filter(MD5=self.md5).exists())

    def test_ipa_analysis_db_exists_branch_api(self):
        # DB entry exists + rescan False -> get_context_from_db_entry ->
        # generate_dynamic_context (api=True returns the context dict).
        app_dic = build_app_dic(self.md5)
        ctx = ipa_analysis(
            self._admin_request(), app_dic, rescan=False, api=True)
        self.assertIsInstance(ctx, dict)
        self.assertIn('appsec', ctx)
        self.assertIn('average_cvss', ctx)

    def test_generate_dynamic_context_render_html(self):
        # api=False path -> real Django render of the report template.
        app_dic = build_app_dic(self.md5)
        db = StaticAnalyzerIOS.objects.filter(MD5=self.md5)
        context = get_context_from_db_entry(db)
        resp = generate_dynamic_context(
            self._admin_request(), app_dic, context, self.md5, api=False)
        self.assertEqual(resp.status_code, 200)

    def test_ipa_analysis_rescan_branch(self):
        # rescan True -> re-runs full ipa_analysis_task on the real ipa.
        app_dic = build_app_dic(self.md5)
        ctx = ipa_analysis(
            self._admin_request(), app_dic, rescan=True, api=True)
        self.assertIsInstance(ctx, dict)
        self.assertIn('appsec', ctx)

    def test_extract_and_check_ipa_true_real(self):
        # Extract the real uploaded ipa into a fresh temp dir -> Payload found.
        tmp = tempfile.mkdtemp()
        real_ipa = (Path(settings.UPLD_DIR) / self.md5
                    / f'{self.md5}.ipa').as_posix()
        app_dic = build_app_dic(self.md5, app_dir=tmp, app_path=real_ipa)
        self.assertTrue(extract_and_check_ipa(self.md5, app_dic))
        self.assertIn('payload', app_dic['bin_dir'].lower())

    def test_ipa_analysis_async_branch_returns_early(self):
        # ASYNC_ANALYSIS on -> ipa_analysis routes to async_analysis. We
        # pre-seed a completed EnqueuedTask + a completed RecentScansDB so
        # async_analysis returns its "already completed" dict WITHOUT
        # enqueuing to a real broker (no worker infra in tests).
        RecentScansDB.objects.filter(MD5=self.md5).update(APP_NAME='App')
        EnqueuedTask.objects.create(
            task_id='ipa-async-1', checksum=self.md5,
            file_name='ios.ipa', completed_at=timezone.now())
        app_dic = build_app_dic(self.md5)
        with override_settings(ASYNC_ANALYSIS=True):
            result = ipa_analysis(
                self._admin_request(), app_dic, rescan=True, api=True)
        self.assertIsInstance(result, dict)
        self.assertIn('message', result)

    def test_ipa_analysis_task_queue_success(self):
        # queue=True -> mark_task_started/completed path + success return.
        tmp = tempfile.mkdtemp()
        real_ipa = (Path(settings.UPLD_DIR) / self.md5
                    / f'{self.md5}.ipa').as_posix()
        app_dic = build_app_dic(self.md5, app_dir=tmp, app_path=real_ipa)
        original = settings.ASYNC_ANALYSIS
        try:
            result = ipa_analysis_task(
                self.md5, app_dic, rescan=True, queue=True)
        finally:
            settings.ASYNC_ANALYSIS = original
        # mark_task_completed returns True.
        self.assertTrue(result)

    def test_ipa_analysis_task_queue_malformed(self):
        # queue=True + malformed -> mark_task_completed('Failed', msg).
        checksum = '1' * 32
        tmp = tempfile.mkdtemp()
        zip_path = os.path.join(tmp, f'{checksum}.ipa')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('Contents/x.txt', 'y')
        app_dic = build_app_dic(checksum, app_dir=tmp, app_path=zip_path)
        original = settings.ASYNC_ANALYSIS
        try:
            result = ipa_analysis_task(
                checksum, app_dic, rescan=False, queue=True)
        finally:
            settings.ASYNC_ANALYSIS = original
        self.assertTrue(result)

    def test_ipa_analysis_task_queue_exception(self):
        # queue=True + bad path -> exception -> mark_task_completed('Failed').
        checksum = '2' * 32
        app_dic = build_app_dic(
            checksum, app_dir=tempfile.mkdtemp(),
            app_path='/nonexistent/bad.ipa')
        original = settings.ASYNC_ANALYSIS
        try:
            result = ipa_analysis_task(
                checksum, app_dic, rescan=False, queue=True)
        finally:
            settings.ASYNC_ANALYSIS = original
        self.assertTrue(result)


# --------------------------------------------------------------------------
# FULL real iOS SOURCE (zip) scan + ios_analysis branches.
# --------------------------------------------------------------------------
@override_settings(
    RATELIMIT_ENABLE=False, DISABLE_AUTHENTICATION=None, ASYNC_ANALYSIS=False)
class IosSourceScanTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            'ios_src_admin', 'ios_src_admin@example.com', 'admin')
        _, cls.api_key = ApiKey.generate(cls.admin, 'ios-src-key')
        auth = {'HTTP_AUTHORIZATION': cls.api_key}
        client = Client()
        path = os.path.join(SAMPLES_DIR, 'ios_src.zip')
        with open(path, 'rb') as fh:
            upload = SimpleUploadedFile(
                'ios_src.zip', fh.read(),
                content_type='application/octet-stream')
        up = client.post('/api/v1/upload', {'file': upload}, **auth)
        assert up.status_code == 200, up.content
        cls.md5 = up.json()['hash']
        cls.scan_type = up.json().get('scan_type')
        sc = client.post('/api/v1/scan', {'hash': cls.md5}, **auth)
        cls.scan_status = sc.status_code

    def _admin_request(self):
        rf = RequestFactory()
        request = rf.get('/')
        request.user = self.admin
        request.api_user = self.admin
        return request

    def test_source_scan_created_db_entry(self):
        self.assertEqual(self.scan_status, 200)
        self.assertTrue(
            StaticAnalyzerIOS.objects.filter(MD5=self.md5).exists())

    def test_ios_analysis_db_exists_branch_api(self):
        # DB entry exists -> get_context_from_db_entry ->
        # generate_dynamic_ios_context (api=True returns context dict).
        app_dic = build_app_dic(self.md5, file_name='ios_src.zip')
        ctx = ios_analysis(
            self._admin_request(), app_dic, rescan=False, api=True)
        self.assertIsInstance(ctx, dict)
        self.assertIn('appsec', ctx)
        self.assertIn('average_cvss', ctx)

    def test_generate_dynamic_ios_context_render_html(self):
        app_dic = build_app_dic(self.md5, file_name='ios_src.zip')
        db = StaticAnalyzerIOS.objects.filter(MD5=self.md5)
        context = get_context_from_db_entry(db)
        resp = generate_dynamic_ios_context(
            self._admin_request(), context, api=False)
        self.assertEqual(resp.status_code, 200)

    def test_ios_analysis_rescan_branch(self):
        # rescan True -> re-runs ios_analysis_task on the real source tree.
        app_dic = build_app_dic(self.md5, file_name='ios_src.zip')
        ctx = ios_analysis(
            self._admin_request(), app_dic, rescan=True, api=True)
        self.assertIsInstance(ctx, dict)
        self.assertIn('appsec', ctx)

    def test_ios_analysis_async_branch_returns_early(self):
        RecentScansDB.objects.filter(MD5=self.md5).update(APP_NAME='SrcApp')
        EnqueuedTask.objects.create(
            task_id='ios-async-1', checksum=self.md5,
            file_name='ios_src.zip', completed_at=timezone.now())
        app_dic = build_app_dic(self.md5, file_name='ios_src.zip')
        with override_settings(ASYNC_ANALYSIS=True):
            result = ios_analysis(
                self._admin_request(), app_dic, rescan=True, api=True)
        self.assertIsInstance(result, dict)
        self.assertIn('message', result)

    def test_ios_analysis_task_queue_success(self):
        # queue=True path through ios_analysis_task on the real source tree.
        app_dic = build_app_dic(self.md5, file_name='ios_src.zip')
        # initialize_app_dic sets app_path to the real uploaded zip.
        initialize_app_dic(app_dic, 'zip')
        original = settings.ASYNC_ANALYSIS
        try:
            result = ios_analysis_task(
                self.md5, app_dic, rescan=True, queue=True)
        finally:
            settings.ASYNC_ANALYSIS = original
        self.assertTrue(result)

    def test_ios_analysis_permission_denied(self):
        checksum = '3' * 32
        tmp = tempfile.mkdtemp()
        app_dic = build_app_dic(
            checksum, app_dir=tmp, file_name='ios_src.zip')
        rf = RequestFactory()
        request = rf.get('/')
        User = get_user_model()
        viewer = User.objects.create_user(
            'ios_viewer', 'ios_viewer@example.com', 'pass')
        request.user = viewer
        request.api_user = None
        resp = ios_analysis(request, app_dic, rescan=False, api=False)
        self.assertEqual(resp.status_code, 500)

    def test_ios_analysis_task_queue_exception(self):
        # queue=True + bad path -> except -> mark_task_completed('Failed').
        checksum = '5' * 32
        app_dic = build_app_dic(
            checksum, app_dir='/nonexistent/dir_y',
            app_path='/nonexistent/dir_y/bad.zip', file_name='ios_src.zip')
        original = settings.ASYNC_ANALYSIS
        try:
            result = ios_analysis_task(
                checksum, app_dic, rescan=False, queue=True)
        finally:
            settings.ASYNC_ANALYSIS = original
        self.assertTrue(result)

    def test_ios_analysis_task_exception_returns_none(self):
        # bad app_dir path -> get_size_and_hashes raises -> context None
        # (non-queue ios_analysis_task swallows and returns None).
        checksum = '4' * 32
        app_dic = build_app_dic(
            checksum, app_dir='/nonexistent/dir_x',
            app_path='/nonexistent/dir_x/bad.zip')
        result = ios_analysis_task(checksum, app_dic, rescan=False)
        self.assertIsNone(result)
