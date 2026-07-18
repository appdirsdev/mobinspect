# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage tests for apk.py.

Drives initialize_app_dic/get_size_and_hashes/print_scan_subject/clean_up,
the eclipse/studio/iOS source-type detectors, and the apk/src analysis task
+ view wrappers with real files, real permission checks (RequestFactory +
real users), and real fault injection (missing keys/files) for the error
branches -- no mocking.
"""
import shutil
import tempfile
import zipfile
from pathlib import Path

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, TestCase, override_settings

from mobinspect.StaticAnalyzer.views.android.apk import (
    apk_analysis,
    apk_analysis_task,
    clean_up,
    get_size_and_hashes,
    initialize_app_dic,
    is_android_source,
    move_to_parent,
    print_scan_subject,
    src_analysis,
    src_analysis_task,
    valid_source_code,
)
from mobinspect.StaticAnalyzer.views.common.shared_func import unzip

REPO_ROOT = Path(__file__).resolve().parents[4]
TEST_FILES = REPO_ROOT / 'test_files'
TOOLS_DIR = (REPO_ROOT / 'mobinspect' / 'StaticAnalyzer' / 'tools').as_posix()
APK_SAMPLE = TEST_FILES / 'android.apk'
SRC_ZIP_SAMPLE = TEST_FILES / 'android_src.zip'


def _staff_request(factory, method='post', path='/', data=None):
    req = getattr(factory, method)(path, data or {})
    User = get_user_model()
    user, _ = User.objects.get_or_create(
        username='cov_apk_staff',
        defaults={'is_staff': True, 'is_superuser': True})
    req.user = user
    return req


def _anon_request(factory, method='post', path='/', data=None):
    req = getattr(factory, method)(path, data or {})
    req.user = AnonymousUser()
    return req


class InitializeAppDicTests(TestCase):

    def test_sets_paths_and_returns_checksum(self):
        tmp = Path(tempfile.mkdtemp())
        app_dic = {'md5': 'abc123', 'app_dir': tmp}
        checksum = initialize_app_dic(app_dic, 'apk')
        self.assertEqual(checksum, 'abc123')
        self.assertEqual(app_dic['app_file'], 'abc123.apk')
        self.assertTrue(app_dic['app_dir'].endswith('/'))
        self.assertTrue(app_dic['app_path'].endswith('abc123.apk'))
        shutil.rmtree(tmp, ignore_errors=True)


class GetSizeAndHashesTests(TestCase):

    def test_real_file_size_and_hash(self):
        tmp = tempfile.mkdtemp()
        f = Path(tmp) / 'x.apk'
        f.write_bytes(b'hello world' * 1000)
        app_dic = {'md5': 'q', 'app_path': f.as_posix()}
        get_size_and_hashes(app_dic)
        self.assertTrue(app_dic['size'].endswith('MB'))
        self.assertEqual(len(app_dic['sha1']), 40)
        self.assertEqual(len(app_dic['sha256']), 64)
        shutil.rmtree(tmp, ignore_errors=True)


class CleanUpTests(TestCase):

    def test_resets_androguard_fields(self):
        app_dic = {
            'androguard_apk': object(),
            'androguard_apk_resources': object(),
        }
        clean_up(app_dic)
        self.assertIsNone(app_dic['androguard_apk'])
        self.assertIsNone(app_dic['androguard_apk_resources'])


class PrintScanSubjectTests(TestCase):
    """Every branch of subject resolution, including the pkg_name2
    fallback (apk_features.package) and the literal 'Failed' guard."""

    def test_pkg_name_falls_back_to_apk_features_package(self):
        app_dic = {'md5': 'ps1', 'real_name': None,
                   'apk_features': {'package': 'com.example.fallback'}}
        print_scan_subject(app_dic, {'packagename': None})
        self.assertEqual(app_dic['subject'], 'com.example.fallback')

    def test_app_name_only_subject(self):
        app_dic = {'md5': 'ps2', 'real_name': 'MyApp'}
        print_scan_subject(app_dic, {'packagename': None})
        self.assertEqual(app_dic['subject'], 'MyApp')

    def test_subject_failed_literal_gets_parenthesized(self):
        app_dic = {'md5': 'ps3', 'real_name': 'Failed'}
        print_scan_subject(app_dic, {'packagename': None})
        self.assertEqual(app_dic['subject'], '(Failed)')

    def test_both_app_name_and_pkg_name(self):
        app_dic = {'md5': 'ps4', 'real_name': 'MyApp'}
        print_scan_subject(app_dic, {'packagename': 'com.my.app'})
        self.assertEqual(app_dic['subject'], 'MyApp (com.my.app)')

    def test_neither_name_nor_pkg_defaults(self):
        app_dic = {'md5': 'ps5', 'real_name': None}
        print_scan_subject(app_dic, {'packagename': None})
        self.assertEqual(app_dic['subject'], 'Android App')


class IsAndroidSourceTests(TestCase):

    def test_eclipse_layout_detected(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / 'AndroidManifest.xml').write_text('<manifest/>')
        (tmp / 'src').mkdir()
        self.assertEqual(is_android_source(tmp), ('eclipse', True))
        shutil.rmtree(tmp, ignore_errors=True)

    def test_studio_layout_with_java_detected(self):
        tmp = Path(tempfile.mkdtemp())
        main = tmp / 'app' / 'src' / 'main'
        main.mkdir(parents=True)
        (main / 'AndroidManifest.xml').write_text('<manifest/>')
        (main / 'java').mkdir()
        self.assertEqual(is_android_source(tmp), ('studio', True))
        shutil.rmtree(tmp, ignore_errors=True)

    def test_studio_layout_with_kotlin_detected(self):
        tmp = Path(tempfile.mkdtemp())
        main = tmp / 'app' / 'src' / 'main'
        main.mkdir(parents=True)
        (main / 'AndroidManifest.xml').write_text('<manifest/>')
        (main / 'kotlin').mkdir()
        self.assertEqual(is_android_source(tmp), ('studio', True))
        shutil.rmtree(tmp, ignore_errors=True)

    def test_no_recognizable_layout(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / 'randomfile.txt').write_text('x')
        self.assertEqual(is_android_source(tmp), (None, False))
        shutil.rmtree(tmp, ignore_errors=True)


class MoveToParentTests(TestCase):

    def test_moves_contents_and_removes_source(self):
        tmp = Path(tempfile.mkdtemp())
        inside = tmp / 'inner'
        inside.mkdir()
        (inside / 'a.txt').write_text('a')
        (inside / 'b.txt').write_text('b')
        move_to_parent(inside, tmp)
        self.assertFalse(inside.exists())
        self.assertTrue((tmp / 'a.txt').exists())
        self.assertTrue((tmp / 'b.txt').exists())
        shutil.rmtree(tmp, ignore_errors=True)


class ValidSourceCodeTests(TestCase):

    def test_direct_eclipse_detected(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / 'AndroidManifest.xml').write_text('<manifest/>')
        (tmp / 'src').mkdir()
        self.assertEqual(valid_source_code('vsc1', tmp), ('eclipse', True))
        shutil.rmtree(tmp, ignore_errors=True)

    def test_relaxed_one_level_down_android_moves_to_parent(self):
        tmp = Path(tempfile.mkdtemp())
        nested = tmp / 'project-master'
        nested.mkdir()
        (nested / 'AndroidManifest.xml').write_text('<manifest/>')
        (nested / 'src').mkdir()
        result = valid_source_code('vsc2', tmp)
        self.assertEqual(result, ('eclipse', True))
        # Contents were moved up; the nested dir no longer exists.
        self.assertFalse(nested.exists())
        self.assertTrue((tmp / 'AndroidManifest.xml').exists())
        shutil.rmtree(tmp, ignore_errors=True)

    def test_top_level_ios_xcodeproj_detected(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / 'MyApp.xcodeproj').mkdir()
        self.assertEqual(valid_source_code('vsc3', tmp), ('ios', True))
        shutil.rmtree(tmp, ignore_errors=True)

    def test_relaxed_one_level_down_ios_detected(self):
        tmp = Path(tempfile.mkdtemp())
        nested = tmp / 'ios-project'
        nested.mkdir()
        (nested / 'MyApp.xcodeproj').mkdir()
        # Not moved for iOS (only Android relaxed-check moves), just detected.
        self.assertEqual(valid_source_code('vsc4', tmp), ('ios', True))
        shutil.rmtree(tmp, ignore_errors=True)

    def test_no_valid_structure_returns_empty(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / 'readme.txt').write_text('nothing here')
        self.assertEqual(valid_source_code('vsc5', tmp), ('', False))
        shutil.rmtree(tmp, ignore_errors=True)

    def test_exception_branch_nonexistent_dir(self):
        # A directory that does not exist makes Path.iterdir() raise ->
        # the except branch runs and returns None (no crash).
        result = valid_source_code('vsc6', '/nonexistent/path/for/sure')
        self.assertIsNone(result)


class ApkAnalysisTaskQueueTests(TestCase):
    """Exercise the queue=True branches (mark_task_started / mark_task_
    completed) that a synchronous (queue=False) call never reaches, plus
    the exception branches for both queue values via real fault injection
    (a required key missing from app_dic)."""

    def test_missing_required_key_queue_false_returns_error_tuple(self):
        context, err = apk_analysis_task(
            'brokenq0', {'md5': 'brokenq0'}, False, queue=False)
        self.assertIsNone(context)
        self.assertIsNotNone(err)

    @override_settings(ASYNC_ANALYSIS=False)
    def test_missing_required_key_queue_true_marks_failed(self):
        # queue=True: mark_task_started() runs first (lines 150-151), then
        # the KeyError from the missing 'app_dir'/'app_path' propagates to
        # the except branch's queue=True arm (mark_task_completed 'Failed').
        result = apk_analysis_task(
            'brokenq1', {'md5': 'brokenq1'}, False, queue=True)
        self.assertTrue(result)

    @override_settings(ASYNC_ANALYSIS=False)
    def test_full_real_apk_queue_true_marks_success(self):
        # A complete, real APK analysis run (same pipeline as the E2E
        # test) but invoked with queue=True so the success arm of the
        # queue branch (mark_task_completed 'Success') is reached too.
        tmp = Path(tempfile.mkdtemp())
        checksum = 'q' + 'e' * 31
        shutil.copy(APK_SAMPLE, tmp / f'{checksum}.apk')
        app_dic = {
            'md5': checksum,
            'app_dir': tmp,
            'tools_dir': TOOLS_DIR,
        }
        initialize_app_dic(app_dic, 'apk')
        result = apk_analysis_task(checksum, app_dic, False, queue=True)
        self.assertTrue(result)
        shutil.rmtree(tmp, ignore_errors=True)


class ApkAnalysisViewTests(TestCase):
    """apk_analysis() view-wrapper branches: permission denial, the
    ASYNC_ANALYSIS enqueue branch, and error propagation from a failed
    task -- driven with real RequestFactory requests and real users."""

    def setUp(self):
        self.factory = RequestFactory()

    def test_permission_denied_html(self):
        req = _anon_request(self.factory)
        tmp = Path(tempfile.mkdtemp())
        app_dic = {'md5': 'permden0' + '0' * 24, 'app_dir': tmp}
        resp = apk_analysis(req, app_dic, False, False)
        self.assertEqual(resp.status_code, 500)
        shutil.rmtree(tmp, ignore_errors=True)

    def test_permission_denied_api(self):
        # NB: apk_analysis() hardcodes `False` (not the `api` argument) in
        # its permission-denied print_n_send_error_response() call, so even
        # with api=True this renders the HTML error page rather than
        # returning a JSON-style error dict. Documented as a suspected
        # production bug (not fixed here); this test asserts the real,
        # current behaviour.
        req = _anon_request(self.factory)
        tmp = Path(tempfile.mkdtemp())
        app_dic = {'md5': 'permden1' + '0' * 24, 'app_dir': tmp}
        resp = apk_analysis(req, app_dic, False, True)
        self.assertEqual(resp.status_code, 500)
        shutil.rmtree(tmp, ignore_errors=True)

    @override_settings(ASYNC_ANALYSIS=True)
    def test_async_analysis_branch_enqueues(self):
        req = _staff_request(self.factory)
        tmp = Path(tempfile.mkdtemp())
        checksum = 'asyncq0' + '0' * 25
        app_dic = {'md5': checksum, 'app_dir': tmp, 'app_name': 'x.apk'}
        resp = apk_analysis(req, app_dic, False, True)
        self.assertIn('task_id', resp)
        shutil.rmtree(tmp, ignore_errors=True)

    @override_settings(ASYNC_ANALYSIS=False)
    def test_task_error_propagates_as_error_response(self):
        # Permission granted, but the app_dic is missing the keys the task
        # needs (no real apk placed at app_path) -> apk_analysis_task
        # returns an err string, which apk_analysis() must surface.
        req = _staff_request(self.factory)
        tmp = Path(tempfile.mkdtemp())
        checksum = 'taskerr0' + '0' * 25
        app_dic = {'md5': checksum, 'app_dir': tmp}
        resp = apk_analysis(req, app_dic, False, True)
        self.assertIn('error', resp)
        shutil.rmtree(tmp, ignore_errors=True)


class SrcAnalysisTaskTests(TestCase):

    def test_missing_key_queue_false_swallows_and_returns_none(self):
        # src_analysis_task's except branch (queue=False) simply returns
        # the still-None context (no re-raise), unlike apk_analysis_task.
        result = src_analysis_task(
            'srcbroken0', {'md5': 'srcbroken0'}, False, 'eclipse',
            queue=False)
        self.assertIsNone(result)

    @override_settings(ASYNC_ANALYSIS=False)
    def test_missing_key_queue_true_marks_failed(self):
        result = src_analysis_task(
            'srcbroken1', {'md5': 'srcbroken1'}, False, 'eclipse',
            queue=True)
        self.assertTrue(result)

    @override_settings(ASYNC_ANALYSIS=False)
    def test_full_real_src_analysis_queue_true_marks_success(self):
        # A complete, real Android-source-ZIP analysis run (same real
        # unzip + studio-layout pipeline as the E2E test) invoked with
        # queue=True, so the success arm of the queue branch (mark_task_
        # completed 'Success') is reached (only failure was covered above).
        tmp = Path(tempfile.mkdtemp())
        checksum = 's' + 'r' * 31
        app_dic = {'md5': checksum, 'app_dir': tmp}
        initialize_app_dic(app_dic, 'zip')
        shutil.copy(SRC_ZIP_SAMPLE, app_dic['app_path'])
        app_dic['files'] = unzip(
            checksum, app_dic['app_path'], app_dic['app_dir'])
        app_dic['tools_dir'] = TOOLS_DIR
        result = src_analysis_task(
            checksum, app_dic, False, 'studio', queue=True)
        self.assertTrue(result)
        shutil.rmtree(tmp, ignore_errors=True)


class SrcAnalysisViewTests(TestCase):

    def setUp(self):
        self.factory = RequestFactory()

    def _zip_with(self, files):
        tmp = Path(tempfile.mkdtemp())
        checksum = 'src' + 'f' * 29
        app_dir = tmp / checksum
        app_dir.mkdir()
        zpath = app_dir / f'{checksum}.zip'
        with zipfile.ZipFile(zpath, 'w') as z:
            for name, content in files.items():
                z.writestr(name, content)
        app_dic = {'md5': checksum, 'app_dir': app_dir}
        return tmp, app_dic

    def test_permission_denied(self):
        tmp, app_dic = self._zip_with({'readme.txt': b'x'})
        req = _anon_request(self.factory)
        resp = src_analysis(req, app_dic, False, False)
        self.assertEqual(resp.status_code, 500)
        shutil.rmtree(tmp, ignore_errors=True)

    @override_settings(ASYNC_ANALYSIS=True)
    def test_async_analysis_branch_for_valid_eclipse_source(self):
        tmp, app_dic = self._zip_with({
            'AndroidManifest.xml': b'<manifest/>',
            'src/Placeholder.java': b'// x',
        })
        req = _staff_request(self.factory)
        resp = src_analysis(req, app_dic, False, True)
        self.assertIn('task_id', resp)
        shutil.rmtree(tmp, ignore_errors=True)

    @override_settings(ASYNC_ANALYSIS=False)
    def test_unsupported_zip_format_api(self):
        tmp, app_dic = self._zip_with({'readme.txt': b'nothing useful'})
        req = _staff_request(self.factory)
        resp = src_analysis(req, app_dic, False, True)
        self.assertIn('error', resp)
        self.assertIn('not supported', resp['error'])
        shutil.rmtree(tmp, ignore_errors=True)

    @override_settings(ASYNC_ANALYSIS=False)
    def test_unsupported_zip_format_html(self):
        tmp, app_dic = self._zip_with({'readme.txt': b'nothing useful'})
        req = _staff_request(self.factory)
        resp = src_analysis(req, app_dic, False, False)
        self.assertEqual(resp.status_code, 200)
        shutil.rmtree(tmp, ignore_errors=True)
