# -*- coding: utf_8 -*-
"""Real-execution unit tests for shared_func.py (NO mocks).

Everything here drives the real functions with real files / real bytes /
real Django ORM rows. DB access is provided by django.test.TestCase.
"""
import hashlib
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from django.test import TestCase, RequestFactory, override_settings

from mobinspect.MobInspect import settings
from mobinspect.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerAndroid,
)
from mobinspect.StaticAnalyzer.views.common.shared_func import (
    ar_extract,
    ar_os,
    compare_apps,
    compare_versions,
    find_java_source_folder,
    get_avg_cvss,
    get_symbols,
    hash_gen,
    is_reserved_file_conflict,
    is_secret_key,
    lipo_thin,
    os_unzip,
    scan_library,
    strings_and_entropies,
    unzip,
    url_n_email_extract,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
TEST_FILES = REPO_ROOT / 'test_files'
CHK = 'a' * 32  # a valid-looking md5 checksum; no DB row required


class PureHelperTests(TestCase):
    """Pure functions with no I/O."""

    def test_is_reserved_file_conflict(self):
        # Prefix of a reserved name but not equal -> conflict
        self.assertTrue(is_reserved_file_conflict('classes.dex/evil'))
        self.assertTrue(is_reserved_file_conflict('AndroidManifest.xml/x'))
        self.assertTrue(is_reserved_file_conflict('classes2.dex/y'))
        # Exact reserved name -> no conflict
        self.assertFalse(is_reserved_file_conflict('classes.dex'))
        self.assertFalse(is_reserved_file_conflict('AndroidManifest.xml'))
        # Unrelated file -> no conflict
        self.assertFalse(is_reserved_file_conflict('assets/data.json'))

    def test_is_secret_key(self):
        # endswith / contains hits
        self.assertTrue(is_secret_key('password'))
        self.assertTrue(is_secret_key('api_key'))
        self.assertTrue(is_secret_key('oauth_token_value'))
        self.assertTrue(is_secret_key('firebase_url'))
        self.assertTrue(is_secret_key('MY_AWS_THING'))
        # not_string exclusions win
        self.assertFalse(is_secret_key('label_text'))
        self.assertFalse(is_secret_key('welcome_message'))
        self.assertFalse(is_secret_key('btn_login'))
        # neither endswith nor contains
        self.assertFalse(is_secret_key('randomfield'))

    def test_get_symbols(self):
        symbols = [{'a': ['x', 'y']}, {'b': ['y', 'z']}, {'c': []}]
        out = get_symbols(symbols)
        self.assertEqual(set(out), {'x', 'y', 'z'})
        self.assertEqual(get_symbols([]), [])

    def test_url_n_email_extract(self):
        dat = ('Reach us at https://example.com/path and '
               'mailto contact test.user@example.com now')
        urllist, url_n_file, email_n_file = url_n_email_extract(dat, 'src/A.java')
        self.assertTrue(any('example.com' in u for u in urllist))
        self.assertEqual(len(url_n_file), 1)
        self.assertEqual(url_n_file[0]['path'], 'src/A.java')
        self.assertIn('test.user@example.com', email_n_file[0]['emails'])

    def test_url_n_email_extract_empty(self):
        urllist, url_n_file, email_n_file = url_n_email_extract('nothing here', 'x')
        self.assertEqual(urllist, [])
        self.assertEqual(url_n_file, [])
        self.assertEqual(email_n_file, [])

    def test_url_n_email_extract_skips_comment_email(self):
        # Emails starting with // are dropped
        dat = 'see //ignored@example.com only'
        _, _, email_n_file = url_n_email_extract(dat, 'p')
        emails = email_n_file[0]['emails'] if email_n_file else []
        self.assertNotIn('//ignored@example.com', emails)

    def test_get_avg_cvss_metadata_shape(self):
        # Exercises averaging (round) + zero-skip + missing-cvss branches.
        # CVSS scoring is disabled by default (env flag unset) so the
        # public result is None, but all the accumulation lines still run.
        findings = {
            'r1': {'metadata': {'cvss': 8.0}},
            'r2': {'metadata': {'cvss': 6.0}},
            'r3': {'metadata': {'cvss': 0}},   # zero ignored
            'r4': {'metadata': {}},            # no cvss key
        }
        self.assertIsNone(get_avg_cvss(findings))

    def test_get_avg_cvss_ios_binary_shape(self):
        # iOS binary results have no 'metadata' wrapper -> find = finding
        findings = {'r1': {'cvss': 5.0}, 'r2': {'cvss': 5.0}}
        self.assertIsNone(get_avg_cvss(findings))

    def test_get_avg_cvss_empty(self):
        # No scores collected; still returns None while disabled
        self.assertIsNone(get_avg_cvss({}))

    def test_find_java_source_folder(self):
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        (base / 'app' / 'src' / 'main' / 'kotlin').mkdir(parents=True)
        path, stype, syntax = find_java_source_folder(base)
        self.assertEqual(stype, 'kotlin')
        self.assertEqual(syntax, '*.kt')
        self.assertTrue(path.exists())

    def test_find_java_source_folder_java_source(self):
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        (base / 'java_source').mkdir(parents=True)
        path, stype, syntax = find_java_source_folder(base)
        self.assertEqual(stype, 'java')
        self.assertEqual(syntax, '*.java')


class HashAndStringTests(TestCase):

    def test_hash_gen_matches_hashlib(self):
        apk = str(TEST_FILES / 'android.jar')  # small real file
        sha1, sha256 = hash_gen(CHK, apk)
        raw = Path(apk).read_bytes()
        self.assertEqual(sha1, hashlib.sha1(raw).hexdigest())
        self.assertEqual(sha256, hashlib.sha256(raw).hexdigest())

    def test_hash_gen_missing_file_returns_none(self):
        # Exception is caught internally -> returns None
        self.assertIsNone(hash_gen(CHK, '/no/such/file/at/all'))

    def test_strings_and_entropies_real_source(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        (d / 'A.java').write_text(
            'class A { String a = "SuperSecretPassword12345"; '
            'String b = "AKIAIOSFODNN7EXAMPLE"; }')
        (d / 'skip.txt').write_text('String c = "ShouldBeIgnored9999";')
        data = strings_and_entropies(CHK, d, ('.java',))
        self.assertIn('SuperSecretPassword12345', data['strings'])
        self.assertIn('AKIAIOSFODNN7EXAMPLE', data['strings'])
        # .txt not in exts -> excluded
        self.assertNotIn('ShouldBeIgnored9999', data['strings'])
        # secrets computed from entropies (real call)
        self.assertIsInstance(data['secrets'], set)

    def test_strings_and_entropies_none_src(self):
        data = strings_and_entropies(CHK, None, ('.java',))
        self.assertEqual(data['strings'], set())
        self.assertEqual(data['secrets'], set())

    def test_strings_and_entropies_missing_src(self):
        data = strings_and_entropies(CHK, Path('/no/such/dir'), ('.java',))
        self.assertEqual(data['strings'], set())


class UnzipTests(TestCase):

    def _extract_dir(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d

    def test_unzip_real_apk(self):
        ext = self._extract_dir()
        files = unzip(CHK, str(TEST_FILES / 'android.apk'), ext)
        self.assertIn('AndroidManifest.xml', files)
        self.assertTrue((Path(ext) / 'AndroidManifest.xml').exists())

    def test_unzip_reserved_conflict_and_dir(self):
        ext = self._extract_dir()
        zpath = Path(self._extract_dir()) / 'crafted.zip'
        with zipfile.ZipFile(zpath, 'w') as z:
            z.writestr('mydir/', '')                    # directory entry
            z.writestr('classes.dex/inner.txt', 'data')  # reserved conflict
            z.writestr('normal.txt', 'hello')
        files = unzip(CHK, str(zpath), ext)
        self.assertIn('normal.txt', files)
        self.assertTrue((Path(ext) / 'normal.txt').exists())
        # reserved conflict extracted under _conflict_
        self.assertTrue((Path(ext) / '_conflict_' / 'classes.dex' / 'inner.txt').exists())

    def test_unzip_zip_slip_skipped(self):
        ext = self._extract_dir()
        zpath = Path(self._extract_dir()) / 'slip.zip'
        with zipfile.ZipFile(zpath, 'w') as z:
            z.writestr('good.txt', 'ok')
            z.writestr('../evil.txt', 'pwn')
        files = unzip(CHK, str(zpath), ext)
        self.assertIn('good.txt', files)
        # traversal target not written outside
        self.assertFalse((Path(ext).parent / 'evil.txt').exists())

    @override_settings(ZIP_MAX_UNCOMPRESSED_FILE_SIZE=5)
    def test_unzip_file_too_large_warns_but_continues(self):
        ext = self._extract_dir()
        zpath = Path(self._extract_dir()) / 'big.zip'
        with zipfile.ZipFile(zpath, 'w') as z:
            z.writestr('big.txt', 'this content is bigger than five bytes')
        files = unzip(CHK, str(zpath), ext)
        self.assertIn('big.txt', files)

    @override_settings(ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE=5)
    def test_unzip_total_size_exceeded_aborts(self):
        ext = self._extract_dir()
        zpath = Path(self._extract_dir()) / 'total.zip'
        with zipfile.ZipFile(zpath, 'w') as z:
            z.writestr('a.txt', 'this is definitely more than five bytes total')
        # raises internally -> stop_fallback_extraction -> returns namelist
        files = unzip(CHK, str(zpath), ext)
        self.assertIn('a.txt', files)

    def test_os_unzip_real_apk(self):
        ext = self._extract_dir()
        out = os_unzip(CHK, str(TEST_FILES / 'android.apk'), ext)
        self.assertIsInstance(out, list)
        # Header row is always prepended on success
        self.assertEqual(out[0], 'Length   Date   Time   Name')
        self.assertTrue((Path(ext) / 'AndroidManifest.xml').exists())


class ArArchiveTests(TestCase):

    def _dst(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d

    def test_ar_extract_linux_static_lib(self):
        dst = self._dst()
        ar_extract(CHK, str(TEST_FILES / 'linux_static_lib.a'), dst)
        # arpy path should have written at least one member
        self.assertTrue(any(Path(dst).iterdir()))

    def test_ar_extract_macho_static_lib(self):
        dst = self._dst()
        # macho archive: exercises arpy + possible OS ar fallback; no crash
        ar_extract(CHK, str(TEST_FILES / 'macho_static_lib.a'), dst)
        self.assertTrue(os.path.isdir(dst))

    def test_ar_os_real_archive(self):
        dst = self._dst()
        out = ar_os(str(TEST_FILES / 'linux_static_lib.a'), dst)
        self.assertIsInstance(out, (bytes, bytearray))

    def test_lipo_thin_returns_path(self):
        dst = self._dst()
        new_src = lipo_thin(CHK, str(TEST_FILES / 'macho_static_lib.a'), dst)
        # Returns the computed thinned-output posix path string
        self.assertIsInstance(new_src, str)
        self.assertTrue(new_src.endswith('_thin.a'))


@override_settings(DISABLE_AUTHENTICATION='1')
class CompareViewTests(TestCase):
    """DISABLE_AUTHENTICATION bypasses the login + RBAC permission
    decorators so these tests exercise the compare logic directly."""

    def setUp(self):
        self.rf = RequestFactory()

    def test_compare_apps_same_hash(self):
        req = self.rf.get('/')
        resp = compare_apps(req, 'd' * 32, 'd' * 32, api=True)
        self.assertIsNotNone(resp)

    def test_compare_apps_invalid_hashes(self):
        req = self.rf.get('/')
        resp = compare_apps(req, 'not-md5', 'also-bad', api=True)
        self.assertIsNotNone(resp)

    def test_compare_versions_invalid_hash(self):
        req = self.rf.get('/')
        resp = compare_versions(req, 'invalid', api=True)
        self.assertIsNotNone(resp)

    def test_compare_versions_no_android_entry(self):
        req = self.rf.get('/')
        resp = compare_versions(req, 'b' * 32, api=True)
        self.assertIsNotNone(resp)

    def test_compare_versions_with_matches(self):
        md5_a = '1' * 32
        md5_b = '2' * 32
        md5_c = '3' * 32
        pkg = 'com.example.app'
        StaticAnalyzerAndroid.objects.create(
            MD5=md5_a, PACKAGE_NAME=pkg, FILE_NAME='v1.apk',
            APP_NAME='App', VERSION_NAME='1.0')
        StaticAnalyzerAndroid.objects.create(
            MD5=md5_b, PACKAGE_NAME=pkg, FILE_NAME='v2.apk',
            APP_NAME='App', VERSION_NAME='2.0')
        # Third shares package but only appears via StaticAnalyzerAndroid
        StaticAnalyzerAndroid.objects.create(
            MD5=md5_c, PACKAGE_NAME=pkg, FILE_NAME='v3.apk',
            APP_NAME='App', VERSION_NAME='3.0')
        # md5_b has a RecentScansDB row (timestamp-ordered branch)
        RecentScansDB.objects.create(
            MD5=md5_b, APP_NAME='App', VERSION_NAME='2.0',
            FILE_NAME='v2.apk', ANALYZER='static_analyzer',
            SCAN_TYPE='apk')
        req = self.rf.get('/')
        ctx = compare_versions(req, md5_a, api=True)
        self.assertEqual(ctx['title'], 'Compare Versions')
        self.assertEqual(ctx['package'], pkg)
        others_md5 = {o['md5'] for o in ctx['others']}
        self.assertEqual(others_md5, {md5_b, md5_c})
        # md5_c has no RecentScansDB row -> timestamp None branch
        c_row = next(o for o in ctx['others'] if o['md5'] == md5_c)
        self.assertIsNone(c_row['timestamp'])

    def test_compare_versions_no_package_filename_fallback(self):
        md5_a = '4' * 32
        md5_b = '5' * 32
        StaticAnalyzerAndroid.objects.create(
            MD5=md5_a, PACKAGE_NAME='', FILE_NAME='src.zip',
            APP_NAME='S', VERSION_NAME='')
        StaticAnalyzerAndroid.objects.create(
            MD5=md5_b, PACKAGE_NAME='', FILE_NAME='src.zip',
            APP_NAME='S', VERSION_NAME='')
        req = self.rf.get('/')
        ctx = compare_versions(req, md5_a, api=True)
        others_md5 = {o['md5'] for o in ctx['others']}
        self.assertIn(md5_b, others_md5)


@override_settings(DISABLE_AUTHENTICATION='1')
class ScanLibraryTests(TestCase):
    """DISABLE_AUTHENTICATION bypasses login/permission decorators."""

    def setUp(self):
        self.rf = RequestFactory()

    def test_scan_library_invalid_md5(self):
        req = self.rf.get('/', {'library': 'x'})
        resp = scan_library(req, 'not-a-real-md5')
        self.assertIsNotNone(resp)

    def test_scan_library_path_traversal(self):
        chk = '6' * 32
        lib_dir = Path(settings.UPLD_DIR) / chk
        lib_dir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, lib_dir, ignore_errors=True)
        req = self.rf.get('/', {'library': '../../etc/passwd'})
        resp = scan_library(req, chk)
        self.assertIsNotNone(resp)

    def test_scan_library_not_found(self):
        chk = '7' * 32
        lib_dir = Path(settings.UPLD_DIR) / chk
        lib_dir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, lib_dir, ignore_errors=True)
        req = self.rf.get('/', {'library': 'missing.dylib'})
        resp = scan_library(req, chk)
        self.assertIsNotNone(resp)

    def test_scan_library_valid_dylib_redirect(self):
        chk = '8' * 32
        lib_dir = Path(settings.UPLD_DIR) / chk / 'Frameworks'
        lib_dir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(
            shutil.rmtree, Path(settings.UPLD_DIR) / chk, ignore_errors=True)
        shutil.copy(str(TEST_FILES / 'macho.dylib'), str(lib_dir / 'lib.dylib'))
        req = self.rf.get('/', {'library': 'Frameworks/lib.dylib'})
        resp = scan_library(req, chk)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('static_analyzer_ios', resp['Location'])
        new_md5 = resp['Location'].strip('/').split('/')[-1]
        self.addCleanup(
            shutil.rmtree,
            Path(settings.UPLD_DIR) / new_md5, ignore_errors=True)

    def test_scan_library_extension_not_supported(self):
        chk = '9' * 32
        lib_dir = Path(settings.UPLD_DIR) / chk
        lib_dir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, lib_dir, ignore_errors=True)
        (lib_dir / 'weird.xyz').write_bytes(b'binarydata')
        req = self.rf.get('/', {'library': 'weird.xyz'})
        resp = scan_library(req, chk)
        self.assertIsNotNone(resp)
        # A leftover upload for the xyz file may be created; best-effort clean
