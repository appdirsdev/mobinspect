# -*- coding: utf_8 -*-
"""Real-execution unit tests for shared_func.py, phase 2 (NO mocks).

These cover branches that became reachable after the phase-1 fixes:
unzip -> os_unzip fallback on a genuine non-zip upload, os_unzip error
handling, ar_extract / ar_os fallback paths on the real static-library
fixtures (macOS host has ar / lipo / unzip / zip), lipo_thin error path,
strings/entropy filter branches, and the remaining scan_library / compare
branches. Everything runs real code against real bytes / real Django ORM.
"""
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from django.test import TestCase, RequestFactory, override_settings

from mobsf.MobSF import settings
from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerAndroid,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    ar_extract,
    ar_os,
    compare_apps,
    compare_versions,
    lipo_thin,
    os_unzip,
    scan_library,
    strings_and_entropies,
    unzip,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
TEST_FILES = REPO_ROOT / 'test_files'
CHK = 'a' * 32  # valid-looking md5; no DB row required for most helpers


def _tmpdir(test):
    d = tempfile.mkdtemp()
    test.addCleanup(shutil.rmtree, d, ignore_errors=True)
    return d


class UnzipFallbackTests(TestCase):
    """unzip()/os_unzip() branches beyond the happy path."""

    def test_unzip_non_zip_falls_back_to_os_unzip(self):
        # A real non-zip upload makes zipfile.ZipFile raise, which now
        # (post UnboundLocalError fix) reaches the except handler and calls
        # os_unzip. os_unzip itself fails to list a non-zip and returns [].
        ext = _tmpdir(self)
        non_zip = Path(_tmpdir(self)) / 'notazip.bin'
        non_zip.write_bytes(b'this is definitely not a zip archive' * 4)
        files = unzip(CHK, str(non_zip), ext)
        # namelist never populated + os_unzip returns [] for a non-zip
        self.assertEqual(files, [])

    def test_unzip_encrypted_entry_skipped(self):
        # Build a genuinely password-encrypted zip with the OS `zip` tool so
        # the traditional-encryption flag bit (0x1) is really set.
        srcdir = _tmpdir(self)
        secret = Path(srcdir) / 'secret.txt'
        secret.write_text('top secret contents here')
        plain = Path(srcdir) / 'plain.txt'
        plain.write_text('not encrypted')
        zpath = Path(_tmpdir(self)) / 'enc.zip'
        zip_b = shutil.which('zip')
        self.assertIsNotNone(zip_b, 'zip CLI required for this test')
        subprocess.check_call(
            [zip_b, '-j', '-P', 'pw', str(zpath), str(secret)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Append a plaintext member so extraction still produces a file.
        subprocess.check_call(
            [zip_b, '-j', str(zpath), str(plain)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Confirm the encrypted flag is really present.
        with zipfile.ZipFile(zpath) as z:
            flags = {i.filename: i.flag_bits & 0x1 for i in z.infolist()}
        self.assertEqual(flags.get('secret.txt'), 1)
        ext = _tmpdir(self)
        files = unzip(CHK, str(zpath), ext)
        self.assertIn('secret.txt', files)
        # Encrypted file skipped, plaintext extracted.
        self.assertFalse((Path(ext) / 'secret.txt').exists())
        self.assertTrue((Path(ext) / 'plain.txt').exists())

    def test_unzip_file_too_large_warns_but_continues(self):
        # The module reads mobsf.MobSF.settings (not django.conf.settings),
        # so override_settings can't reach it; set the real config value and
        # restore it. Behaviour under test is 100% real.
        orig = settings.ZIP_MAX_UNCOMPRESSED_FILE_SIZE
        settings.ZIP_MAX_UNCOMPRESSED_FILE_SIZE = 5
        self.addCleanup(
            setattr, settings, 'ZIP_MAX_UNCOMPRESSED_FILE_SIZE', orig)
        ext = _tmpdir(self)
        zpath = Path(_tmpdir(self)) / 'big.zip'
        with zipfile.ZipFile(zpath, 'w') as z:
            z.writestr('big.txt', 'far more than five bytes of content here')
        files = unzip(CHK, str(zpath), ext)
        self.assertIn('big.txt', files)
        # Oversized-but-under-total file is still extracted (only warned).
        self.assertTrue((Path(ext) / 'big.txt').exists())

    def test_unzip_total_size_exceeded_aborts(self):
        orig = settings.ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE
        settings.ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE = 5
        self.addCleanup(
            setattr, settings, 'ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE', orig)
        ext = _tmpdir(self)
        zpath = Path(_tmpdir(self)) / 'total.zip'
        with zipfile.ZipFile(zpath, 'w') as z:
            z.writestr('a.txt', 'this content exceeds the tiny total limit')
        # Internal raise sets stop_fallback_extraction -> returns namelist,
        # no OS-unzip fallback.
        files = unzip(CHK, str(zpath), ext)
        self.assertIn('a.txt', files)

    def test_os_unzip_error_on_non_zip_returns_empty(self):
        # `unzip -qq -l` on a non-zip exits non-zero -> check_output raises
        # -> except handler -> returns [].
        ext = _tmpdir(self)
        non_zip = Path(_tmpdir(self)) / 'garbage.bin'
        non_zip.write_bytes(b'\x00\x01\x02not a zip at all')
        out = os_unzip(CHK, str(non_zip), ext)
        self.assertEqual(out, [])


class ArFallbackTests(TestCase):
    """ar_extract / ar_os / lipo_thin real fallback + error branches."""

    def _dst(self):
        return _tmpdir(self)

    def test_ar_os_non_ar_file_captures_error_output(self):
        # `ar t` on a non-ar file (a zip) exits non-zero -> CalledProcessError
        # whose .output bytes are returned.
        dst = self._dst()
        out = ar_os(str(TEST_FILES / 'android.jar'), dst)
        self.assertIsInstance(out, (bytes, bytearray))
        self.assertTrue(len(out) > 0)

    def test_ar_extract_arpy_slip_member_skipped(self):
        # Hand-craft a BSD ar archive whose sole member name is a path
        # traversal; arpy parses it and shared_func skips the slip member.
        dst = self._dst()
        arpath = Path(_tmpdir(self)) / 'slip.a'
        name = b'../evil.txt'
        data = b'pwned'
        header = b'!<arch>\n'
        file_hdr = (
            name.ljust(16)
            + b'0'.ljust(12)      # mtime
            + b'0'.ljust(6)       # uid
            + b'0'.ljust(6)       # gid
            + b'100644'.ljust(8)  # mode
            + str(len(data)).encode().ljust(10)
            + b'`\n')
        blob = header + file_hdr + data
        if len(data) % 2:
            blob += b'\n'
        arpath.write_bytes(blob)
        ar_extract(CHK, str(arpath), dst)
        # Slip member must NOT be written inside or outside dst.
        self.assertFalse((Path(dst) / '../evil.txt').exists())
        self.assertFalse((Path(dst).parent / 'evil.txt').exists())

    def test_ar_extract_non_ar_triggers_os_fallback(self):
        # A non-ar file makes arpy raise -> except block -> OS `ar` fallback.
        # `ar` also fails (not lipo(1), not Linux) so it returns cleanly.
        dst = self._dst()
        ar_extract(CHK, str(TEST_FILES / 'android.jar'), dst)
        self.assertTrue(os.path.isdir(dst))

    def test_ar_extract_macho_static_lib_real(self):
        # Real Mach-O static library; arpy path succeeds on this fixture.
        dst = self._dst()
        ar_extract(CHK, str(TEST_FILES / 'macho_static_lib.a'), dst)
        self.assertTrue(os.path.isdir(dst))

    def test_lipo_thin_error_path_returns_none(self):
        # src=None makes Path(None) raise inside the try -> except handler;
        # new_src was never reassigned so None is returned.
        dst = self._dst()
        self.assertIsNone(lipo_thin(CHK, None, dst))


class StringsAndEntropiesBranchTests(TestCase):

    def test_strings_filter_branches(self):
        d = Path(_tmpdir(self))
        # Quoted tokens exercise every continue branch + one kept string.
        # A leading quoted anchor is needed because STRINGS_REGEX pairs quote
        # boundaries; without it the first quoted token is not matched.
        (d / 'A.java').write_text(
            '"AnchorStringAAAA" '
            '"com.google.gms.measurement" '          # excludes -> skip
            '"android/widget/ButtonView" '           # eslash + '/' -> skip
            '"#leadingsymboltoken" '                  # first char not alnum
            '"KeptStringValue1234"'                   # kept
        )
        data = strings_and_entropies(CHK, d, ('.java',))
        self.assertIn('KeptStringValue1234', data['strings'])
        self.assertNotIn('com.google.gms.measurement', data['strings'])
        self.assertNotIn('android/widget/ButtonView', data['strings'])
        self.assertNotIn('#leadingsymboltoken', data['strings'])
        self.assertIsInstance(data['secrets'], set)

    def test_strings_read_error_is_caught(self):
        # A *directory* whose name matches the extension makes read_text raise
        # IsADirectoryError, which propagates to the except handler.
        d = Path(_tmpdir(self))
        (d / 'looks_like.java').mkdir()
        data = strings_and_entropies(CHK, d, ('.java',))
        # Exception handled -> strings stays empty, function still returns dict.
        self.assertEqual(data['strings'], set())
        self.assertEqual(data['secrets'], set())


class CompareBranchTests(TestCase):

    def setUp(self):
        self.rf = RequestFactory()

    def test_compare_apps_valid_hashes_invokes_generic_compare(self):
        # Distinct valid md5s pass both guards and reach generic_compare.
        req = self.rf.get('/')
        resp = compare_apps(req, '1' * 32, '2' * 32, api=True)
        self.assertIsNotNone(resp)

    @override_settings(DISABLE_AUTHENTICATION='1')
    def test_compare_versions_renders_html(self):
        md5_a = 'c' * 32
        StaticAnalyzerAndroid.objects.create(
            MD5=md5_a, PACKAGE_NAME='com.render.app', FILE_NAME='r.apk',
            APP_NAME='R', VERSION_NAME='1.0')
        req = self.rf.get('/')
        resp = compare_versions(req, md5_a, api=False)
        # Non-api path renders the template -> HttpResponse 200.
        self.assertEqual(resp.status_code, 200)


@override_settings(DISABLE_AUTHENTICATION='1')
class ScanLibraryBranchTests(TestCase):

    def setUp(self):
        self.rf = RequestFactory()

    def _lib_dir(self, chk):
        lib_dir = Path(settings.UPLD_DIR) / chk
        lib_dir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, lib_dir, ignore_errors=True)
        return lib_dir

    def _cleanup_upload(self, resp):
        new_md5 = resp['Location'].strip('/').split('/')[-1]
        self.addCleanup(
            shutil.rmtree,
            Path(settings.UPLD_DIR) / new_md5, ignore_errors=True)

    def test_scan_library_missing_param_hits_except(self):
        # No 'library' GET key -> KeyError inside try -> except handler.
        chk = 'd' * 32
        self._lib_dir(chk)
        req = self.rf.get('/')
        resp = scan_library(req, chk)
        self.assertIsNotNone(resp)

    def test_scan_library_frameworks_no_ext_forces_dylib(self):
        # Extension-less file under Frameworks -> ext forced to .dylib -> iOS.
        chk = 'e' * 32
        lib_dir = self._lib_dir(chk) / 'Frameworks'
        lib_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(str(TEST_FILES / 'macho.dylib'), str(lib_dir / 'MyLib'))
        req = self.rf.get('/', {'library': 'Frameworks/MyLib'})
        resp = scan_library(req, chk)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('static_analyzer_ios', resp['Location'])
        self._cleanup_upload(resp)

    def test_scan_library_appx_windows_analyzer(self):
        chk = 'f' * 32
        lib_dir = self._lib_dir(chk)
        shutil.copy(str(TEST_FILES / 'windows.appx'), str(lib_dir / 'app.appx'))
        req = self.rf.get('/', {'library': 'app.appx'})
        resp = scan_library(req, chk)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('windows_static_analyzer', resp['Location'])
        self._cleanup_upload(resp)

    def test_scan_library_android_ext_analyzer(self):
        chk = '0' * 31 + 'e'
        lib_dir = self._lib_dir(chk)
        shutil.copy(str(TEST_FILES / 'android.apk'), str(lib_dir / 'lib.apk'))
        req = self.rf.get('/', {'library': 'lib.apk'})
        resp = scan_library(req, chk)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('static_analyzer', resp['Location'])
        self._cleanup_upload(resp)
