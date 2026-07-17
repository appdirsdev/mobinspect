# -*- coding: utf_8 -*-
"""Real-execution (STRICT no-mock) coverage tests for apk_downloader.

Every branch below is exercised by driving the REAL functions in
``mobinspect.MobInspect.views.apk_downloader`` with REAL sample files from the
repo-root ``test_files/`` directory, REAL tempfiles for crafted inputs
and REAL Django ORM rows (RecentScansDB against the isolated SQLite
test DB). No mocks, no monkeypatch of internal logic, no fake returns.

The genuine download path (fetch_html -> find_apk_link -> download_file
-> try_provider -> add_apk success) needs live upstream APK-mirror
hosts, so those success branches are intentionally left as ceiling-gap.
Where the network is touched at all here it is only to drive a REAL
socket that fails fast (connection refused to 127.0.0.1:1), exercising
the real exception paths -- never a faked/mocked response.
"""
import os
import shutil
import tempfile
from pathlib import Path

from django.conf import settings
from django.test import TestCase

from mobinspect.MobInspect.views import apk_downloader as ad
from mobinspect.StaticAnalyzer.models import RecentScansDB


# settings.BASE_DIR points at the inner ``mobinspect`` package dir; the sample
# files live in ``test_files/`` at the actual repository root one level up.
REPO_ROOT = os.path.dirname(settings.BASE_DIR)
TEST_FILES = os.path.join(REPO_ROOT, 'test_files')
REAL_APK = os.path.join(TEST_FILES, 'android.apk')
REAL_XAPK = os.path.join(TEST_FILES, 'android_xapk.xapk')

# A local address that refuses connections instantly (port 1) so the real
# requests call raises and we hit the genuine exception branch fast.
DEAD_URL = 'http://127.0.0.1:1/nope.apk'


class GetScanTypeTests(TestCase):
    """get_scan_type inspects a REAL zip's namelist."""

    def test_plain_apk_returns_apk(self):
        # android.apk is a zip with no nested *.apk entries.
        self.assertEqual(ad.get_scan_type(REAL_APK), 'apk')

    def test_xapk_with_nested_apk_returns_apks(self):
        # android_xapk.xapk really contains multiple *.apk members.
        self.assertEqual(ad.get_scan_type(REAL_XAPK), 'apks')


class AddApkTests(TestCase):
    """add_apk: both the magic-check reject and the full success path."""

    def _cleanup(self, md5):
        anal_dir = os.path.join(settings.UPLD_DIR, md5)
        if os.path.isdir(anal_dir):
            shutil.rmtree(anal_dir, ignore_errors=True)

    def test_non_zip_file_rejected(self):
        # A real tempfile that is NOT a zip -> is_zip_magic False -> None.
        with tempfile.NamedTemporaryFile(
                suffix='.apk', delete=False) as tf:
            tf.write(b'this is definitely not a zip archive')
            path = Path(tf.name)
        try:
            self.assertIsNone(ad.add_apk(path, 'notzip.apk'))
        finally:
            path.unlink(missing_ok=True)

    def test_real_apk_success_creates_recent_scan(self):
        # Drive the full success branch with the real APK: it is written
        # to UPLD_DIR, scan_type computed and a real RecentScansDB row made.
        before = RecentScansDB.objects.count()
        data = ad.add_apk(Path(REAL_APK), 'com.real.sample.apk')
        self.assertIsNotNone(data)
        self.assertEqual(data['analyzer'], 'static_analyzer')
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['scan_type'], 'apk')
        self.assertEqual(data['file_name'], 'com.real.sample.apk')
        md5 = data['hash']
        self.addCleanup(self._cleanup, md5)
        # Real file landed on disk.
        apk_path = os.path.join(settings.UPLD_DIR, md5, f'{md5}.apk')
        self.assertTrue(os.path.isfile(apk_path))
        # Real ORM row created.
        self.assertEqual(RecentScansDB.objects.count(), before + 1)
        row = RecentScansDB.objects.get(MD5=md5)
        self.assertEqual(row.FILE_NAME, 'com.real.sample.apk')
        self.assertEqual(row.SCAN_TYPE, 'apk')


class NetworkExceptionPathTests(TestCase):
    """Real socket failures drive the genuine exception/None branches."""

    def test_fetch_html_returns_none_on_failure(self):
        self.assertIsNone(ad.fetch_html(DEAD_URL))

    def test_download_file_returns_none_on_failure(self):
        out = Path(tempfile.gettempdir()) / 'cov_dl_should_not_exist.apk'
        self.assertIsNone(ad.download_file(DEAD_URL, out))
        self.assertFalse(out.exists())

    def test_find_apk_link_none_when_no_html(self):
        # fetch_html fails -> bsp is None -> find_apk_link returns None.
        self.assertIsNone(ad.find_apk_link(DEAD_URL, 'dead.example'))


class ApkDownloadValidationTests(TestCase):
    """apk_download early-exit validation with real invalid inputs.

    Depending on whether the sandbox has outbound internet, this exercises
    either the 'internet not available' guard or the strict package-name /
    path-traversal guard. Both real branches return None for these inputs.
    """

    def test_invalid_package_name_returns_none(self):
        # Contains characters disallowed by strict_package_check.
        self.assertIsNone(ad.apk_download('not a valid package!!'))

    def test_path_traversal_package_returns_none(self):
        self.assertIsNone(ad.apk_download('..%2f..%2fetc%2fpasswd'))

    def test_empty_package_returns_none(self):
        self.assertIsNone(ad.apk_download(''))
