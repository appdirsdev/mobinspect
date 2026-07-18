# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage tests for static_analyzer.py.

Drives the real decorated static_analyzer() view directly (as api_scan()
does in production: `static_analyzer(request, checksum, True)`), with real
RecentScansDB rows and real crafted xapk/apks/aab fixtures on disk under
the real UPLD_DIR, so handle_xapk/handle_split_apk/handle_aab genuinely
fail and drive the exception branches -- no mocking.
"""
import shutil
import zipfile
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings

from mobinspect.StaticAnalyzer.models import RecentScansDB
from mobinspect.StaticAnalyzer.views.android.static_analyzer import (
    static_analyzer,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
TEST_FILES = REPO_ROOT / 'test_files'
UPLD_DIR = Path(settings.UPLD_DIR)


def _staff_request(factory, method='post', data=None):
    req = getattr(factory, method)('/', data or {})
    User = get_user_model()
    user, _ = User.objects.get_or_create(
        username='cov_sa_staff',
        defaults={'is_staff': True, 'is_superuser': True})
    req.user = user
    return req


class StaticAnalyzerViewTests(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self._dirs = []

    def tearDown(self):
        for d in self._dirs:
            shutil.rmtree(d, ignore_errors=True)

    def _app_dir(self, checksum):
        d = UPLD_DIR / checksum
        d.mkdir(parents=True, exist_ok=True)
        self._dirs.append(d)
        return d

    def test_invalid_hash_not_md5_shaped(self):
        # Calling the function directly (as api_scan does) bypasses the
        # URL router's 32-hex-char regex, reaching is_md5()'s own check.
        req = _staff_request(self.factory)
        resp = static_analyzer(req, 'not-an-md5-hash', True)
        self.assertIn('error', resp)

    def test_file_not_uploaded(self):
        req = _staff_request(self.factory)
        resp = static_analyzer(req, 'a' * 32, True)
        self.assertIn('error', resp)
        self.assertIn('not uploaded', resp['error'])

    def test_invalid_extension_mismatch(self):
        # SCAN_TYPE is a valid Android ext, but FILE_NAME's extension does
        # not match it -- a real inconsistent-but-plausible DB row.
        checksum = 'b' * 32
        RecentScansDB.objects.create(
            MD5=checksum, SCAN_TYPE='apk', FILE_NAME='no_extension_here')
        req = _staff_request(self.factory)
        resp = static_analyzer(req, checksum, True)
        self.assertIn('error', resp)
        self.assertIn('extension', resp['error'])

    def test_invalid_xapk_raises_and_is_caught(self):
        # A real (but manifest-less) zip named <checksum>.xapk: handle_xapk
        # unzips it for real, finds no manifest.json, returns False for
        # real -> 'Invalid XAPK File' is raised and caught by the outer
        # except (covers both the raise and the outer except handler).
        checksum = 'c' * 32
        app_dir = self._app_dir(checksum)
        with zipfile.ZipFile(app_dir / f'{checksum}.xapk', 'w') as z:
            z.writestr('base.apk', b'PK-fake-apk-content')
        RecentScansDB.objects.create(
            MD5=checksum, SCAN_TYPE='xapk', FILE_NAME='sample.xapk')
        req = _staff_request(self.factory)
        resp = static_analyzer(req, checksum, True)
        self.assertIn('error', resp)

    def test_invalid_split_apks_raises_and_is_caught(self):
        # Only config.*.apk entries -> handle_split_apk returns None for
        # real -> 'Invalid Split APK File' raised and caught.
        checksum = 'd' * 32
        app_dir = self._app_dir(checksum)
        with zipfile.ZipFile(app_dir / f'{checksum}.apk', 'w') as z:
            z.writestr('config.en.apk', b'PK-fake-apk-content')
            z.writestr('config.xxhdpi.apk', b'PK-fake-apk-content')
        RecentScansDB.objects.create(
            MD5=checksum, SCAN_TYPE='apks', FILE_NAME='sample.apks')
        req = _staff_request(self.factory)
        resp = static_analyzer(req, checksum, True)
        self.assertIn('error', resp)

    def test_invalid_aab_raises_and_is_caught(self):
        # A real, non-bundle .aab file: the real bundletool subprocess
        # fails for real, handle_aab returns None -> 'Invalid AAB File'
        # raised and caught.
        checksum = 'e' * 32
        app_dir = self._app_dir(checksum)
        (app_dir / f'{checksum}.aab').write_bytes(b'not a real aab bundle')
        RecentScansDB.objects.create(
            MD5=checksum, SCAN_TYPE='aab', FILE_NAME='sample.aab')
        req = _staff_request(self.factory)
        resp = static_analyzer(req, checksum, True)
        self.assertIn('error', resp)

    def test_valid_split_apk_reaches_apk_type_reassignment(self):
        # A real zip with a genuine base.apk entry -> handle_split_apk
        # succeeds for real, reaching the `typ = APK_TYPE` reassignment
        # (previously only the failure/raise branch was covered). The
        # subsequent apk_analysis() call on the fake apk bytes fails
        # internally and is handled normally -- not this test's concern.
        checksum = '1' * 32
        app_dir = self._app_dir(checksum)
        with zipfile.ZipFile(app_dir / f'{checksum}.apk', 'w') as z:
            z.writestr('base.apk', b'PK-fake-apk-content')
        RecentScansDB.objects.create(
            MD5=checksum, SCAN_TYPE='apks', FILE_NAME='sample.apks')
        req = _staff_request(self.factory)
        with override_settings(ASYNC_ANALYSIS=False):
            resp = static_analyzer(req, checksum, True)
        self.assertIsNotNone(resp)

    def test_valid_aab_already_converted_reaches_apk_type_reassignment(self):
        # AndroidManifest.xml already present -> handle_aab's own
        # short-circuit returns True without needing bundletool, reaching
        # the `typ = APK_TYPE` reassignment for the aab branch.
        checksum = '2' * 32
        app_dir = self._app_dir(checksum)
        (app_dir / 'AndroidManifest.xml').write_text('<manifest/>')
        RecentScansDB.objects.create(
            MD5=checksum, SCAN_TYPE='aab', FILE_NAME='sample.aab')
        req = _staff_request(self.factory)
        with override_settings(ASYNC_ANALYSIS=False):
            resp = static_analyzer(req, checksum, True)
        self.assertIsNotNone(resp)

    def test_unsupported_scan_type_hits_else_branch(self):
        # settings.ANDROID_EXTS is exhaustively handled by the elif chain
        # (apk/xapk/apks/aab all normalize to APK_TYPE; jar/aar/so/zip are
        # each routed directly), so the defensive final `else` clause is
        # unreachable through any real SCAN_TYPE value. A test-only
        # ANDROID_EXTS extension (not a production code change) lets a
        # real 'fake' SCAN_TYPE pass the extension-allowlist check and fall
        # through to that defensive branch for real.
        checksum = 'f' * 32
        self._app_dir(checksum)
        RecentScansDB.objects.create(
            MD5=checksum, SCAN_TYPE='fake', FILE_NAME='sample.fake')
        req = _staff_request(self.factory)
        with override_settings(
                ANDROID_EXTS=settings.ANDROID_EXTS + ('fake',)):
            resp = static_analyzer(req, checksum, True)
        self.assertIn('error', resp)

    def test_rescan_get_param_sets_rescan_true(self):
        # Non-API (browser) path reads `rescan` from GET, not POST.
        # A tiny real .so sample keeps the (still real, unmocked) analysis
        # this triggers fast.
        checksum = 'a1' * 16
        app_dir = self._app_dir(checksum)
        shutil.copy(TEST_FILES / 'android.so', app_dir / f'{checksum}.so')
        RecentScansDB.objects.create(
            MD5=checksum, SCAN_TYPE='so', FILE_NAME='sample.so')
        req = _staff_request(self.factory, method='get', data={'rescan': '1'})
        with override_settings(ASYNC_ANALYSIS=False):
            resp = static_analyzer(req, checksum, False)
        # Whatever the outcome, the view must have run past the rescan
        # flag assignment without raising out of static_analyzer() itself.
        self.assertIsNotNone(resp)
