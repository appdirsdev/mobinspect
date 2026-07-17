# -*- coding: utf_8 -*-
"""Real-execution (STRICT no-mock) coverage tests for duplicate-upload
detection in ``mobinspect.MobInspect.views.scanning``.

Every branch is driven with real DB rows (Django ORM against the isolated
Postgres test DB), the committed ``test_files/android.apk`` sample, and real
files on disk. No mocks, no monkeypatching, no fake returns.
"""
import os
import shutil

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, Client, RequestFactory, override_settings

from mobinspect.MobInspect.views import home, scanning
from mobinspect.RBAC.models import ApiKey
from mobinspect.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerAndroid,
)


SAMPLES_DIR = os.path.normpath(
    os.path.join(settings.BASE_DIR, '..', 'test_files'))
APK_PATH = os.path.join(SAMPLES_DIR, 'android.apk')


def _upload_dir(md5):
    return os.path.join(settings.UPLD_DIR, md5)


def _write_upload(md5, extension='.apk', body=b'x'):
    """Create ``UPLD_DIR/<md5>/<md5><ext>`` and return its path."""
    d = _upload_dir(md5)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, md5 + extension)
    with open(path, 'wb') as fh:
        fh.write(body)
    return path


def _cleanup(md5):
    d = _upload_dir(md5)
    if os.path.isdir(d):
        shutil.rmtree(d, ignore_errors=True)


class _DirTrackingTestCase(TestCase):
    """Base that removes any upload dirs a test created, on teardown."""

    def setUp(self):
        self._dirs = set()

    def tearDown(self):
        for md5 in self._dirs:
            _cleanup(md5)

    def _track(self, md5):
        self._dirs.add(md5)
        return md5


class FindDuplicateScanTests(_DirTrackingTestCase):
    """Unit coverage of ``find_duplicate_scan`` — both detection layers."""

    def test_first_upload_is_not_duplicate(self):
        md5 = self._track('0' * 32)
        path = _write_upload(md5)
        self.assertIsNone(scanning.find_duplicate_scan(md5, 'apk', path))

    def test_exact_file_is_duplicate(self):
        md5 = self._track('1' * 32)
        RecentScansDB.objects.create(
            ANALYZER='static_analyzer', SCAN_TYPE='apk',
            FILE_NAME='old.apk', APP_NAME='OldApp',
            PACKAGE_NAME='com.x', VERSION_NAME='1.0', MD5=md5)
        path = _write_upload(md5)
        dup = scanning.find_duplicate_scan(md5, 'apk', path)
        self.assertIsNotNone(dup)
        self.assertEqual(dup['hash'], md5)
        self.assertEqual(dup['url'], f'/static_analyzer/{md5}/')
        self.assertEqual(dup['app_name'], 'OldApp')

    def test_exact_file_duplicate_applies_to_any_type(self):
        # Layer 1 (identical bytes) covers non-APK types too, e.g. a zip.
        md5 = self._track('2' * 32)
        RecentScansDB.objects.create(
            ANALYZER='static_analyzer', SCAN_TYPE='zip',
            FILE_NAME='src.zip', MD5=md5)
        path = _write_upload(md5, '.zip')
        self.assertIsNotNone(scanning.find_duplicate_scan(md5, 'zip', path))

    def test_exact_file_meta_uses_recorded_analyzer(self):
        # An iOS re-upload must point back at the iOS report URL.
        md5 = self._track('3' * 32)
        RecentScansDB.objects.create(
            ANALYZER='static_analyzer_ios', SCAN_TYPE='ipa',
            FILE_NAME='app.ipa', MD5=md5)
        path = _write_upload(md5, '.ipa')
        dup = scanning.find_duplicate_scan(md5, 'ipa', path)
        self.assertEqual(dup['url'], f'/static_analyzer_ios/{md5}/')


class PackageVersionDuplicateTests(TestCase):
    """Layer 2 — same Android package + versionName, different bytes."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.pkg, cls.ver = scanning._apk_package_version(APK_PATH)

    def setUp(self):
        # The committed android.apk MUST parse — a failure here is a real
        # regression (e.g. a broken androguard call), NOT a reason to silently
        # skip the headline feature's only coverage. Fail loudly instead.
        self.assertTrue(
            self.pkg and self.ver,
            'android.apk manifest did not parse (pkg=%r ver=%r) — the '
            'package+version duplicate layer is unexercised' % (
                self.pkg, self.ver))

    def test_sample_apk_parses_package_and_version(self):
        self.assertTrue(self.pkg)
        self.assertTrue(self.ver)

    def test_same_package_version_different_bytes_is_duplicate(self):
        prior = 'a' * 32  # a prior build => different bytes => different md5
        StaticAnalyzerAndroid.objects.create(
            MD5=prior, PACKAGE_NAME=self.pkg, VERSION_NAME=self.ver,
            APP_NAME='PriorBuild', FILE_NAME='prior.apk')
        RecentScansDB.objects.create(
            ANALYZER='static_analyzer', SCAN_TYPE='apk', MD5=prior,
            PACKAGE_NAME=self.pkg, VERSION_NAME=self.ver,
            APP_NAME='PriorBuild', FILE_NAME='prior.apk')
        new_md5 = 'c' * 32  # no RecentScansDB row => layer 1 misses
        dup = scanning.find_duplicate_scan(new_md5, 'apk', APK_PATH)
        self.assertIsNotNone(dup)
        self.assertEqual(dup['hash'], prior)
        self.assertEqual(dup['app_name'], 'PriorBuild')

    def test_different_version_same_package_is_allowed(self):
        StaticAnalyzerAndroid.objects.create(
            MD5='a' * 32, PACKAGE_NAME=self.pkg,
            VERSION_NAME=self.ver + '-next',
            APP_NAME='OtherVersion', FILE_NAME='other.apk')
        self.assertIsNone(
            scanning.find_duplicate_scan('c' * 32, 'apk', APK_PATH))

    def test_non_plain_apk_skips_version_layer(self):
        # A split APK (scan_type 'apks') never consults the version layer.
        StaticAnalyzerAndroid.objects.create(
            MD5='a' * 32, PACKAGE_NAME=self.pkg, VERSION_NAME=self.ver,
            APP_NAME='X', FILE_NAME='x.apk')
        self.assertIsNone(
            scanning.find_duplicate_scan('c' * 32, 'apks', APK_PATH))

    def test_static_analyzer_only_prior_synthesizes_duplicate(self):
        # The API-scanned-app case: a prior build left a StaticAnalyzerAndroid
        # row but NO RecentScansDB row. find_duplicate_scan must fall back to
        # a synthesized payload (app_name='', canonical URL) — the branch that
        # had no coverage before.
        prior = 'a' * 32
        StaticAnalyzerAndroid.objects.create(
            MD5=prior, PACKAGE_NAME=self.pkg, VERSION_NAME=self.ver,
            APP_NAME='ApiScanned', FILE_NAME='api.apk')
        dup = scanning.find_duplicate_scan('c' * 32, 'apk', APK_PATH)
        self.assertIsNotNone(dup)
        self.assertEqual(dup['hash'], prior)
        self.assertEqual(dup['url'], f'/static_analyzer/{prior}/')
        self.assertEqual(dup['app_name'], '')  # no RecentScansDB row -> ''
        # build_duplicate_response then falls back to the uploaded file name.
        data = {'analyzer': 'static_analyzer', 'scan_type': 'apk',
                'file_name': 'rebuild.apk'}
        resp = scanning.build_duplicate_response(data, dup, 'c' * 32)
        self.assertIn('rebuild.apk', resp['description'])
        self.assertEqual(resp['hash'], prior)

    @override_settings(MOBINSPECT_DUP_VERSION_MAX_BYTES=8)
    def test_version_layer_skipped_when_file_exceeds_cap(self):
        # A prior build exists and would normally match, but the real sample is
        # far bigger than the 8-byte cap, so the synchronous manifest parse is
        # skipped and no duplicate is reported (exact-MD5 layer still applies).
        StaticAnalyzerAndroid.objects.create(
            MD5='a' * 32, PACKAGE_NAME=self.pkg, VERSION_NAME=self.ver,
            APP_NAME='Prior', FILE_NAME='prior.apk')
        self.assertIsNone(
            scanning.find_duplicate_scan('c' * 32, 'apk', APK_PATH))


class ApkParseAndOrphanTests(_DirTrackingTestCase):
    """``_apk_package_version`` fallback + orphan-upload cleanup."""

    def test_unparseable_apk_returns_empty(self):
        md5 = self._track('d' * 32)
        path = _write_upload(md5, '.apk', b'not a real apk archive')
        self.assertEqual(scanning._apk_package_version(path), ('', ''))

    def test_unparseable_apk_is_not_flagged_as_duplicate(self):
        # A brand-new, unparseable file with no matching row is allowed.
        md5 = self._track('5' * 32)
        path = _write_upload(md5, '.apk', b'garbage')
        self.assertIsNone(scanning.find_duplicate_scan(md5, 'apk', path))

    def test_orphan_upload_removed_on_version_duplicate(self):
        new_md5 = self._track('e' * 32)
        _write_upload(new_md5)  # freshly written, no DB row backs it
        existing = {
            'hash': 'f' * 32, 'url': '/static_analyzer/' + 'f' * 32 + '/',
            'app_name': 'Prior', 'version_name': '2.0',
            'package_name': 'com.x', 'timestamp': None}
        data = {'analyzer': 'static_analyzer', 'scan_type': 'apk',
                'file_name': 'new.apk'}
        resp = scanning.build_duplicate_response(data, existing, new_md5)
        self.assertTrue(resp['duplicate'])
        self.assertEqual(resp['existing_hash'], 'f' * 32)
        # hash points at the EXISTING scan, not the rejected upload.
        self.assertEqual(resp['hash'], 'f' * 32)
        self.assertIn('Duplicate APK', resp['description'])
        # New bytes differ from the existing scan and have no DB row -> removed.
        self.assertFalse(os.path.isdir(_upload_dir(new_md5)))

    def test_shared_dir_kept_on_exact_reupload(self):
        md5 = self._track('9' * 32)
        _write_upload(md5)
        RecentScansDB.objects.create(
            ANALYZER='static_analyzer', SCAN_TYPE='apk',
            FILE_NAME='old.apk', MD5=md5)
        existing = scanning._existing_scan_meta(md5)
        data = {'analyzer': 'static_analyzer', 'file_name': 'old.apk'}
        scanning.build_duplicate_response(data, existing, md5)
        # Exact re-upload shares the existing scan's dir -> must be preserved.
        self.assertTrue(os.path.isdir(_upload_dir(md5)))

    def test_orphan_cleanup_skips_dir_with_existing_db_row(self):
        # Guard: never delete an upload backing a real (API) scan even when
        # a different build triggers the version-duplicate path.
        md5 = self._track('8' * 32)
        _write_upload(md5)
        StaticAnalyzerAndroid.objects.create(
            MD5=md5, PACKAGE_NAME='com.x', VERSION_NAME='1.0')
        existing = {
            'hash': '7' * 32, 'url': '/static_analyzer/' + '7' * 32 + '/',
            'app_name': 'P', 'version_name': '1.0',
            'package_name': 'com.x', 'timestamp': None}
        data = {'analyzer': 'static_analyzer', 'file_name': 'n.apk'}
        scanning.build_duplicate_response(data, existing, md5)
        self.assertTrue(os.path.isdir(_upload_dir(md5)))


class ScanReportUrlAndMessageTests(TestCase):
    """Pure-helper coverage: URL construction + type-aware duplicate wording.

    These make a revert of the fixes visible — a hardcoded 'APK' label or a
    no-default URL would fail here even though the endpoint tests would not.
    """

    def test_scan_report_url_defaults_empty_analyzer(self):
        md5 = 'a' * 32
        self.assertEqual(
            scanning.scan_report_url('', md5), f'/static_analyzer/{md5}/')
        self.assertEqual(
            scanning.scan_report_url(None, md5), f'/static_analyzer/{md5}/')

    def test_scan_report_url_passthrough(self):
        md5 = 'b' * 32
        self.assertEqual(
            scanning.scan_report_url('static_analyzer_ios', md5),
            f'/static_analyzer_ios/{md5}/')

    def test_duplicate_message_is_type_aware(self):
        existing = {
            'hash': 'f' * 32, 'url': '/static_analyzer/' + 'f' * 32 + '/',
            'app_name': 'App', 'version_name': '', 'package_name': '',
            'timestamp': None}
        base = {'analyzer': 'static_analyzer', 'file_name': 'x'}
        # md5 == existing['hash'] so no filesystem/DB side effect here.
        ipa = scanning.build_duplicate_response(
            {**base, 'scan_type': 'ipa'}, existing, 'f' * 32)
        self.assertIn('Duplicate IPA', ipa['description'])
        self.assertNotIn('APK', ipa['description'])
        zp = scanning.build_duplicate_response(
            {**base, 'scan_type': 'zip'}, existing, 'f' * 32)
        self.assertIn('Duplicate source archive', zp['description'])
        unknown = scanning.build_duplicate_response(
            {**base, 'scan_type': 'mystery'}, existing, 'f' * 32)
        self.assertIn('Duplicate upload', unknown['description'])


class FinalizeWiringTests(_DirTrackingTestCase):
    """The _finalize refactor must wire every scan_* to the right
    (extension, scan_type, analyzer) — not just the APK path."""

    def _scan(self, method_name, filename, body):
        f = SimpleUploadedFile(
            filename, body, content_type='application/octet-stream')
        req = RequestFactory().post('/upload/', {'file': f})
        data = getattr(scanning.Scanning(req), method_name)()
        if data.get('hash'):
            self._track(data['hash'])
        return data

    def test_ipa_wiring(self):
        d = self._scan('scan_ipa', 'app.ipa', b'fake-ios-binary-bytes')
        self.assertEqual(d['status'], 'success')
        self.assertEqual(d['scan_type'], 'ipa')
        self.assertEqual(d['analyzer'], 'static_analyzer_ios')

    def test_appx_wiring(self):
        d = self._scan('scan_appx', 'app.appx', b'fake-windows-appx-bytes')
        self.assertEqual(d['status'], 'success')
        self.assertEqual(d['scan_type'], 'appx')
        self.assertEqual(d['analyzer'], 'static_analyzer_windows')

    def test_zip_source_wiring(self):
        d = self._scan('scan_zip', 'src.zip', b'fake-source-zip-bytes')
        self.assertEqual(d['status'], 'success')
        self.assertEqual(d['scan_type'], 'zip')
        self.assertEqual(d['analyzer'], 'static_analyzer')

    def test_aab_wiring(self):
        d = self._scan('scan_aab', 'app.aab', b'fake-app-bundle-bytes')
        self.assertEqual(d['status'], 'success')
        self.assertEqual(d['scan_type'], 'aab')
        self.assertEqual(d['analyzer'], 'static_analyzer')


@override_settings(RATELIMIT_ENABLE=False, DISABLE_AUTHENTICATION=None)
class UploadDuplicateEndpointTests(TestCase):
    """End-to-end: the web and API upload endpoints reject a re-upload."""

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            'dup_admin', 'dup_admin@example.com', 'admin')
        _, cls.api_key = ApiKey.generate(cls.admin, 'dup-key')

    def setUp(self):
        self.client = Client()
        self.client.force_login(self.admin)
        self._md5s = set()

    def tearDown(self):
        for md5 in self._md5s:
            _cleanup(md5)

    def _apk_file(self):
        with open(APK_PATH, 'rb') as fh:
            return SimpleUploadedFile(
                'android.apk', fh.read(),
                content_type='application/octet-stream')

    def test_web_second_upload_is_duplicate(self):
        first = self.client.post('/upload/', {'file': self._apk_file()})
        self.assertEqual(first.status_code, 200)
        data1 = first.json()
        self.assertEqual(data1['status'], 'success')
        self._md5s.add(data1['hash'])

        second = self.client.post('/upload/', {'file': self._apk_file()})
        self.assertEqual(second.status_code, 200)
        data2 = second.json()
        self.assertEqual(data2['status'], 'error')
        self.assertTrue(data2['duplicate'])
        self.assertIn('Duplicate APK', data2['description'])
        self.assertEqual(data2['existing_hash'], data1['hash'])
        # hash still points at a usable md5 (the existing scan).
        self.assertEqual(data2['hash'], data1['hash'])
        self.assertTrue(data2['existing_url'])

    def test_api_second_upload_is_conflict(self):
        auth = {'HTTP_AUTHORIZATION': self.api_key}
        first = self.client.post(
            '/api/v1/upload', {'file': self._apk_file()}, **auth)
        self.assertEqual(first.status_code, 200)
        md5 = first.json()['hash']
        self._md5s.add(md5)

        second = self.client.post(
            '/api/v1/upload', {'file': self._apk_file()}, **auth)
        self.assertEqual(second.status_code, home.HTTP_CONFLICT)
        body = second.json()
        self.assertTrue(body['duplicate'])
        self.assertEqual(body['status'], 'error')
        self.assertIn('Duplicate APK', body['error'])
        self.assertEqual(body['existing_hash'], md5)
        # Envelope keeps `hash` so an upload->scan client still reaches it.
        self.assertEqual(body['hash'], md5)
        self.assertTrue(body['existing_url'])

    def test_first_api_upload_succeeds(self):
        auth = {'HTTP_AUTHORIZATION': self.api_key}
        resp = self.client.post(
            '/api/v1/upload', {'file': self._apk_file()}, **auth)
        self.assertEqual(resp.status_code, 200)
        md5 = resp.json()['hash']
        self._md5s.add(md5)
        self.assertTrue(RecentScansDB.objects.filter(MD5=md5).exists())
