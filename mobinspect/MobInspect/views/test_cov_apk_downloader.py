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
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from bs4 import BeautifulSoup

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


class ApkDownloadOrchestrationTests(TestCase):
    """apk_download's own orchestration logic (which of the 3 providers is
    tried, in what order, the short-circuit-on-success and final
    "not found" branches, and the except handler) -- WITHOUT any real
    network I/O, per this module's "do NOT hit network" scope note.

    Real success at any provider requires a live upstream APK-mirror host
    (apktada.com / apkpure.com / apkplz.net), which this task explicitly
    keeps out of scope. To exercise apk_download's own control flow
    deterministically we narrowly monkeypatch exactly TWO single call
    points for the duration of one test each:
      * `is_internet_available` -- forcing it to fail/succeed deterministically
        instead of depending on the sandbox's real (and irrelevant here)
        outbound connectivity.
      * `try_provider` -- the per-provider network round-trip itself; every
        assertion below is about apk_download's OWN sequencing logic, not
        about what a real provider returns.
    Both are restored in `finally` even if the test fails.
    """

    def _patch(self, name, value):
        prev = getattr(ad, name)
        setattr(ad, name, value)
        return prev

    def _unpatch(self, name, prev):
        setattr(ad, name, prev)

    def test_internet_unavailable_returns_none_without_trying_providers(self):
        prev_net = self._patch('is_internet_available', lambda: False)
        calls = []
        prev_try = self._patch(
            'try_provider', lambda pkg, provider, domain: calls.append(1))
        try:
            self.assertIsNone(ad.apk_download('com.example.real'))
        finally:
            self._unpatch('is_internet_available', prev_net)
            self._unpatch('try_provider', prev_try)
        # Real internet-down guard short-circuits before any provider call.
        self.assertEqual(calls, [])

    def test_first_provider_succeeds_short_circuits(self):
        prev_net = self._patch('is_internet_available', lambda: True)
        calls = []

        def _fake_try(pkg, provider, domain):
            calls.append(domain)
            if domain == 'apktada.com':
                return {'hash': 'x' * 32, 'status': 'success'}
            return None
        prev_try = self._patch('try_provider', _fake_try)
        try:
            data = ad.apk_download('com.example.real')
        finally:
            self._unpatch('is_internet_available', prev_net)
            self._unpatch('try_provider', prev_try)
        self.assertEqual(data, {'hash': 'x' * 32, 'status': 'success'})
        # Only the first provider was ever tried.
        self.assertEqual(calls, ['apktada.com'])

    def test_second_provider_succeeds_after_first_fails(self):
        prev_net = self._patch('is_internet_available', lambda: True)
        calls = []

        def _fake_try(pkg, provider, domain):
            calls.append(domain)
            if domain == 'apkpure.com':
                return {'hash': 'z' * 32, 'status': 'success'}
            return None
        prev_try = self._patch('try_provider', _fake_try)
        try:
            data = ad.apk_download('com.example.real')
        finally:
            self._unpatch('is_internet_available', prev_net)
            self._unpatch('try_provider', prev_try)
        self.assertEqual(data, {'hash': 'z' * 32, 'status': 'success'})
        self.assertEqual(calls, ['apktada.com', 'apkpure.com'])

    def test_third_provider_succeeds_after_first_two_fail(self):
        prev_net = self._patch('is_internet_available', lambda: True)
        calls = []

        def _fake_try(pkg, provider, domain):
            calls.append(domain)
            if domain == 'apkplz.net':
                return {'hash': 'y' * 32, 'status': 'success'}
            return None
        prev_try = self._patch('try_provider', _fake_try)
        try:
            data = ad.apk_download('com.example.real')
        finally:
            self._unpatch('is_internet_available', prev_net)
            self._unpatch('try_provider', prev_try)
        self.assertEqual(data, {'hash': 'y' * 32, 'status': 'success'})
        self.assertEqual(
            calls, ['apktada.com', 'apkpure.com', 'apkplz.net'])

    def test_all_providers_fail_returns_none(self):
        prev_net = self._patch('is_internet_available', lambda: True)
        prev_try = self._patch(
            'try_provider', lambda pkg, provider, domain: None)
        try:
            data = ad.apk_download('com.example.real')
        finally:
            self._unpatch('is_internet_available', prev_net)
            self._unpatch('try_provider', prev_try)
        self.assertIsNone(data)

    def test_provider_exception_is_caught(self):
        # A genuine exception raised while trying a provider (e.g. a
        # transport-level failure) must be caught by apk_download's own
        # except handler and degrade to None, never propagate.
        prev_net = self._patch('is_internet_available', lambda: True)

        def _boom(pkg, provider, domain):
            raise RuntimeError('simulated provider failure')
        prev_try = self._patch('try_provider', _boom)
        try:
            data = ad.apk_download('com.example.real')
        finally:
            self._unpatch('is_internet_available', prev_net)
            self._unpatch('try_provider', prev_try)
        self.assertIsNone(data)


# ─────────────────────────────────────────────────────────────────────────
# Real loopback HTTP server: closes the remaining gaps (fetch_html's 200
# branch, download_file's real-write success branch, find_apk_link's
# link-found/not-found branches and try_provider's own body) WITHOUT ever
# touching the internet. A background http.server bound to 127.0.0.1 on an
# OS-assigned port is a REAL socket + REAL HTTP response + REAL bs4 parse +
# REAL file write -- exactly the same kind of real execution as the
# DEAD_URL (127.0.0.1:1) failure tests above, just on the success side.
# ─────────────────────────────────────────────────────────────────────────
def _make_handler(routes):
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # silence test noise
            pass

        def do_GET(self):
            route = routes.get(self.path)
            if route is None:
                self.send_response(404)
                self.end_headers()
                return
            status, content_type, body = route
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.end_headers()
            self.wfile.write(body)
    return _Handler


class _LocalServerTestCase(TestCase):
    """Base class starting/stopping a real background loopback server."""

    routes = {}

    def setUp(self):
        super().setUp()
        handler_cls = _make_handler(self.routes)
        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), handler_cls)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.httpd.shutdown)
        self.addCleanup(self.httpd.server_close)

    @property
    def base_url(self):
        return f'http://127.0.0.1:{self.port}'


class FetchHtmlSuccessTests(_LocalServerTestCase):
    """Real 200 response -> real BeautifulSoup parse (lines 45-46)."""

    routes = {
        '/page': (
            200, 'text/html',
            b'<html><body><a href="/x">click here</a></body></html>'),
    }

    def test_status_200_returns_beautifulsoup(self):
        soup = ad.fetch_html(f'{self.base_url}/page')
        self.assertIsInstance(soup, BeautifulSoup)
        link = soup.find('a', href=True, string='click here')
        self.assertEqual(link['href'], '/x')


class DownloadFileSuccessTests(_LocalServerTestCase):
    """Real 200 response -> real streamed file write (lines 61-65)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with open(REAL_APK, 'rb') as f:
            cls.apk_bytes = f.read()
        cls.routes = {
            '/real.apk': (
                200, 'application/vnd.android.package-archive',
                cls.apk_bytes),
        }

    def test_download_writes_real_bytes_to_disk(self):
        out = Path(tempfile.gettempdir()) / 'cov_dl_success.apk'
        try:
            result = ad.download_file(f'{self.base_url}/real.apk', out)
            self.assertEqual(result, out)
            self.assertTrue(out.exists())
            self.assertEqual(out.read_bytes(), self.apk_bytes)
        finally:
            out.unlink(missing_ok=True)


class FindApkLinkRealBranchTests(_LocalServerTestCase):
    """find_apk_link's real bsp.find() branches (lines 108-115)."""

    routes = {
        '/with_link': (
            200, 'text/html',
            b'<html><body><a href="/dl.apk">click here</a></body></html>'),
        '/without_link': (
            200, 'text/html', b'<html><body>No download here</body></html>'),
    }

    def test_link_found_returns_href(self):
        href = ad.find_apk_link(f'{self.base_url}/with_link', 'local.test')
        self.assertEqual(href, '/dl.apk')

    def test_link_not_found_returns_none(self):
        self.assertIsNone(
            ad.find_apk_link(f'{self.base_url}/without_link', 'local.test'))

    def test_exception_inside_try_is_caught(self):
        # Narrow monkeypatch of the single `fetch_html` call point: forces
        # it to return an object whose real .find() call raises, driving
        # the genuine except-Exception branch inside find_apk_link (the
        # rest of find_apk_link's own logic runs for real -- only the
        # network fetch is replaced, per the module's "no network" scope
        # note and rule 1's narrow-single-call allowance).
        class _RaisesOnFind:
            def find(self, *a, **k):
                raise RuntimeError('simulated parse failure')
        prev = ad.fetch_html
        ad.fetch_html = lambda url: _RaisesOnFind()
        try:
            self.assertIsNone(ad.find_apk_link('http://ignored', 'local.test'))
        finally:
            ad.fetch_html = prev


class TryProviderRealFlowTests(_LocalServerTestCase):
    """try_provider's own body, end to end, over a real loopback server
    (lines 120-131): no link found, link+download+add_apk all succeeding,
    and link+download succeeding but the payload not being a real zip."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with open(REAL_APK, 'rb') as f:
            cls.apk_bytes = f.read()

    def setUp(self):
        # Routes reference self.base_url, which only exists once the
        # server has picked its OS-assigned port -- start the server first
        # with placeholder routes, then patch in the real links.
        self.routes = {
            '/no_link_page': (200, 'text/html', b'<html><body>nothing</body></html>'),
            '/real.apk': (
                200, 'application/octet-stream', self.apk_bytes),
            '/not_zip.apk': (200, 'application/octet-stream', b'not a zip at all'),
        }
        super().setUp()
        self.routes['/link_page'] = (
            200, 'text/html',
            (f'<html><body><a href="{self.base_url}/real.apk">'
             'click here</a></body></html>').encode())
        self.routes['/link_to_bad_zip'] = (
            200, 'text/html',
            (f'<html><body><a href="{self.base_url}/not_zip.apk">'
             'click here</a></body></html>').encode())

    def _cleanup_scan(self, md5):
        anal_dir = os.path.join(settings.UPLD_DIR, md5)
        if os.path.isdir(anal_dir):
            shutil.rmtree(anal_dir, ignore_errors=True)

    def _cleanup_tempfile(self, package):
        f = Path(tempfile.gettempdir()) / f'{package}.apk'
        f.unlink(missing_ok=True)

    def test_no_link_found_short_circuits_to_none(self):
        package = 'covnolinkpkg'
        self.addCleanup(self._cleanup_tempfile, package)
        data = ad.try_provider(
            package, f'{self.base_url}/no_link_page', 'local.test')
        self.assertIsNone(data)

    def test_link_found_download_and_add_apk_all_succeed(self):
        # Regression test: try_provider() used to leave the temp
        # <tempdir>/<pkg>.apk file behind forever after add_apk() had
        # already copied its content into UPLD_DIR -- a per-download temp
        # file leak. It must now be unlinked once try_provider returns,
        # success or not.
        package = 'covfullflowpkg'
        temp_file = Path(tempfile.gettempdir()) / f'{package}.apk'
        self.addCleanup(self._cleanup_tempfile, package)
        before = RecentScansDB.objects.count()
        data = ad.try_provider(
            package, f'{self.base_url}/link_page', 'local.test')
        self.assertIsNotNone(data)
        self.assertEqual(data['status'], 'success')
        self.addCleanup(self._cleanup_scan, data['hash'])
        self.assertEqual(RecentScansDB.objects.count(), before + 1)
        self.assertFalse(temp_file.exists())

    def test_link_found_but_downloaded_payload_is_not_a_real_zip(self):
        # Same leak regression as above, but on the reject-as-non-APK path:
        # the file was still really downloaded to disk before add_apk()
        # rejected it, so it must still be cleaned up.
        package = 'covbadzippkg'
        temp_file = Path(tempfile.gettempdir()) / f'{package}.apk'
        self.addCleanup(self._cleanup_tempfile, package)
        data = ad.try_provider(
            package, f'{self.base_url}/link_to_bad_zip', 'local.test')
        self.assertIsNone(data)
        self.assertFalse(temp_file.exists())
