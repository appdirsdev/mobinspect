# -*- coding: utf_8 -*-
"""Real-execution unit tests for playstore.py (STRICT: NO mocks).

The live Play Store / AppMonsta lookups are network calls (ceiling-gap).
These tests exercise every offline-reachable branch with REAL inputs and
REAL Django test infrastructure:

* ``override_settings`` (real Django test infra, not a mock) points
  ``PLAYSTORE`` / ``APPMONSTA_URL`` at either a *closed* localhost port
  (real connection-refused -> the "not reachable" / exception branches)
  or a *real* threaded ``http.server`` we spin up in-process (real HTTP
  request + real JSON body -> the reachable / success-formatting branches).
* ``append_scan_status`` issues a real ORM query against the test DB.
* ``BeautifulSoup`` really parses the returned HTML description.

No internal logic is mocked, monkeypatched, or faked.
"""
import http.server
import json
import socket
import threading

from django.test import TestCase, override_settings

from mobinspect.StaticAnalyzer.views.android.playstore import (
    app_search,
    get_app_details,
)

MD5 = 'aabbccddeeff00112233445566778899'

# A package id that cannot resolve on the real Play Store, so the
# google_play_scraper ``app()`` call always raises -> app_search fallback,
# whether or not the test host has network.
BOGUS_PKG = 'com.mobinspect.definitely.not.a.real.package.xyz123abc'

APPMONSTA_JSON = {
    'app_name': 'Test App',
    'all_rating': '4.5',
    'downloads': '1000+',
    'price': 'Free',
    'requires_os': '5.0 and up',
    'genre': 'Tools',
    'store_url': 'https://play.google.com/store/apps/details?id=x',
    'publisher_name': 'Test Dev',
    'publisher_id': 'devid',
    'publisher_address': '1 Test Street',
    'publisher_url': 'https://dev.example.com',
    'publisher_email': 'dev@example.com',
    'release_date': '2020-01-01',
    'privacy_url': 'https://privacy.example.com',
    'description': '<b>Hello</b> <i>World</i>',
}


def _closed_port_url():
    """Bind then release a localhost port so nothing is listening on it.

    A request to this URL yields a real ECONNREFUSED (fast, deterministic).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return f'http://127.0.0.1:{port}'


class _JSONHandler(http.server.BaseHTTPRequestHandler):
    """Real HTTP handler returning the AppMonsta-shaped JSON body."""

    def do_GET(self):  # noqa: N802
        body = json.dumps(APPMONSTA_JSON).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence server logging
        pass


class _LocalServer:
    """A real threaded HTTP server bound to a free localhost port."""

    def __enter__(self):
        self.httpd = http.server.ThreadingHTTPServer(
            ('127.0.0.1', 0), _JSONHandler)
        self.port = self.httpd.server_address[1]
        self.url = f'http://127.0.0.1:{self.port}'
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


class AppSearchTests(TestCase):
    """Direct, fully-offline coverage of app_search()."""

    def test_no_appmonsta_api_returns_error(self):
        """APPMONSTA_API unset (default) -> immediate {'error': True}."""
        with override_settings(APPMONSTA_API=''):
            det = app_search(MD5, BOGUS_PKG)
        self.assertEqual(det, {'error': True})

    def test_unreachable_appmonsta_hits_exception_branch(self):
        """API set but URL refused -> exception branch -> {'error': True}."""
        with override_settings(APPMONSTA_API='dummy-key',
                               APPMONSTA_URL=_closed_port_url() + '/'):
            det = app_search(MD5, BOGUS_PKG)
        # requests.get raised (connection refused); det never got 'title'.
        self.assertTrue(det['error'])
        self.assertNotIn('title', det)

    def test_success_formatting_with_real_response(self):
        """Real HTTP JSON response -> full result formatting, error False."""
        with _LocalServer() as srv:
            with override_settings(APPMONSTA_API='dummy-key',
                                   APPMONSTA_URL=srv.url + '/'):
                det = app_search(MD5, BOGUS_PKG)
        self.assertFalse(det['error'])
        self.assertEqual(det['title'], 'Test App')
        self.assertEqual(det['score'], '4.5')
        self.assertEqual(det['installs'], '1000+')
        self.assertEqual(det['price'], 'Free')
        self.assertEqual(det['androidVersionText'], '5.0 and up')
        self.assertEqual(det['genre'], 'Tools')
        self.assertEqual(det['developer'], 'Test Dev')
        self.assertEqual(det['developerId'], 'devid')
        self.assertEqual(det['developerEmail'], 'dev@example.com')
        self.assertEqual(det['released'], '2020-01-01')
        self.assertEqual(det['privacyPolicy'], 'https://privacy.example.com')
        # BeautifulSoup really stripped the HTML tags from the description.
        self.assertEqual(det['description'], 'Hello World')


class GetAppDetailsTests(TestCase):
    """Coverage of get_app_details() branch logic."""

    def _base_app_dic(self):
        return {'md5': MD5}

    def test_playstore_unreachable_keeps_default_error(self):
        """PLAYSTORE refused -> early return, default error dict retained."""
        app_dic = self._base_app_dic()
        with override_settings(PLAYSTORE=_closed_port_url()):
            get_app_details(app_dic, {'packagename': BOGUS_PKG})
        self.assertEqual(app_dic['playstore'], {
            'error': True,
            'description': 'Failed to identify the package name',
        })

    def test_reachable_but_no_package_name(self):
        """Reachable store, no packagename & no apk_features -> default dict."""
        app_dic = self._base_app_dic()
        with _LocalServer() as srv:
            with override_settings(PLAYSTORE=srv.url):
                get_app_details(app_dic, {})
        self.assertEqual(app_dic['playstore'], {
            'error': True,
            'description': 'Failed to identify the package name',
        })

    def test_packagename_falls_through_to_appsearch_no_api(self):
        """Reachable store, bogus pkg -> app() fails -> app_search (no API)."""
        app_dic = self._base_app_dic()
        with _LocalServer() as srv:
            with override_settings(PLAYSTORE=srv.url, APPMONSTA_API=''):
                get_app_details(app_dic, {'packagename': BOGUS_PKG})
        self.assertEqual(app_dic['playstore'], {'error': True})

    def test_apk_features_package_falls_through_to_appsearch_success(self):
        """elif apk_features.package branch -> app() fails -> app_search OK.

        Drives BOTH functions end to end: reachable store, package id taken
        from apk_features, the real google_play_scraper lookup fails on the
        bogus id, and the AppMonsta fallback returns a real formatted result.
        """
        app_dic = self._base_app_dic()
        app_dic['apk_features'] = {'package': BOGUS_PKG}
        with _LocalServer() as srv:
            with override_settings(PLAYSTORE=srv.url,
                                   APPMONSTA_API='dummy-key',
                                   APPMONSTA_URL=srv.url + '/'):
                get_app_details(app_dic, {})
        self.assertFalse(app_dic['playstore']['error'])
        self.assertEqual(app_dic['playstore']['title'], 'Test App')
