# -*- coding: utf_8 -*-
"""Real-execution coverage tests for common/pdf.py.

Real wkhtmltopdf/pdfkit are installed on this host and are used for real
PDF generation (success path). Real fault injection: a nonexistent
wkhtmltopdf path (pdfkit.configuration() genuinely raises OSError) and
``/usr/bin/false`` substituted as the wkhtmltopdf binary (a real
executable that genuinely exits non-zero, so pdfkit.from_string()
genuinely raises OSError) drive the error branches -- no mocking of
pdfkit/wkhtmltopdf's own behavior. A real StaticAnalyzerIOS row created
without its matching RecentScansDB row triggers a genuine
RecentScansDB.DoesNotExist for the outer exception branch. One narrow,
single-value monkeypatch (module-level ``pdfkit`` -> None) is used only
for the `pdfkit is not installed` guard, which is unreachable for real
since pdfkit is genuinely installed in this environment (noted below and
in the coverage report).

IMPORTANT DISCOVERY: pdf.py does ``from mobinspect.MobInspect import
settings`` (the raw settings module), not ``from django.conf import
settings``. Django's ``@override_settings`` only patches the
``django.conf.settings`` LazySettings wrapper (a separate copy built once
at setup time), so it has **no effect whatsoever** on attributes read
through the raw-module import -- confirmed empirically below (an
override_settings-based attempt at WKHTMLTOPDF_BINARY silently took the
default PATH-probing branch instead). The same raw-import pattern is used
by ``mobinspect/MobInspect/utils.py`` for ``upstream_proxy()``
(UPSTREAM_PROXY_*). Tests here patch attributes directly on the real raw
settings module object instead -- this is the actually-correct way to
configure these two code paths, not a workaround around real behavior.
"""
import os
import shutil
from unittest import mock

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import (
    Client,
    RequestFactory,
    SimpleTestCase,
    TestCase,
    override_settings,
)

from mobinspect.MobInspect import settings as raw_settings
from mobinspect.RBAC.models import ApiKey
from mobinspect.StaticAnalyzer.models import StaticAnalyzerIOS
from mobinspect.StaticAnalyzer.views.common.pdf import (
    get_pdf_configuration,
    pdf,
)


SAMPLES_DIR = os.path.normpath(
    os.path.join(settings.BASE_DIR, '..', 'test_files'))
REAL_WKHTMLTOPDF = shutil.which('wkhtmltopdf') or ''


class GetPdfConfigurationTests(SimpleTestCase):

    def test_pdfkit_none_raises_oserror(self):
        # `if pdfkit is None: raise OSError(...)` (line 69) is unreachable
        # for real on this host -- pdfkit is genuinely installed and
        # imports successfully. Narrow, single-value monkeypatch of the
        # module-level `pdfkit` name (not of get_pdf_configuration itself)
        # forces the guard to run for real.
        with mock.patch(
                'mobinspect.StaticAnalyzer.views.common.pdf.pdfkit', None):
            with self.assertRaises(OSError):
                get_pdf_configuration()

    def test_wkhtmltopdf_binary_setting_used(self):
        # settings.WKHTMLTOPDF_BINARY truthy -> pdfkit.configuration()
        # called with it directly (line 72). /usr/bin/true is a real,
        # always-present executable so this succeeds for real.
        # (@override_settings does NOT work here -- see module docstring;
        # the raw settings module attribute is patched directly instead.)
        with mock.patch.object(
                raw_settings, 'WKHTMLTOPDF_BINARY', '/usr/bin/true'):
            config = get_pdf_configuration()
        self.assertIsNotNone(config)


@override_settings(RATELIMIT_ENABLE=False, DISABLE_AUTHENTICATION=None,
                   ASYNC_ANALYSIS=False)
class PdfViewTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            'pdf_admin', 'pdf_admin@example.com', 'admin')
        _, cls.api_key = ApiKey.generate(cls.admin, 'pdf-key')
        client = Client()
        path = os.path.join(SAMPLES_DIR, 'ios.ipa')
        with open(path, 'rb') as fh:
            upload = SimpleUploadedFile(
                'ios.ipa', fh.read(), content_type='application/octet-stream')
        up = client.post('/api/v1/upload', {'file': upload},
                         HTTP_AUTHORIZATION=cls.api_key)
        assert up.status_code == 200, up.content
        cls.md5 = up.json()['hash']
        sc = client.post('/api/v1/scan', {'hash': cls.md5},
                         HTTP_AUTHORIZATION=cls.api_key)
        assert sc.status_code == 200, sc.content

    def _admin_request(self):
        rf = RequestFactory()
        request = rf.get('/')
        request.user = self.admin
        request.api_user = self.admin
        return request

    def test_invalid_hash_api_false(self):
        # not is_md5(checksum), api=False -> HttpResponse status 500
        # (line 84).
        resp = pdf(self._admin_request(), 'not-a-valid-hash', api=False)
        self.assertEqual(resp.status_code, 500)

    def test_report_not_found_api_false(self):
        # Valid-format md5, no matching row, api=False -> HttpResponse
        # status 500 (line 105).
        resp = pdf(self._admin_request(), '1' * 32, api=False)
        self.assertEqual(resp.status_code, 500)

    def test_invalid_hash_api_true(self):
        # not is_md5(checksum), api=True -> {'error': 'Invalid Hash'}
        # dict return (line 82).
        resp = pdf(self._admin_request(), 'not-a-valid-hash', api=True)
        self.assertEqual(resp, {'error': 'Invalid Hash'})

    def test_report_not_found_api_true(self):
        # Valid-format md5, no matching row, api=True -> {'report': ...}
        # dict return (line 103).
        resp = pdf(self._admin_request(), '4' * 32, api=True)
        self.assertEqual(resp, {'report': 'Report not Found'})

    def test_windows_platform_and_real_success(self):
        # platform.system() patched to 'Windows' (narrow, single call --
        # this host is Darwin) -> proto/host_os set (lines 123-124);
        # everything downstream (real appsec dashboard, real
        # template.render, real wkhtmltopdf invocation) executes for real,
        # producing a genuine PDF (line 175).
        assert REAL_WKHTMLTOPDF, 'wkhtmltopdf must be installed for this test'
        with mock.patch.object(
                raw_settings, 'WKHTMLTOPDF_BINARY', REAL_WKHTMLTOPDF), \
                mock.patch(
                    'mobinspect.StaticAnalyzer.views.common.pdf.platform.'
                    'system', return_value='Windows'):
            resp = pdf(self._admin_request(), self.md5, api=False)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp['Content-Type'], 'application/pdf')

    def test_proxy_option_set_real_success(self):
        # upstream_proxy('https') genuinely returns a truthy proxy string
        # -> options['proxy'] gets set (line 169); real end-to-end PDF
        # generation still succeeds (wkhtmltopdf ignores the bogus proxy
        # for a local HTML string render).
        assert REAL_WKHTMLTOPDF, 'wkhtmltopdf must be installed for this test'
        with mock.patch.object(
                raw_settings, 'WKHTMLTOPDF_BINARY', REAL_WKHTMLTOPDF), \
                mock.patch.object(
                    raw_settings, 'UPSTREAM_PROXY_ENABLED', True), \
                mock.patch.object(
                    raw_settings, 'UPSTREAM_PROXY_USERNAME', ''), \
                mock.patch.object(
                    raw_settings, 'UPSTREAM_PROXY_TYPE', 'http'), \
                mock.patch.object(
                    raw_settings, 'UPSTREAM_PROXY_IP', '127.0.0.1'), \
                mock.patch.object(
                    raw_settings, 'UPSTREAM_PROXY_PORT', 8080):
            resp = pdf(self._admin_request(), self.md5, api=True)
        self.assertIsInstance(resp, dict)
        self.assertIn('pdf_dat', resp)

    def test_wkhtmltopdf_missing_binary_api_true(self):
        # get_pdf_configuration() raises real OSError (binary genuinely
        # does not exist) -> except (OSError, IOError) branch, api=True
        # (lines 138-139, 141-142).
        with mock.patch.object(
                raw_settings, 'WKHTMLTOPDF_BINARY',
                '/nonexistent/wkhtmltopdf/binary'):
            resp = pdf(self._admin_request(), self.md5, api=True)
        self.assertIsInstance(resp, dict)
        self.assertIn('error', resp)
        self.assertIn('err_details', resp)

    def test_wkhtmltopdf_missing_binary_api_false(self):
        # Same real fault, api=False -> HttpResponse status 503 (line 145).
        with mock.patch.object(
                raw_settings, 'WKHTMLTOPDF_BINARY',
                '/nonexistent/wkhtmltopdf/binary'):
            resp = pdf(self._admin_request(), self.md5, api=False)
        self.assertEqual(resp.status_code, 503)

    def test_pdf_generation_failure_api_true(self):
        # /usr/bin/false is a real executable that always exits non-zero;
        # pdfkit.configuration() succeeds (the file exists) but
        # pdfkit.from_string() genuinely raises OSError when actually
        # invoked -> outer except, api=True (lines 177-180).
        with mock.patch.object(
                raw_settings, 'WKHTMLTOPDF_BINARY', '/usr/bin/false'):
            resp = pdf(self._admin_request(), self.md5, api=True)
        self.assertIsInstance(resp, dict)
        self.assertEqual(resp['error'], 'Cannot Generate PDF/JSON')
        self.assertIn('err_details', resp)

    def test_pdf_generation_failure_api_false(self):
        # Same real fault, api=False -> HttpResponse status 500 with a
        # JSON error body (lines 184, 187).
        with mock.patch.object(
                raw_settings, 'WKHTMLTOPDF_BINARY', '/usr/bin/false'):
            resp = pdf(self._admin_request(), self.md5, api=False)
        self.assertEqual(resp.status_code, 500)

    def test_outer_exception_missing_recentscans_row_api_true(self):
        # A real StaticAnalyzerIOS row with NO matching RecentScansDB row
        # -> RecentScansDB.objects.get(MD5=checksum) genuinely raises
        # DoesNotExist, outside the inner try -> the view's own outer
        # except, api=True (lines 191-196).
        checksum = '2' * 32
        StaticAnalyzerIOS.objects.create(
            MD5=checksum, FILE_NAME='orphan.ipa', APP_NAME='Orphan')
        resp = pdf(self._admin_request(), checksum, api=True)
        self.assertIsInstance(resp, dict)
        self.assertIn('error', resp)

    def test_outer_exception_missing_recentscans_row_api_false(self):
        # Same real fault, api=False (line 198).
        checksum = '3' * 32
        StaticAnalyzerIOS.objects.create(
            MD5=checksum, FILE_NAME='orphan2.ipa', APP_NAME='Orphan2')
        resp = pdf(self._admin_request(), checksum, api=False)
        self.assertEqual(resp.status_code, 500)
