# -*- coding: utf_8 -*-
"""Real-execution coverage tests for ios/static_analyzer.py.

Real fault injection throughout: a genuinely nonexistent uploaded file
makes the real ``os.path.getsize()`` call inside ``file_size()`` (invoked
transitively from ``dylib_analysis()``) raise a real ``FileNotFoundError``
that propagates up into this module's own outer except (no monkeypatch);
``checksum=None`` makes the real ``MD5_REGEX.match(None)`` call inside
``is_md5()`` raise a real ``TypeError`` for the same branch via a
different, independent path.
"""
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings

from mobinspect.StaticAnalyzer.models import RecentScansDB
from mobinspect.StaticAnalyzer.views.ios.static_analyzer import (
    static_analyzer_ios,
)


@override_settings(DISABLE_AUTHENTICATION=None, RATELIMIT_ENABLE=False)
class StaticAnalyzerIosTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            'sa_admin', 'sa_admin@example.com', 'admin')

    def _admin_request(self, method='get', data=None):
        rf = RequestFactory()
        request = getattr(rf, method)('/', data or {})
        request.user = self.admin
        request.api_user = self.admin
        return request

    def test_invalid_hash_api_false(self):
        # not is_md5(checksum) -> error response (line 51).
        resp = static_analyzer_ios(
            self._admin_request(), 'not-a-valid-hash', api=False)
        self.assertEqual(resp.status_code, 500)

    def test_no_recentscans_row_api_false(self):
        # Valid-format checksum, no RecentScansDB row -> "not
        # uploaded/available" error response (line 57).
        resp = static_analyzer_ios(
            self._admin_request(), '1' * 32, api=False)
        self.assertEqual(resp.status_code, 500)

    def test_invalid_extension_or_type_api_false(self):
        # A real RecentScansDB row whose FILE_NAME extension does not
        # match its own SCAN_TYPE's allowed extensions -> line 71.
        checksum = '2' * 32
        RecentScansDB.objects.create(
            MD5=checksum, SCAN_TYPE='ipa', FILE_NAME='app.badext',
            APP_NAME='BadExt')
        resp = static_analyzer_ios(self._admin_request(), checksum, api=False)
        self.assertEqual(resp.status_code, 500)

    def test_rescan_true_forces_dylib_extension_and_outer_exception(self):
        # SCAN_TYPE == 'dylib' with an extensionless FILE_NAME -> the
        # '.dylib' suffix is forced on for real (line 65). re_scan='1' in
        # POST -> rescan = True (line 48). Dispatch to the real
        # dylib_analysis(): with rescan=True and permission granted (real
        # admin), it proceeds to a real os.path.getsize() on a genuinely
        # nonexistent uploaded file, raising FileNotFoundError with no
        # internal handling in dylib_analysis() itself -> propagates up
        # into static_analyzer_ios()'s own outer except (lines 98-103).
        checksum = '3' * 32
        RecentScansDB.objects.create(
            MD5=checksum, SCAN_TYPE='dylib', FILE_NAME='mylib',
            APP_NAME='MyLib')
        resp = static_analyzer_ios(
            self._admin_request('post', {'re_scan': '1'}), checksum,
            api=True)
        self.assertIsInstance(resp, dict)
        self.assertIn('error', resp)

    def test_a_scan_type_dispatch_and_outer_exception(self):
        # SCAN_TYPE == 'a' dispatches to a_analysis() (line 89); with a
        # genuinely nonexistent uploaded file, the real os.path.getsize()
        # call inside file_size() raises FileNotFoundError, unhandled by
        # a_analysis() itself, propagating to this module's own outer
        # except (lines 98-103).
        checksum = '4' * 32
        RecentScansDB.objects.create(
            MD5=checksum, SCAN_TYPE='a', FILE_NAME='mylib.a',
            APP_NAME='MyStaticLib')
        resp = static_analyzer_ios(self._admin_request(), checksum, api=True)
        self.assertIsInstance(resp, dict)
        self.assertIn('error', resp)

    def test_outer_exception_checksum_none(self):
        # checksum=None -> the real MD5_REGEX.match(None) call inside
        # is_md5() raises a real TypeError -> this module's own outer
        # except, independently of the dispatch path above
        # (lines 98-103).
        resp = static_analyzer_ios(self._admin_request(), None, api=True)
        self.assertIsInstance(resp, dict)
        self.assertIn('error', resp)
