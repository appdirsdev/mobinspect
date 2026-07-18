# -*- coding: utf_8 -*-
"""Real-execution coverage tests for ios/dylib.py.

The full dylib_analysis() pipeline (extraction, library_analysis,
binary_rule_matcher, string metadata, domain/tracker/firebase checks,
save_get_ctx) is already exercised end-to-end elsewhere by real .dylib
uploads (test_integration.py). This adds the one remaining real branch,
mirroring common/test_cov_a.py's ``a_analysis`` permission-denied
convention exactly (both functions share the same independent-binary
analysis shape) -- using its own tempfile.mkdtemp(), never the shared
upload directory.
"""
import tempfile
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase

from mobinspect.StaticAnalyzer.views.ios.dylib import dylib_analysis


class DylibAnalysisTests(TestCase):

    def test_permission_denied_branch(self):
        # A real, non-staff user with no scan permission -> has_permission
        # returns False -> print_n_send_error_response('Permission
        # Denied', False) -> render(..., status=500) (line 66).
        checksum = '2' * 32
        tmp = tempfile.mkdtemp()
        app_dict = {
            'directory': Path(settings.BASE_DIR),
            'file_name': 'lib.dylib',
            'md5_hash': checksum,
            'app_dir': tmp + '/',
            'tools_dir': (Path(settings.BASE_DIR)
                          / 'StaticAnalyzer' / 'tools' / 'ios').as_posix(),
        }
        rf = RequestFactory()
        request = rf.get('/')
        User = get_user_model()
        viewer = User.objects.create_user(
            'dylib_viewer', 'dylib_viewer@example.com', 'pass')
        request.user = viewer
        request.api_user = None
        resp = dylib_analysis(request, app_dict, rescan=False, api=False)
        self.assertEqual(resp.status_code, 500)
