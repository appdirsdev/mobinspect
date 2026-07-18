# -*- coding: utf_8 -*-
"""Real-execution coverage tests for common/a.py (independent .a static
library analysis).

The full a_analysis() pipeline (extraction, library_analysis,
binary_rule_matcher, string metadata, domain/tracker/firebase checks,
save_get_ctx) is already exercised end-to-end elsewhere by real .a uploads
(test_integration.py). These tests cover the few remaining real branches
directly, without touching the shared upload directory (each test uses its
own tempfile.mkdtemp()):

* extract_n_get_files()'s ``for i in dst.rglob('*.a')`` loop -- a real
  nested ``.a``-named file is seeded into the real extraction directory
  before calling the real function (no mocking; arpy's real extraction of
  a genuine static lib runs alongside it).
* a_analysis()'s "Permission Denied" branch -- a real RBAC user without
  scan permission, exactly mirroring ios/test_cov_ipa.py's
  ``test_permission_denied_branch`` convention.
"""
import os
import tempfile
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import RequestFactory, SimpleTestCase, TestCase

from mobinspect.StaticAnalyzer.views.common.a import (
    a_analysis,
    extract_n_get_files,
)

SAMPLES_DIR = os.path.normpath(
    os.path.join(settings.BASE_DIR, '..', 'test_files'))
MACHO_STATIC_LIB = os.path.join(SAMPLES_DIR, 'macho_static_lib.a')


class ExtractNGetFilesTests(SimpleTestCase):

    def test_nested_a_file_is_listed(self):
        # Real extraction of a real .a archive into a real directory that
        # already contains a real, independently-created nested `.a` file
        # -- the rglob('*.a') loop (line 58) genuinely finds and appends
        # it. No part of this is mocked; arpy still does the real
        # extraction of macho_static_lib.a's real members alongside it.
        checksum = 'a' * 32
        dst = Path(tempfile.mkdtemp())
        seeded_dir = dst / 'static_objects' / 'nested'
        seeded_dir.mkdir(parents=True)
        (seeded_dir / 'inner.a').write_bytes(b'!<arch>\n')
        files = extract_n_get_files(checksum, MACHO_STATIC_LIB, dst.as_posix())
        self.assertEqual(len(files), 1)


class AAnalysisTests(TestCase):

    def _build_app_dict(self, checksum, app_dir, file_name='lib.a'):
        return {
            'directory': Path(settings.BASE_DIR),
            'file_name': file_name,
            'md5_hash': checksum,
            'app_dir': app_dir if app_dir.endswith('/') else app_dir + '/',
            'tools_dir': (Path(settings.BASE_DIR)
                          / 'StaticAnalyzer' / 'tools' / 'ios').as_posix(),
        }

    def test_permission_denied_branch(self):
        # A real, non-staff user with no scan permission -> has_permission
        # returns False -> print_n_send_error_response('Permission
        # Denied', False) -> render(..., status=500) (line 76).
        checksum = '1' * 32
        tmp = tempfile.mkdtemp()
        app_dict = self._build_app_dict(checksum, tmp)
        rf = RequestFactory()
        request = rf.get('/')
        User = get_user_model()
        viewer = User.objects.create_user(
            'a_py_viewer', 'a_py_viewer@example.com', 'pass')
        request.user = viewer
        request.api_user = None
        resp = a_analysis(request, app_dict, rescan=False, api=False)
        self.assertEqual(resp.status_code, 500)
