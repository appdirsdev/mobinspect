# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage test for so.py's permission-denied
branch (line 53), driven with a real RequestFactory + AnonymousUser."""
import tempfile
from pathlib import Path

from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, TestCase

from mobinspect.StaticAnalyzer.views.android.so import so_analysis


class SoAnalysisPermissionTests(TestCase):

    def test_permission_denied(self):
        req = RequestFactory().post('/')
        req.user = AnonymousUser()
        tmp = Path(tempfile.mkdtemp())
        app_dic = {'md5': 's' * 32, 'app_dir': tmp}
        resp = so_analysis(req, app_dic, False, False)
        self.assertEqual(resp.status_code, 500)
