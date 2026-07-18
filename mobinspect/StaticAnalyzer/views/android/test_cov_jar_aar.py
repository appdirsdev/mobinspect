# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage tests for jar_aar.py.

Drives common_analysis()'s permission-denied and invalid-archive branches
with a real RequestFactory + AnonymousUser and a real empty/corrupt
archive, and obfuscated_check()'s real filesystem walk (non-file jar/class
entries, a real class file containing LocalVariableTable, and a genuine
fault-injected exception).
"""
import tempfile
import zipfile
from pathlib import Path

from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, TestCase

from mobinspect.StaticAnalyzer.views.android.jar_aar import (
    aar_analysis,
    jar_analysis,
    obfuscated_check,
)


class CommonAnalysisPermissionTests(TestCase):

    def _anon(self):
        req = RequestFactory().post('/')
        req.user = AnonymousUser()
        return req

    def test_jar_permission_denied(self):
        tmp = Path(tempfile.mkdtemp())
        app_dic = {'md5': 'j' * 32, 'app_dir': tmp}
        resp = jar_analysis(self._anon(), app_dic, False, False)
        self.assertEqual(resp.status_code, 500)

    def test_aar_permission_denied(self):
        tmp = Path(tempfile.mkdtemp())
        app_dic = {'md5': 'a' * 32, 'app_dir': tmp}
        resp = aar_analysis(self._anon(), app_dic, False, False)
        self.assertEqual(resp.status_code, 500)


class CommonAnalysisInvalidArchiveTests(TestCase):

    def _staff(self):
        from django.contrib.auth import get_user_model
        req = RequestFactory().post('/')
        User = get_user_model()
        user, _ = User.objects.get_or_create(
            username='cov_jaar_staff',
            defaults={'is_staff': True, 'is_superuser': True})
        req.user = user
        return req

    def test_jar_invalid_archive_returns_error(self):
        # An empty real zip unzips to no files -> `not app_dic['files']`.
        tmp = Path(tempfile.mkdtemp())
        checksum = 'k' * 32
        with zipfile.ZipFile(tmp / f'{checksum}.jar', 'w'):
            pass
        app_dic = {'md5': checksum, 'app_dir': tmp}
        resp = jar_analysis(self._staff(), app_dic, False, True)
        self.assertIn('error', resp)
        self.assertIn('invalid or corrupt', resp['error'])


class ObfuscatedCheckTests(TestCase):

    def test_skips_non_file_jar_and_class_entries(self):
        # Directories literally named '*.jar' / '*.class' match the rglob
        # patterns but must be skipped by the `is_file()` guards. No
        # exception occurs, so the trailing default ("absent") finding is
        # set with an empty files dict (no class file was ever read).
        app_dir = Path(tempfile.mkdtemp())
        (app_dir / 'fakedir.jar').mkdir()
        (app_dir / 'fakedir.class').mkdir()
        code_an_dic = {'findings': {}}
        obfuscated_check('oc1', app_dir.as_posix(), code_an_dic)
        finding = code_an_dic['findings']['aar_class_obfuscation']
        self.assertEqual(finding['files'], {})
        self.assertIn('absent', finding['metadata']['description'])

    def test_finds_local_variable_table_and_records_finding(self):
        app_dir = Path(tempfile.mkdtemp())
        (app_dir / 'Sample.class').write_text(
            'garbage bytes ... LocalVariableTable ... more garbage',
            encoding='utf-8')
        code_an_dic = {'findings': {}}
        obfuscated_check('oc2', app_dir.as_posix(), code_an_dic)
        self.assertIn('aar_class_obfuscation', code_an_dic['findings'])
        finding = code_an_dic['findings']['aar_class_obfuscation']
        self.assertIn('Sample.class', finding['files'])

    def test_exception_branch_is_caught(self):
        # src=None makes the real `Path(src)` call raise a genuine
        # TypeError, exercising the except branch; execution then falls
        # through (same as the no-finding case) to the trailing default
        # finding.
        code_an_dic = {'findings': {}}
        obfuscated_check('oc3', None, code_an_dic)
        finding = code_an_dic['findings']['aar_class_obfuscation']
        self.assertEqual(finding['files'], {})
