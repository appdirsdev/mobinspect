# -*- coding: utf_8 -*-
"""Real-execution unit tests for android view_source.py (STRICT: NO mocks).

Every test drives the real ``run`` view (and the ``send_json`` / ``send_error``
helpers through it) with real files placed on disk under a real (temp)
UPLD_DIR, real Django requests (RequestFactory / Client) and a real created
superuser. No mocking, no monkeypatching of internal logic, no fake returns.

The android source viewer resolves ``<UPLD_DIR>/<md5>`` and then either
``smali_source`` (type == 'smali') or the java/kotlin source folder found by
``find_java_source_folder``. We reproduce those real on-disk layouts so the
view reads real file bytes.
"""
import json
import os
import tempfile
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import (
    Client,
    RequestFactory,
    TestCase,
    override_settings,
)

from mobsf.StaticAnalyzer.views.android.views.view_source import (
    run,
    send_error,
    send_json,
)

# Real, valid 32-hex md5 values used as the scan hash / directory name.
MD5 = 'a' * 32
MD5_NO_JAVA = 'b' * 32

# Module-level real temp dir used as UPLD_DIR for every test.
TMP_UPLD = tempfile.mkdtemp(prefix='mobsf_android_vs_')

JAVA_CONTENT = 'package com.example;\npublic class Main { int x = 1; }\n'
SMALI_CONTENT = '.class public Lcom/example/Main;\n.super Ljava/lang/Object;\n'


def _build_fixtures():
    """Create real files under TMP_UPLD/<md5> exercising every branch."""
    base = Path(TMP_UPLD) / MD5
    java_src = base / 'java_source' / 'com' / 'example'
    java_src.mkdir(parents=True, exist_ok=True)
    (java_src / 'Main.java').write_text(JAVA_CONTENT)

    smali_src = base / 'smali_source' / 'com' / 'example'
    smali_src.mkdir(parents=True, exist_ok=True)
    (smali_src / 'Main.smali').write_text(SMALI_CONTENT)

    # A real file OUTSIDE the java_source root, and a symlink inside it that
    # points to that file. The form allows the name (no '..', .java suffix)
    # but is_safe_path -> realpath escapes the root -> blocked branch.
    outside = Path(TMP_UPLD) / 'outside_secret.java'
    outside.write_text('SECRET OUTSIDE ROOT\n')
    link = base / 'java_source' / 'link.java'
    if link.exists() or link.is_symlink():
        link.unlink()
    os.symlink(outside, link)

    # A scan dir that exists but has NO java/kotlin source folder at all
    # -> find_java_source_folder raises StopIteration.
    (Path(TMP_UPLD) / MD5_NO_JAVA).mkdir(parents=True, exist_ok=True)


@override_settings(UPLD_DIR=TMP_UPLD)
class ApiRunTests(TestCase):
    """Drive run(request, api=True) against real files on disk."""

    @classmethod
    def setUpTestData(cls):
        _build_fixtures()

    def setUp(self):
        self.factory = RequestFactory()

    def _api(self, fil, typ='java', md5=MD5):
        req = self.factory.post(
            '/view_file/',
            {'file': fil, 'hash': md5, 'type': typ})
        return run(req, api=True)

    def test_api_java_success(self):
        ctx = self._api('com/example/Main.java', typ='java')
        self.assertEqual(ctx['type'], 'java')
        self.assertIn('class Main', ctx['data'])
        self.assertEqual(ctx['file'], 'Main.java')
        self.assertEqual(ctx['title'], 'Main.java')

    def test_api_smali_success(self):
        ctx = self._api('com/example/Main.smali', typ='smali')
        self.assertEqual(ctx['type'], 'smali')
        self.assertIn('Lcom/example/Main;', ctx['data'])
        self.assertEqual(ctx['file'], 'Main.smali')

    def test_api_form_invalid_traversal(self):
        out = self._api('../evil.java', typ='java')
        # form clean_file raises 'Attack Detected' -> error dict under 'error'
        self.assertIn('error', out)
        self.assertIn('file', out['error'])

    def test_api_form_invalid_bad_extension(self):
        out = self._api('Main.exe', typ='java')
        self.assertIn('error', out)
        self.assertIn('file', out['error'])

    def test_api_form_invalid_bad_hash(self):
        out = self._api('com/example/Main.java', typ='java', md5='zzz')
        self.assertIn('error', out)
        self.assertIn('hash', out['error'])

    def test_api_form_invalid_bad_type(self):
        out = self._api('com/example/Main.java', typ='bogus')
        self.assertIn('error', out)
        self.assertIn('type', out['error'])

    def test_api_missing_file_error(self):
        # valid form + safe path but file absent -> read_text raises -> error
        out = self._api('com/example/Absent.java', typ='java')
        self.assertIn('error', out)

    def test_api_no_java_source_stopiteration(self):
        # dir exists but no java/kotlin source folder -> StopIteration branch
        out = self._api('Main.java', typ='java', md5=MD5_NO_JAVA)
        self.assertIn('error', out)
        self.assertEqual(out['error'], 'Invalid directory or file extension')

    def test_api_symlink_path_traversal_blocked(self):
        # symlink inside java_source resolves outside root -> is_safe_path False
        out = self._api('link.java', typ='java')
        self.assertIn('error', out)
        self.assertEqual(out['error'], 'Path Traversal Detected!')

    def test_api_smali_missing_folder_error(self):
        # smali type on a dir without smali_source -> read raises -> error
        out = self._api('Main.smali', typ='smali', md5=MD5_NO_JAVA)
        self.assertIn('error', out)


@override_settings(UPLD_DIR=TMP_UPLD)
class WebRunTests(TestCase):
    """Drive the web path via real Client + real superuser (login_required)."""

    @classmethod
    def setUpTestData(cls):
        _build_fixtures()
        User = get_user_model()
        cls.user = User.objects.create_superuser(
            'android_vs_admin', 'android_vs_admin@example.com',
            'Str0ngPass!123')

    def setUp(self):
        self.client = Client()
        self.client.force_login(self.user)

    def _get(self, fil, typ='java', md5=MD5, extra=None):
        params = {'file': fil, 'md5': md5, 'type': typ}
        if extra:
            params.update(extra)
        return self.client.get('/view_file/', params)

    def test_web_java_renders(self):
        resp = self._get('com/example/Main.java', typ='java')
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Main.java')

    def test_web_smali_renders(self):
        resp = self._get('com/example/Main.smali', typ='smali')
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Main.smali')

    def test_web_form_invalid_traversal(self):
        resp = self._get('../secret.java', typ='java')
        self.assertNotEqual(resp.status_code, 200)

    def test_web_missing_file(self):
        resp = self._get('com/example/Absent.java', typ='java')
        self.assertNotEqual(resp.status_code, 200)

    def test_web_stopiteration(self):
        resp = self._get('Main.java', typ='java', md5=MD5_NO_JAVA)
        self.assertNotEqual(resp.status_code, 200)

    def test_web_json_success(self):
        # json=1 -> api_mode + json_resp -> JsonResponse with the context dict
        resp = self._get(
            'com/example/Main.java', typ='java', extra={'json': '1'})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertEqual(data['type'], 'java')
        self.assertIn('class Main', data['data'])

    def test_web_json_error(self):
        # json=1 + missing file -> JsonResponse carrying the error dict
        resp = self._get(
            'com/example/Absent.java', typ='java', extra={'json': '1'})
        data = json.loads(resp.content)
        self.assertIn('error', data)

    def test_web_json_symlink_blocked(self):
        resp = self._get('link.java', typ='java', extra={'json': '1'})
        data = json.loads(resp.content)
        self.assertEqual(data['error'], 'Path Traversal Detected!')


class HelperTests(TestCase):
    """Real helper coverage: send_json / send_error without mocks."""

    def setUp(self):
        self.factory = RequestFactory()

    def test_send_json_wraps_dict(self):
        resp = send_json({'a': 1})
        self.assertEqual(json.loads(resp.content), {'a': 1})

    def test_send_error_api_returns_dict(self):
        req = self.factory.post('/view_file/')
        out = send_error(req, 'boom', api_mode=True, json_resp=False)
        self.assertEqual(out, {'error': 'boom'})

    def test_send_error_json_wraps_response(self):
        req = self.factory.post('/view_file/')
        resp = send_error(req, 'boom', api_mode=True, json_resp=True)
        self.assertEqual(json.loads(resp.content), {'error': 'boom'})
