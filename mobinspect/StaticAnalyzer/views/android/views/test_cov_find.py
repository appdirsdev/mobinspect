# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage tests for views/find.py.

Drives the real, login_required-decorated find.run() view directly via
RequestFactory + a real authenticated user (matching test_cov_view_source
.py's ApiRunTests convention for this same views/ package), with real
java/kotlin/smali source files written under an isolated (override_
settings) UPLD_DIR.

find.run() now returns a real ``JsonResponse`` on EVERY path (it previously
returned ``print_n_send_error_response(request, msg, True)`` — a bare dict —
on its error branches, which Django's response middleware could not render,
500ing every error path with ``AttributeError: 'dict' object has no
attribute 'headers'``). The response body is double-encoded
(``JsonResponse(json.dumps(context))``) for wire compatibility with the
source-tree search client, so tests decode it with ``_body()`` below.
"""
import json
import tempfile
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings

from mobinspect.StaticAnalyzer.views.android.views.find import run

TMP_UPLD = tempfile.mkdtemp(prefix='mobinspect_find_')


def _body(resp):
    """Decode find.run()'s DOUBLE-encoded JSON response body to a dict."""
    return json.loads(json.loads(resp.content))


@override_settings(UPLD_DIR=TMP_UPLD)
class FindViewTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.user = User.objects.create_superuser(
            'cov_find_user', 'find@example.com', 'pw')

    def setUp(self):
        self.factory = RequestFactory()

    def _post(self, data):
        req = self.factory.post('/find/', data)
        req.user = self.user
        return run(req)

    def _base(self, checksum):
        d = Path(TMP_UPLD) / checksum
        d.mkdir(parents=True, exist_ok=True)
        return d

    def test_invalid_md5_returns_clean_400(self):
        resp = self._post({
            'md5': 'not-an-md5', 'q': 'x', 'code': 'java',
            'search_type': 'content'})
        self.assertEqual(resp.status_code, 400)
        body = _body(resp)
        self.assertEqual(body['error'], 'Invalid Hash')
        self.assertEqual(body['matches'], [])

    def test_missing_md5_param_returns_clean_400(self):
        # request.POST has no 'md5' at all -> .get() default '' -> not an md5
        # -> clean 400, not a KeyError-driven 500.
        resp = self._post({'q': 'x', 'code': 'java', 'search_type': 'content'})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(_body(resp)['error'], 'Invalid Hash')

    def test_unknown_search_type_returns_clean_400(self):
        checksum = '1' * 32
        self._base(checksum)
        resp = self._post({
            'md5': checksum, 'q': 'x', 'code': 'java',
            'search_type': 'bogus'})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(_body(resp)['error'], 'Unknown search type')

    def test_missing_search_type_returns_clean_400(self):
        # No 'search_type' key -> .get() default '' -> not in the allowed set.
        checksum = '1' * 32
        self._base(checksum)
        resp = self._post({'md5': checksum, 'q': 'x', 'code': 'java'})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(_body(resp)['error'], 'Unknown search type')

    def test_invalid_directory_structure_returns_clean_404(self):
        # No java_source/app-src-main-java/kotlin/src folder exists at all.
        checksum = '2' * 32
        self._base(checksum)
        resp = self._post({
            'md5': checksum, 'q': 'x', 'code': 'java',
            'search_type': 'content'})
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(_body(resp)['error'], 'Invalid Directory Structure')

    def test_unexpected_exception_returns_clean_500(self):
        # The outer except is a defensive catch-all no normal input reaches
        # (all known failure modes return early with their own status). Induce
        # a genuine unexpected error via a narrow patch so the safety-net
        # branch is still exercised end to end (returns a real JsonResponse,
        # NOT the old bare-dict crash).
        checksum = '9' * 32
        self._base(checksum)
        target = ('mobinspect.StaticAnalyzer.views.android.views.find'
                  '.find_java_source_folder')
        with mock.patch(target, side_effect=RuntimeError('boom')):
            resp = self._post({
                'md5': checksum, 'q': 'x', 'code': 'java',
                'search_type': 'content'})
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(_body(resp)['error'], 'Searching Failed')

    def test_smali_content_search_finds_match(self):
        checksum = '3' * 32
        base = self._base(checksum)
        smali_dir = base / 'smali_source' / 'com' / 'example'
        smali_dir.mkdir(parents=True)
        (smali_dir / 'Main.smali').write_text(
            '.class public Lcom/example/Main;\n'
            'super-secret-string-token\n')
        resp = self._post({
            'md5': checksum, 'q': 'super-secret-string-token',
            'code': 'smali', 'search_type': 'content'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Main.smali', resp.content)
        self.assertIn(rb'\"found\": \"1\"', resp.content)

    def test_java_filename_search_finds_match(self):
        checksum = '4' * 32
        base = self._base(checksum)
        java_dir = base / 'java_source' / 'com' / 'example'
        java_dir.mkdir(parents=True)
        (java_dir / 'MainActivity.java').write_text(
            'package com.example;\nclass MainActivity {}\n')
        resp = self._post({
            'md5': checksum, 'q': 'MainActivity', 'code': 'java',
            'search_type': 'filename'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'MainActivity.java', resp.content)

    def test_no_matches_returns_zero_found(self):
        checksum = '5' * 32
        base = self._base(checksum)
        java_dir = base / 'java_source'
        java_dir.mkdir(parents=True)
        (java_dir / 'Empty.java').write_text('class Empty {}\n')
        resp = self._post({
            'md5': checksum, 'q': 'nonexistent_token_xyz', 'code': 'java',
            'search_type': 'content'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(rb'\"found\": \"0\"', resp.content)

    def test_kotlin_source_folder_content_search(self):
        checksum = '6' * 32
        base = self._base(checksum)
        kt_dir = base / 'app' / 'src' / 'main' / 'kotlin'
        kt_dir.mkdir(parents=True)
        (kt_dir / 'Main.kt').write_text('fun main() { println("hi") }')
        resp = self._post({
            'md5': checksum, 'q': 'println', 'code': 'java',
            'search_type': 'content'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Main.kt', resp.content)
