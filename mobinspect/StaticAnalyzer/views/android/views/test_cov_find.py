# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage tests for views/find.py.

Drives the real, login_required-decorated find.run() view directly via
RequestFactory + a real authenticated user (matching test_cov_view_source
.py's ApiRunTests convention for this same views/ package), with real
java/kotlin/smali source files written under an isolated (override_
settings) UPLD_DIR.

NOTE ON A SUSPECTED PRODUCTION BUG (reported, not fixed): find.run() is a
plain Django view registered directly at /find/ (see urls.py), yet every
one of its error branches calls print_n_send_error_response(request, msg,
True) with `api` hardcoded to True. That makes those branches return a
bare dict ({'error': msg}) instead of an HttpResponse. Going through the
real URL via the Django test Client reproduces a real crash: Django's
response-processing middleware (XFrameOptionsMiddleware) raises
AttributeError: 'dict' object has no attribute 'headers' when it tries to
finish processing that "response". Calling run() directly sidesteps that
crash (as this file's convention already does for its sibling
view_source.py) so we can still exercise -- and document -- every real
line of find.py's own logic.
"""
import tempfile
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings

from mobinspect.StaticAnalyzer.views.android.views.find import run

TMP_UPLD = tempfile.mkdtemp(prefix='mobinspect_find_')


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

    def test_invalid_md5_hits_exception_handler(self):
        # Confirms the suspected bug above: the returned value is a bare
        # dict (not an HttpResponse) because api=True is hardcoded.
        out = self._post({
            'md5': 'not-an-md5', 'q': 'x', 'code': 'java',
            'search_type': 'content'})
        self.assertEqual(out, {'error': 'Searching Failed'})

    def test_unknown_search_type(self):
        checksum = '1' * 32
        self._base(checksum)
        out = self._post({
            'md5': checksum, 'q': 'x', 'code': 'java',
            'search_type': 'bogus'})
        self.assertEqual(out, {'error': 'Unknown search type'})

    def test_invalid_directory_structure_stopiteration(self):
        # No java_source/app-src-main-java/kotlin/src folder exists at all.
        checksum = '2' * 32
        self._base(checksum)
        out = self._post({
            'md5': checksum, 'q': 'x', 'code': 'java',
            'search_type': 'content'})
        self.assertEqual(out, {'error': 'Invalid Directory Structure'})

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
        self.assertIn(b'Main.kt', resp.content)
