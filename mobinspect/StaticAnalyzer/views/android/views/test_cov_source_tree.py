# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage tests for views/source_tree.py.

Drives the real, login_required-decorated source_tree.run() view (and
its tree_index_maker() generator, which really renders the two real
treeview_folder.html / treeview_file.html templates) directly via
RequestFactory + a real authenticated user (matching the sibling
test_cov_find.py / test_cov_manifest_view.py convention for this same
views/ package), with real nested java/smali source trees written under
an isolated (override_settings) UPLD_DIR.
"""
import tempfile
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings

from mobinspect.StaticAnalyzer.views.android.views.source_tree import run

TMP_UPLD = tempfile.mkdtemp(prefix='mobinspect_srctree_')


@override_settings(UPLD_DIR=TMP_UPLD)
class SourceTreeRunTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.user = User.objects.create_superuser(
            'cov_srctree_user', 'srctree@example.com', 'pw')

    def setUp(self):
        self.factory = RequestFactory()

    def _get(self, params):
        req = self.factory.get('/source_tree/', params)
        req.user = self.user
        return run(req)

    def _base(self, checksum):
        d = Path(TMP_UPLD) / checksum
        d.mkdir(parents=True, exist_ok=True)
        return d

    def test_real_java_tree_renders_nested_folders_and_files(self):
        # A real nested folder (com/example) plus a real file inside it
        # exercises both branches of tree_index_maker's _index generator:
        # the is_dir() -> recurse-and-yield-folder branch, and the
        # yield-file leaf branch.
        checksum = '1' * 32
        base = self._base(checksum)
        java_src = base / 'java_source' / 'com' / 'example'
        java_src.mkdir(parents=True)
        (java_src / 'Main.java').write_text(
            'package com.example;\nclass Main {}\n')
        resp = self._get({'md5': checksum, 'type': 'java'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Main.java', resp.content)

    def test_real_smali_tree_renders(self):
        # typ == 'smali' -> src = base / 'smali_source' (line 56-57).
        checksum = '2' * 32
        base = self._base(checksum)
        smali_src = base / 'smali_source' / 'com' / 'example'
        smali_src.mkdir(parents=True)
        (smali_src / 'Main.smali').write_text(
            '.class public Lcom/example/Main;\n')
        resp = self._get({'md5': checksum, 'type': 'smali'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Main.smali', resp.content)

    def test_invalid_md5_returns_error_response(self):
        resp = self._get({'md5': 'not-an-md5', 'type': 'java'})
        self.assertNotEqual(resp.status_code, 200)

    def test_stopiteration_no_java_source_folder(self):
        # A scan dir that exists but has none of the four known
        # java/kotlin source layouts -> find_java_source_folder raises
        # StopIteration -> the 'Invalid Directory Structure' branch.
        checksum = '3' * 32
        self._base(checksum)
        resp = self._get({'md5': checksum, 'type': 'java'})
        self.assertNotEqual(resp.status_code, 200)

    def test_missing_type_param_hits_exception_handler(self):
        # No 'type' in request.GET -> KeyError inside the try -> outer
        # except Exception branch (logger.exception + error response).
        checksum = '4' * 32
        self._base(checksum)
        req = self.factory.get('/source_tree/', {'md5': checksum})
        req.user = self.user
        resp = run(req)
        self.assertNotEqual(resp.status_code, 200)
