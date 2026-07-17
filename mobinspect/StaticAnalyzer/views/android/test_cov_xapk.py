# -*- coding: utf_8 -*-
"""Real-execution unit tests for xapk.py (STRICT: NO mocks).

Every test drives the real handle_xapk / handle_split_apk / handle_aab
functions with real inputs: the bundled android_xapk.xapk sample, crafted
real ZIP archives with real manifest.json variants, and the real Django
test DB (unzip -> append_scan_status issues a real ORM query).
"""
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

from django.test import TestCase

from mobinspect.StaticAnalyzer.views.android.xapk import (
    handle_aab,
    handle_split_apk,
    handle_xapk,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
TEST_FILES = REPO_ROOT / 'test_files'
XAPK_SAMPLE = TEST_FILES / 'android_xapk.xapk'

MD5 = 'aabbccddeeff00112233445566778899'


class XapkTestBase(TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.app_dir = Path(self._tmp.name)
        self.app_dic = {'md5': MD5, 'app_dir': self.app_dir}

    def tearDown(self):
        self._tmp.cleanup()

    def _write_xapk_from_manifest(self, manifest_obj, extra_files=None):
        """Craft a real .xapk (zip) with the given manifest.json object."""
        xapk_path = self.app_dir / f'{MD5}.xapk'
        with zipfile.ZipFile(xapk_path, 'w') as z:
            if manifest_obj is not None:
                z.writestr('manifest.json', json.dumps(manifest_obj))
            for fname in (extra_files or []):
                z.writestr(fname, b'PK-fake-apk-content')
        return xapk_path


class HandleXapkTests(XapkTestBase):

    def test_real_xapk_sample_extracts_base_apk(self):
        """Real sample: base split apk is moved to <md5>.apk, returns True."""
        shutil.copy(XAPK_SAMPLE, self.app_dir / f'{MD5}.xapk')
        result = handle_xapk(self.app_dic)
        self.assertTrue(result)
        moved = self.app_dir / f'{MD5}.apk'
        self.assertTrue(moved.exists())
        # The extracted apk is a real zip (the base APK).
        self.assertTrue(zipfile.is_zipfile(moved))

    def test_missing_manifest_returns_false(self):
        """XAPK without manifest.json -> False."""
        self._write_xapk_from_manifest(None, extra_files=['base.apk'])
        self.assertIs(handle_xapk(self.app_dic), False)

    def test_empty_manifest_returns_false(self):
        """manifest.json that loads to a falsy object -> False."""
        self._write_xapk_from_manifest({})
        self.assertIs(handle_xapk(self.app_dic), False)

    def test_no_split_apks_returns_false(self):
        """manifest.json without split_apks -> False."""
        self._write_xapk_from_manifest({'package_name': 'com.x'})
        self.assertIs(handle_xapk(self.app_dic), False)

    def test_no_base_id_returns_none(self):
        """split_apks present but none with id 'base' -> None."""
        manifest = {'split_apks': [
            {'file': 'config.en.apk', 'id': 'config.en'},
        ]}
        self._write_xapk_from_manifest(manifest, extra_files=['config.en.apk'])
        self.assertIsNone(handle_xapk(self.app_dic))

    def test_base_with_path_traversal_returns_none(self):
        """base file with path traversal fails is_safe_path -> None."""
        manifest = {'split_apks': [
            {'file': '../evil.apk', 'id': 'base'},
        ]}
        self._write_xapk_from_manifest(manifest, extra_files=['base.apk'])
        self.assertIsNone(handle_xapk(self.app_dic))
        # No apk should have been produced.
        self.assertFalse((self.app_dir / f'{MD5}.apk').exists())

    def test_base_apk_moved_for_crafted_manifest(self):
        """Crafted valid manifest: base file is moved to <md5>.apk -> True."""
        manifest = {'split_apks': [
            {'file': 'config.en.apk', 'id': 'config.en'},
            {'file': 'mybase.apk', 'id': 'base'},
        ]}
        self._write_xapk_from_manifest(
            manifest, extra_files=['config.en.apk', 'mybase.apk'])
        self.assertTrue(handle_xapk(self.app_dic))
        self.assertTrue((self.app_dir / f'{MD5}.apk').exists())


class HandleSplitApkTests(XapkTestBase):

    def _write_apks(self, names):
        apks_path = self.app_dir / f'{MD5}.apk'
        with zipfile.ZipFile(apks_path, 'w') as z:
            for n in names:
                z.writestr(n, b'PK-fake-apk-content')
        return apks_path

    def test_previously_extracted_returns_true(self):
        """AndroidManifest.xml already present -> early True."""
        (self.app_dir / 'AndroidManifest.xml').write_text('<manifest/>')
        # No .apk archive needed; short-circuits before unzip.
        self.assertTrue(handle_split_apk(self.app_dic))

    def test_base_apk_entry_moved(self):
        """Archive containing a *base.apk entry -> moved, returns True."""
        self._write_apks(['config.en.apk', 'base.apk'])
        self.assertTrue(handle_split_apk(self.app_dic))
        self.assertTrue((self.app_dir / f'{MD5}.apk').exists())

    def test_non_config_apk_moved(self):
        """No base.apk but a non-config .apk -> moved, returns True."""
        self._write_apks(['app-main.apk'])
        self.assertTrue(handle_split_apk(self.app_dic))
        self.assertTrue((self.app_dir / f'{MD5}.apk').exists())

    def test_only_config_apks_returns_none(self):
        """Archive with only config.* apks -> None (nothing usable)."""
        self._write_apks(['config.en.apk', 'config.xxhdpi.apk'])
        self.assertIsNone(handle_split_apk(self.app_dic))

    def test_real_xapk_as_split_source(self):
        """Real sample used as split-apk archive: has a base -> True."""
        shutil.copy(XAPK_SAMPLE, self.app_dir / f'{MD5}.apk')
        self.assertTrue(handle_split_apk(self.app_dic))


class HandleAabTests(XapkTestBase):

    def test_previously_converted_returns_true(self):
        """AndroidManifest.xml present -> early True, no bundletool needed."""
        (self.app_dir / 'AndroidManifest.xml').write_text('<manifest/>')
        self.app_dic['tools_dir'] = self.app_dir
        self.assertTrue(handle_aab(self.app_dic))
