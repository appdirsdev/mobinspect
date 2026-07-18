# -*- coding: utf_8 -*-
"""Real-execution (no-mock, except narrowly-noted androguard-internal
patches) coverage tests for app.py.

Drives real aapt/aapt2 (via aapt_parse), the real androguard4 APK parser
(via androguard_parse) with genuinely malformed real zip/apk fixtures, and
the real app-name-from-values-folder resolution helpers with real files
(including a non-UTF-8 file to force a real UnicodeDecodeError).
"""
import tempfile
import zipfile
from pathlib import Path

from django.test import TestCase

from mobinspect.StaticAnalyzer.tools.androguard4 import apk as apk_mod
from mobinspect.StaticAnalyzer.views.android import app as app_mod
from mobinspect.StaticAnalyzer.views.android.app import (
    aapt_parse,
    androguard_parse,
    get_app_name_from_file,
    get_app_name_from_values_folder,
    get_apk_name,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
APK_PATH = (REPO_ROOT / 'test_files' / 'android.apk').as_posix()


class AaptParseTests(TestCase):

    def test_populates_files_when_not_already_set(self):
        # Real aapt binary lists real files; app_dict['files'] is not
        # pre-populated here (unlike the production pipeline, which always
        # unzips first), so the `if not app_dict.get('files')` branch runs.
        app_dict = {'md5': 'apc1'}
        app_dict['app_path'] = APK_PATH
        aapt_parse(app_dict)
        self.assertIn('files', app_dict)
        self.assertIn('AndroidManifest.xml', app_dict['files'])
        self.assertTrue(app_dict['apk_strings'])

    def test_generic_exception_branch_missing_app_path(self):
        # No 'app_path' key -> KeyError inside the try -> generic except.
        app_dict = {'md5': 'apc2'}
        aapt_parse(app_dict)
        self.assertEqual(app_dict['apk_features'], {})
        self.assertEqual(app_dict['apk_strings'], [])

    def test_filenotfound_branch_when_aapt_missing(self):
        # Narrow, single-callsite monkeypatch (per project rule 1): this
        # dev host has a real Android SDK (aapt/aapt2) installed, used by
        # every other aapt test, so genuinely hiding it here would be
        # disruptive. AndroidAAPT is patched, for one call, to raise the
        # same FileNotFoundError it raises for real when neither tool is
        # found (see test_cov_aapt.py for that real-execution case).
        orig = app_mod.aapt.AndroidAAPT

        def _raise(_path):
            raise FileNotFoundError('aapt and aapt2 found')

        app_mod.aapt.AndroidAAPT = _raise
        try:
            app_dict = {'md5': 'apc3', 'app_path': APK_PATH}
            aapt_parse(app_dict)
        finally:
            app_mod.aapt.AndroidAAPT = orig
        self.assertEqual(app_dict['apk_features'], {})


class AndroguardParseTests(TestCase):

    def test_not_a_zip_hits_outer_except(self):
        # A file that isn't a zip at all makes apk.APK() itself raise
        # (real androguard ValueError: EOCD signature not found).
        tmp = tempfile.NamedTemporaryFile(suffix='.apk', delete=False)
        tmp.write(b'this is not a zip file at all, no PK header')
        tmp.close()
        app_dict = {'md5': 'agp1', 'app_path': tmp.name}
        androguard_parse(app_dict)
        self.assertIsNone(app_dict['androguard_apk'])
        Path(tmp.name).unlink(missing_ok=True)

    def test_falsy_apk_object_short_circuits(self):
        # Narrow, single-callsite monkeypatch (per project rule 1):
        # apk.APK() always returns a truthy instance in practice (the class
        # defines no __bool__/__len__), so the `if not a:` guard in
        # androguard_parse looks like dead defensive code under real
        # execution -- reported as a suspected issue, not fixed. This patch
        # substitutes a deliberately falsy stand-in for one call to prove
        # the guard's own behaviour (early return, androguard_apk stays
        # None) without touching production code.
        class Falsy:
            def __bool__(self):
                return False

        orig = apk_mod.APK
        apk_mod.APK = lambda path: Falsy()
        try:
            app_dict = {'md5': 'agp2', 'app_path': APK_PATH}
            androguard_parse(app_dict)
        finally:
            apk_mod.APK = orig
        self.assertIsNone(app_dict['androguard_apk'])

    def test_manifest_parse_exception_branch(self):
        # A real zip with a garbage (non-AXML) AndroidManifest.xml: the
        # androguard4 APK() constructor tolerates it (no manifest object
        # parsed), but get_android_manifest_axml() then returns None, and
        # .get_xml() on None raises AttributeError for real.
        tmp = Path(tempfile.mkdtemp()) / 'bad_manifest.apk'
        with zipfile.ZipFile(tmp, 'w') as z:
            z.writestr('AndroidManifest.xml', b'not valid axml binary data')
            z.writestr('classes.dex', b'dex\n035\x00garbage')
        app_dict = {'md5': 'agp3', 'app_path': tmp.as_posix()}
        androguard_parse(app_dict)
        self.assertIsNotNone(app_dict['androguard_apk'])
        self.assertIsNone(app_dict['androguard_manifest_xml'])

    def test_app_name_icon_resources_exception_branches(self):
        # Narrow, single-callsite monkeypatches (per project rule 1): the
        # real androguard4 get_app_name()/get_app_icon()/get_android_
        # resources() swallow their own internal resolution failures (each
        # wraps risky lookups in its own try/except), so no crafted-but-
        # parseable APK could make them raise from app.py's perspective.
        # Each accessor is patched, one at a time, to raise for exactly the
        # one call androguard_parse makes.
        def _raiser(name):
            def _fn(self, *a, **k):
                raise RuntimeError(f'boom-{name}')
            return _fn

        for attr in ('get_app_name', 'get_app_icon', 'get_android_resources'):
            orig = getattr(apk_mod.APK, attr)
            setattr(apk_mod.APK, attr, _raiser(attr))
            try:
                app_dict = {'md5': f'agp_{attr}', 'app_path': APK_PATH}
                androguard_parse(app_dict)
                self.assertIsNotNone(app_dict['androguard_apk'])
            finally:
                setattr(apk_mod.APK, attr, orig)


class GetAppNameFromFileTests(TestCase):

    def test_finds_app_name(self):
        tmp = Path(tempfile.mkdtemp()) / 'strings.xml'
        tmp.write_text(
            '<resources><string name="app_name">MyRealApp</string>'
            '</resources>', encoding='utf-8')
        self.assertEqual(get_app_name_from_file(tmp.as_posix()), 'MyRealApp')

    def test_no_match_returns_empty(self):
        tmp = Path(tempfile.mkdtemp()) / 'strings.xml'
        tmp.write_text(
            '<resources><string name="other">X</string></resources>',
            encoding='utf-8')
        self.assertEqual(get_app_name_from_file(tmp.as_posix()), '')


class GetAppNameFromValuesFolderTests(TestCase):

    def test_returns_empty_when_no_file_has_app_name(self):
        values_dir = Path(tempfile.mkdtemp())
        (values_dir / 'strings.xml').write_text(
            '<resources><string name="other">X</string></resources>',
            encoding='utf-8')
        (values_dir / 'colors.xml').write_text(
            '<resources><color name="c">#fff</color></resources>',
            encoding='utf-8')
        self.assertEqual(
            get_app_name_from_values_folder(values_dir.as_posix()), '')

    def test_finds_app_name_in_second_file(self):
        values_dir = Path(tempfile.mkdtemp())
        (values_dir / 'colors.xml').write_text(
            '<resources><color name="c">#fff</color></resources>',
            encoding='utf-8')
        (values_dir / 'strings.xml').write_text(
            '<resources><string name="app_name">Found</string></resources>',
            encoding='utf-8')
        self.assertEqual(
            get_app_name_from_values_folder(values_dir.as_posix()), 'Found')


class GetApkNameTests(TestCase):

    def test_androguard_name_used_directly(self):
        app_dic = {
            'app_dir': tempfile.mkdtemp(),
            'androguard_apk_name': 'DirectName',
        }
        get_apk_name(app_dic)
        self.assertEqual(app_dic['real_name'], 'DirectName')

    def test_apk_features_label_used_when_no_androguard_name(self):
        app_dic = {
            'app_dir': tempfile.mkdtemp(),
            'androguard_apk_name': None,
            'apk_features': {'application_label': 'FeatLabel'},
        }
        get_apk_name(app_dic)
        self.assertEqual(app_dic['real_name'], 'FeatLabel')

    def test_apk_values_folder_fallback_success(self):
        app_dir = Path(tempfile.mkdtemp())
        values = app_dir / 'apktool_out' / 'res' / 'values'
        values.mkdir(parents=True)
        (values / 'strings.xml').write_text(
            '<resources><string name="app_name">FromValues</string>'
            '</resources>', encoding='utf-8')
        app_dic = {
            'app_dir': app_dir.as_posix(),
            'androguard_apk_name': None,
            # Non-empty (so the 'is APK' branch is taken) but no
            # application_label -> falls through to the values-folder
            # fallback.
            'apk_features': {'package': 'com.x'},
        }
        get_apk_name(app_dic)
        self.assertEqual(app_dic['real_name'], 'FromValues')

    def test_apk_values_folder_fallback_exception_branch(self):
        # A non-UTF-8 file in the values folder makes get_app_name_from_
        # file's open(..., encoding='utf-8') raise a real
        # UnicodeDecodeError, exercising the except branch (real_name
        # stays '' and 'Cannot find app name' logs).
        app_dir = Path(tempfile.mkdtemp())
        values = app_dir / 'apktool_out' / 'res' / 'values'
        values.mkdir(parents=True)
        (values / 'strings.xml').write_bytes(b'\xff\xfe\x00 not utf8 \x80')
        app_dic = {
            'app_dir': app_dir.as_posix(),
            'androguard_apk_name': None,
            'apk_features': {'package': 'com.x'},
        }
        get_apk_name(app_dic)
        self.assertEqual(app_dic['real_name'], '')

    def test_source_code_branch_studio_layout_success(self):
        app_dir = Path(tempfile.mkdtemp())
        values = app_dir / 'app' / 'src' / 'main' / 'res' / 'values'
        values.mkdir(parents=True)
        (values / 'strings.xml').write_text(
            '<resources><string name="app_name">SrcApp</string>'
            '</resources>', encoding='utf-8')
        app_dic = {
            'app_dir': app_dir.as_posix(),
            'androguard_apk_name': None,
            'apk_features': None,
        }
        get_apk_name(app_dic)
        self.assertEqual(app_dic['real_name'], 'SrcApp')

    def test_source_code_branch_exception_branch(self):
        app_dir = Path(tempfile.mkdtemp())
        values = app_dir / 'res' / 'values'
        values.mkdir(parents=True)
        (values / 'strings.xml').write_bytes(b'\xff\xfe\x00 not utf8 \x80')
        app_dic = {
            'app_dir': app_dir.as_posix(),
            'androguard_apk_name': None,
            'apk_features': None,
        }
        get_apk_name(app_dic)
        self.assertEqual(app_dic['real_name'], '')

    def test_no_name_found_anywhere_logs_warning(self):
        app_dir = Path(tempfile.mkdtemp())
        app_dic = {
            'app_dir': app_dir.as_posix(),
            'androguard_apk_name': None,
            'apk_features': None,
        }
        get_apk_name(app_dic)
        self.assertEqual(app_dic['real_name'], '')
