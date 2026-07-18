# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage tests for aapt.py.

Drives the real aapt/aapt2 binaries from the local Android SDK
(~/Library/Android/sdk/build-tools) against the real test_files/android.apk
sample and deliberately-bad inputs. One narrow, documented monkeypatch of
find_aapt is used solely to reach the "neither tool found" branch, since
this dev host has a real Android SDK installed that cannot practically be
hidden/removed just for this test (rule 1 exception).
"""
import tempfile
from pathlib import Path

from django.test import TestCase, override_settings

from mobinspect.StaticAnalyzer.views.android import aapt as aapt_mod
from mobinspect.StaticAnalyzer.views.android.aapt import AndroidAAPT

REPO_ROOT = Path(__file__).resolve().parents[4]
APK_PATH = (REPO_ROOT / 'test_files' / 'android.apk').as_posix()


def _real_tool_paths():
    a = AndroidAAPT(APK_PATH)
    return a.aapt2_path, a.aapt_path


class AndroidAAPTInitTests(TestCase):

    def test_aapt2_binary_setting_override(self):
        aapt2_path, _ = _real_tool_paths()
        with override_settings(AAPT2_BINARY=aapt2_path):
            a = AndroidAAPT(APK_PATH)
            self.assertEqual(a.aapt2_path, aapt2_path)

    def test_aapt_binary_setting_override(self):
        _, aapt_path = _real_tool_paths()
        with override_settings(AAPT_BINARY=aapt_path):
            a = AndroidAAPT(APK_PATH)
            self.assertEqual(a.aapt_path, aapt_path)

    def test_raises_filenotfound_when_neither_tool_found(self):
        # Narrow, single-function monkeypatch (per project rule 1): this
        # host has a real Android SDK installed (used by every other aapt
        # test), so genuinely hiding it just to prove the "not found"
        # branch would be disruptive. find_aapt is patched to always miss.
        orig = aapt_mod.find_aapt
        aapt_mod.find_aapt = lambda name: None
        try:
            with self.assertRaises(FileNotFoundError):
                AndroidAAPT(APK_PATH)
        finally:
            aapt_mod.find_aapt = orig


class ExecuteCommandTests(TestCase):

    def test_called_process_error_is_caught_and_returns_none(self):
        # Real aapt2 binary, but 'dump badging' on a garbage (non-APK) file
        # makes the real subprocess exit non-zero for real.
        aapt2_path, aapt_path = _real_tool_paths()
        tmp = tempfile.NamedTemporaryFile(suffix='.apk', delete=False)
        tmp.write(b'not a real apk')
        tmp.close()
        a = AndroidAAPT(tmp.name)
        a.aapt2_path = aapt2_path
        a.aapt_path = aapt_path
        out = a._execute_command([aapt2_path, 'dump', 'badging', tmp.name])
        self.assertIsNone(out)
        Path(tmp.name).unlink(missing_ok=True)


class GetApkFilesTests(TestCase):

    def test_real_apk_lists_files(self):
        a = AndroidAAPT(APK_PATH)
        files = a.get_apk_files()
        self.assertIsInstance(files, list)
        self.assertTrue(files)
        self.assertIn('AndroidManifest.xml', files)

    def test_garbage_input_returns_empty_list(self):
        tmp = tempfile.NamedTemporaryFile(suffix='.apk', delete=False)
        tmp.write(b'not a real apk')
        tmp.close()
        a = AndroidAAPT(tmp.name)
        self.assertEqual(a.get_apk_files(), [])
        Path(tmp.name).unlink(missing_ok=True)


class GetApkStringsAndFeaturesEmptyOutputTests(TestCase):
    """A garbage (non-APK) input makes the real aapt2 'dump' subcommands
    fail for real, so _execute_command returns None -> the falsy-output
    branches of get_apk_strings/get_apk_features run for real."""

    def setUp(self):
        tmp = tempfile.NamedTemporaryFile(suffix='.apk', delete=False)
        tmp.write(b'not a real apk')
        tmp.close()
        self.bad_path = tmp.name

    def tearDown(self):
        Path(self.bad_path).unlink(missing_ok=True)

    def test_get_apk_strings_empty_output(self):
        a = AndroidAAPT(self.bad_path)
        self.assertEqual(a.get_apk_strings(), [])

    def test_get_apk_features_empty_output_returns_default_data(self):
        a = AndroidAAPT(self.bad_path)
        result = a.get_apk_features()
        self.assertIs(result, a.data)
        self.assertIsNone(result['package'])
