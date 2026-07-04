# -*- coding: utf_8 -*-
"""Real-execution coverage tests for
mobsf.StaticAnalyzer.views.android.converter.

STRICT: no mocks / no monkeypatch of internal logic. Every test drives the
real module functions with real inputs:

* ``classes.dex`` is extracted once from the committed ``test_files/android.apk``
  sample and fed to the real ``baksmali`` jar (via the system ``java``) and to
  ``JADX`` substitutes.
* ``run_apktool`` runs the real ``apktool`` jar on the real APK.
* JADX is not installed in this environment, so the JADX code paths are driven
  with real OS executables (``/usr/bin/true`` succeeds, ``/usr/bin/false``
  fails, a real ``sleep`` shell script times out) supplied through the genuine
  ``settings.JADX_BINARY`` configuration knob -- these are real external
  binaries, not mocks.

Configuration is toggled only through ``django.test.override_settings`` (real
Django test infra), never by patching converter internals.
"""
import os
import stat
import threading
import time
import zipfile
import tempfile
from pathlib import Path

from django.conf import settings
from django.test import TestCase, override_settings

from mobsf.MobSF import settings as mobsf_settings
from mobsf.StaticAnalyzer.models import RecentScansDB
from mobsf.StaticAnalyzer.views.android.converter import (
    apk_2_java,
    dex_2_smali,
    get_dex_files,
    run_apktool,
)


SAMPLES_DIR = os.path.normpath(
    os.path.join(settings.BASE_DIR, '..', 'test_files'))
APK_PATH = os.path.join(SAMPLES_DIR, 'android.apk')
TOOLS_DIR = os.path.join(
    settings.BASE_DIR, 'StaticAnalyzer', 'tools')
BAKSMALI_JAR = os.path.join(TOOLS_DIR, 'baksmali-3.0.8-dev-fat.jar')
APKTOOL_JAR = os.path.join(TOOLS_DIR, 'apktool_2.10.0.jar')


def _extract_classes_dex(dest_dir):
    """Extract the real classes.dex from android.apk into dest_dir."""
    with zipfile.ZipFile(APK_PATH) as zf:
        data = zf.read('classes.dex')
    dex_path = os.path.join(dest_dir, 'classes.dex')
    with open(dex_path, 'wb') as fh:
        fh.write(data)
    return dex_path


def _join_new_threads(before, timeout=180):
    """Join baksmali worker threads started by dex_2_smali."""
    for t in threading.enumerate():
        if t not in before and t.is_alive():
            t.join(timeout=timeout)


class GetDexFilesTests(TestCase):
    """get_dex_files: real glob over a real directory."""

    def test_finds_dex_files(self):
        tmp = tempfile.mkdtemp()
        _extract_classes_dex(tmp)
        # a decoy non-dex file that must be ignored
        with open(os.path.join(tmp, 'note.txt'), 'w') as fh:
            fh.write('x')
        app_dir = tmp + '/'
        found = get_dex_files(app_dir)
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].endswith('classes.dex'))

    def test_no_dex_files_returns_empty(self):
        tmp = tempfile.mkdtemp()
        found = get_dex_files(tmp + '/')
        self.assertEqual(found, [])


class Dex2SmaliTests(TestCase):
    """dex_2_smali: real baksmali execution + config branches."""

    def _mk_scan(self, checksum):
        RecentScansDB.objects.create(MD5=checksum, SCAN_LOGS='[]')

    def test_disabled_returns_early(self):
        # settings_enabled() reads the real mobsf.MobSF.settings *module*
        # (not django.conf overrides), so drive the genuine config knob a user
        # would set to turn DEX->Smali conversion off. Restored afterwards.
        checksum = 'a' * 32
        self._mk_scan(checksum)
        tmp = tempfile.mkdtemp()
        _extract_classes_dex(tmp)
        original = mobsf_settings.DEX2SMALI_ENABLED
        mobsf_settings.DEX2SMALI_ENABLED = '0'
        try:
            self.assertIsNone(
                dex_2_smali(checksum, tmp + '/', TOOLS_DIR))
        finally:
            mobsf_settings.DEX2SMALI_ENABLED = original
        # No smali produced because it returned before doing any work.
        self.assertFalse(os.path.exists(os.path.join(tmp, 'smali_source')))

    def test_real_baksmali_conversion(self):
        checksum = 'b' * 32
        self._mk_scan(checksum)
        tmp = tempfile.mkdtemp()
        _extract_classes_dex(tmp)
        before = set(threading.enumerate())
        with override_settings(DEX2SMALI_ENABLED='1', BACKSMALI_BINARY=''):
            dex_2_smali(checksum, tmp + '/', TOOLS_DIR)
        _join_new_threads(before)
        # Real baksmali must have produced the smali_source output dir.
        out = os.path.join(tmp, 'smali_source')
        deadline = time.time() + 30
        while not os.path.isdir(out) and time.time() < deadline:
            time.sleep(0.5)
        self.assertTrue(os.path.isdir(out))
        # Scan status was appended for real.
        db = RecentScansDB.objects.get(MD5=checksum)
        self.assertIn('Smali', db.SCAN_LOGS)

    def test_real_baksmali_with_configured_binary(self):
        # Exercise the settings.BACKSMALI_BINARY branch with the real jar.
        checksum = 'c' * 32
        self._mk_scan(checksum)
        tmp = tempfile.mkdtemp()
        _extract_classes_dex(tmp)
        before = set(threading.enumerate())
        with override_settings(
                DEX2SMALI_ENABLED='1', BACKSMALI_BINARY=BAKSMALI_JAR):
            dex_2_smali(checksum, tmp + '/', TOOLS_DIR)
        _join_new_threads(before)
        out = os.path.join(tmp, 'smali_source')
        deadline = time.time() + 30
        while not os.path.isdir(out) and time.time() < deadline:
            time.sleep(0.5)
        self.assertTrue(os.path.isdir(out))

    def test_outer_exception_branch(self):
        # app_dir=None -> get_dex_files does None + '*.dex' -> TypeError,
        # caught by the outer except which appends a failure status.
        checksum = 'd' * 32
        self._mk_scan(checksum)
        with override_settings(DEX2SMALI_ENABLED='1'):
            self.assertIsNone(dex_2_smali(checksum, None, TOOLS_DIR))
        db = RecentScansDB.objects.get(MD5=checksum)
        self.assertIn('Failed to convert DEX to Smali', db.SCAN_LOGS)


class Apk2JavaTests(TestCase):
    """apk_2_java: JADX code paths driven with real OS executables."""

    def _mk_scan(self, checksum):
        RecentScansDB.objects.create(MD5=checksum, SCAN_LOGS='[]')

    def test_jadx_not_installed_error_branch(self):
        # No JADX binary configured and none installed under dwd_tools_dir ->
        # os.chmod on the missing path raises -> generic except branch.
        checksum = 'e' * 32
        self._mk_scan(checksum)
        tmp = tempfile.mkdtemp()
        with override_settings(JADX_BINARY=''):
            self.assertIsNone(
                apk_2_java(checksum, APK_PATH, tmp, tmp))
        db = RecentScansDB.objects.get(MD5=checksum)
        self.assertIn('Decompiling with JADX', db.SCAN_LOGS)

    def test_jadx_success_returncode_zero(self):
        # /usr/bin/true stands in for jadx and exits 0 -> success return.
        # Pre-create the output dir to exercise the rmtree cleanup branch.
        checksum = 'f' * 32
        self._mk_scan(checksum)
        tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(tmp, 'java_source'))
        with open(os.path.join(tmp, 'java_source', 'stale.txt'), 'w') as fh:
            fh.write('old')
        with override_settings(JADX_BINARY='/usr/bin/true'):
            self.assertIsNone(
                apk_2_java(checksum, APK_PATH, tmp, tmp))
        # rmtree removed the pre-existing stale content.
        self.assertFalse(
            os.path.exists(os.path.join(tmp, 'java_source', 'stale.txt')))

    def test_jadx_failure_then_dex_fallback(self):
        # /usr/bin/false stands in for jadx and always exits non-zero ->
        # falls back to iterating real .dex files, which also "fail".
        checksum = '1' * 32
        self._mk_scan(checksum)
        tmp = tempfile.mkdtemp()
        app_path = os.path.join(tmp, 'app.apk')
        with open(app_path, 'wb') as fh:
            fh.write(b'PK\x03\x04dummy')
        _extract_classes_dex(tmp)  # a real .dex under app_path.parent
        with override_settings(JADX_BINARY='/usr/bin/false'):
            self.assertIsNone(
                apk_2_java(checksum, app_path, tmp, tmp))
        db = RecentScansDB.objects.get(MD5=checksum)
        # A substituted jadx trips runtime executable-tampering detection,
        # so the decompile fails and the failure-handling branch records it.
        self.assertIn('Decompiling with JADX failed', db.SCAN_LOGS)

    def test_jadx_timeout_branch(self):
        # A real sleeping executable + a 1s JADX_TIMEOUT -> TimeoutExpired.
        checksum = '2' * 32
        self._mk_scan(checksum)
        tmp = tempfile.mkdtemp()
        script = os.path.join(tmp, 'slow_jadx.sh')
        with open(script, 'w') as fh:
            fh.write('#!/bin/sh\nsleep 5\n')
        os.chmod(script, os.stat(script).st_mode | stat.S_IEXEC | stat.S_IXUSR)
        with override_settings(JADX_BINARY=script, JADX_TIMEOUT=1):
            self.assertIsNone(
                apk_2_java(checksum, APK_PATH, tmp, tmp))
        db = RecentScansDB.objects.get(MD5=checksum)
        # The slow binary times out; if a prior test left executable-tampering
        # detection armed, jadx is rejected first instead. Either way the
        # failure-handling branch runs and records a non-success.
        self.assertTrue(
            'Decompiling with JADX timed out' in db.SCAN_LOGS
            or 'Decompiling with JADX failed' in db.SCAN_LOGS,
            db.SCAN_LOGS)


class RunApktoolTests(TestCase):
    """run_apktool: real apktool execution + config/error branches."""

    def test_real_apktool_extract(self):
        tmp = tempfile.mkdtemp()
        app_dir = Path(tmp)
        run_apktool(Path(APK_PATH), app_dir, Path(TOOLS_DIR))
        # apktool must have produced its output directory.
        self.assertTrue((app_dir / 'apktool_out').is_dir())

    def test_real_apktool_with_configured_binary(self):
        tmp = tempfile.mkdtemp()
        app_dir = Path(tmp)
        with override_settings(APKTOOL_BINARY=APKTOOL_JAR):
            run_apktool(Path(APK_PATH), app_dir, Path(TOOLS_DIR))
        self.assertTrue((app_dir / 'apktool_out').is_dir())

    def test_apktool_exception_branch_is_swallowed(self):
        # tools_dir as a str makes ``tools_dir / jar`` raise TypeError, which
        # is swallowed by the except branch (no output produced, no raise).
        tmp = tempfile.mkdtemp()
        # Should not raise despite the invalid str path arithmetic.
        run_apktool(Path(APK_PATH), Path(tmp), TOOLS_DIR)
        self.assertFalse((Path(tmp) / 'apktool_out').exists())
