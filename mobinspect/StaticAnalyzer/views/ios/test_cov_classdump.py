# -*- coding: utf_8 -*-
"""Real-execution coverage tests for ios/classdump.py.

Real tools used throughout: the committed ``tools/ios/class-dump`` (x86_64
Mach-O, runs under Rosetta on this Apple Silicon host) against a real
extracted binary from ``test_files/ios.ipa``, and the committed
``tools/ios/jtool.ELF64`` (a real Linux ELF binary that genuinely raises
``OSError: Exec format error`` when exec'd on this macOS host -- a real
architecture-mismatch fault, not a simulated one).

ONE narrow, documented substitution: the shipped ``class-dump-swift``
binary was confirmed (by direct experimentation -- ``subprocess.run`` with
an 8s timeout against both a plain text file and a real Mach-O binary)
to hang indefinitely on *any* input on this host, and ``classdump_mac()``
calls it with no timeout (unlike ``classdump_linux``, which has one --
see the suspected-bug note in the coverage report). Real execution of the
shipped class-dump-swift is therefore impossible here without risking an
indefinite test hang. For the handful of lines that require the
'class-dump-swift' code path, tests point ``settings.CLASSDUMP_SWIFT_BINARY``
at tiny, real, fast shell scripts written to disk for this purpose --
still a real subprocess exec (real permission checks, real exit codes,
real stdout capture), just not the actual (hanging) vendored tool.
"""
import os
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase, override_settings

from mobinspect.StaticAnalyzer.views.ios.classdump import (
    classdump_linux,
    classdump_mac,
    get_class_dump,
)


SAMPLES_DIR = os.path.normpath(
    os.path.join(settings.BASE_DIR, '..', 'test_files'))
TOOLS_DIR = os.path.normpath(
    os.path.join(settings.BASE_DIR, 'StaticAnalyzer', 'tools', 'ios'))


def _extract_real_ipa_binary(tmp):
    """Unzip the committed ios.ipa and return the real Payload binary path."""
    ipa_path = os.path.join(SAMPLES_DIR, 'ios.ipa')
    with zipfile.ZipFile(ipa_path) as zf:
        zf.extractall(tmp)
    payload = Path(tmp) / 'Payload'
    app_dir = next(payload.glob('*.app'))
    bin_name = app_dir.name.replace('.app', '')
    return app_dir / bin_name


def _write_script(path, body):
    with open(path, 'w') as fh:
        fh.write(body)
    os.chmod(path, 0o755)
    return path


class ClassdumpMacTests(SimpleTestCase):

    def test_real_class_dump_against_real_binary_succeeds(self):
        tmp = tempfile.mkdtemp()
        real_bin = _extract_real_ipa_binary(tmp)
        out = classdump_mac('a' * 32, 'class-dump', TOOLS_DIR, str(real_bin))
        self.assertIn(b'class-dump', out)

    def test_swift_external_override_and_success(self):
        # settings.CLASSDUMP_SWIFT_BINARY set + is_file_exists() True ->
        # class_dump_bin = external (line 32); external path used directly
        # (line 24 assigns it).
        tmp = tempfile.mkdtemp()
        fake = _write_script(
            os.path.join(tmp, 'fake-class-dump-swift'),
            '#!/bin/sh\necho "fake swift dump"\nexit 0\n')
        with override_settings(CLASSDUMP_SWIFT_BINARY=fake):
            out = classdump_mac(
                'b' * 32, 'class-dump-swift', TOOLS_DIR, '/irrelevant/bin')
        self.assertIn(b'fake swift dump', out)

    def test_exec_permission_is_fixed_up_before_running(self):
        # A real copy of class-dump with the execute bit stripped -> the
        # function must chmod it itself before running (lines 37-38).
        tmp = tempfile.mkdtemp()
        real_bin = _extract_real_ipa_binary(tmp)
        no_exec_dir = tempfile.mkdtemp()
        dst = os.path.join(no_exec_dir, 'class-dump')
        with open(os.path.join(TOOLS_DIR, 'class-dump'), 'rb') as src, \
                open(dst, 'wb') as out_fh:
            out_fh.write(src.read())
        os.chmod(dst, 0o644)
        self.assertFalse(os.access(dst, os.X_OK))
        out = classdump_mac('c' * 32, 'class-dump', no_exec_dir, str(real_bin))
        self.assertIn(b'class-dump', out)
        self.assertTrue(os.access(dst, os.X_OK))


class ClassdumpLinuxTests(SimpleTestCase):

    def test_jtool_binary_setting_and_real_exec_format_error(self):
        # settings.JTOOL_BINARY set to the real committed jtool.ELF64 ->
        # lines 47-49 (settings branch). Executing a real Linux ELF binary
        # on this macOS host genuinely raises OSError (Exec format error),
        # caught by the function's own except -> returns b'' (lines 63-64).
        real_jtool = os.path.join(TOOLS_DIR, 'jtool.ELF64')
        with override_settings(JTOOL_BINARY=real_jtool):
            out = classdump_linux('d' * 32, TOOLS_DIR, '/irrelevant/bin')
        self.assertEqual(out, b'')

    def test_default_path_and_permission_fixup_real_exec_format_error(self):
        # JTOOL_BINARY unset (default '') -> default path is built from
        # tools_dir (line 51). A copy without the exec bit forces the
        # chmod fixup (lines 52-53) before the real (still-failing) exec
        # attempt.
        tmp = tempfile.mkdtemp()
        dst = os.path.join(tmp, 'jtool.ELF64')
        with open(os.path.join(TOOLS_DIR, 'jtool.ELF64'), 'rb') as src, \
                open(dst, 'wb') as out_fh:
            out_fh.write(src.read())
        os.chmod(dst, 0o644)
        with override_settings(JTOOL_BINARY=''):
            out = classdump_linux('e' * 32, tmp, '/irrelevant/bin')
        self.assertEqual(out, b'')
        self.assertTrue(os.access(dst, os.X_OK))


class GetClassDumpTests(SimpleTestCase):
    """platform.system() is real (Darwin) for the Darwin-branch tests, and
    is patched (single call, narrow) only for the Linux/unsupported-platform
    branches that cannot occur for real on this host -- a platform guard,
    per the project's own pragma convention for such branches."""

    def test_swift_bin_type_first_try_succeeds(self):
        # bin_type == 'Swift', first classdump_mac('class-dump-swift', ...)
        # call succeeds -> lines 76-83; no 'Source: (null)' in output so
        # the fail-safe block is skipped.
        tmp = tempfile.mkdtemp()
        real_bin = _extract_real_ipa_binary(tmp)
        fake = _write_script(
            os.path.join(tmp, 'fake-class-dump-swift'),
            '#!/bin/sh\necho "clean dump, no null source"\nexit 0\n')
        app_dir = tempfile.mkdtemp()
        with override_settings(CLASSDUMP_SWIFT_BINARY=fake):
            out = get_class_dump(
                'f' * 32, TOOLS_DIR, real_bin, app_dir, 'Swift')
        self.assertIn(b'clean dump', out)
        self.assertTrue(
            os.path.exists(os.path.join(app_dir, 'classdump.txt')))

    def test_swift_bin_type_first_try_fails_falls_back_to_class_dump(self):
        # bin_type == 'Swift', the Swift attempt raises (nonzero exit) ->
        # except -> real fallback to classdump_mac('class-dump', ...)
        # against the real binary (lines 84-90).
        tmp = tempfile.mkdtemp()
        real_bin = _extract_real_ipa_binary(tmp)
        fake_fail = _write_script(
            os.path.join(tmp, 'fake-swift-fail'), '#!/bin/sh\nexit 1\n')
        app_dir = tempfile.mkdtemp()
        with override_settings(CLASSDUMP_SWIFT_BINARY=fake_fail):
            out = get_class_dump(
                'g' * 32, TOOLS_DIR, real_bin, app_dir, 'Swift')
        self.assertIn(b'class-dump', out)

    def test_objc_bin_type_first_try_fails_falls_back_to_class_dump_swift(self):
        # bin_type != 'Swift' (Objective-C), the real class-dump attempt
        # fails for real (nonexistent input path -> nonzero exit) -> except
        # -> falls back to classdump_mac('class-dump-swift', ...); the
        # fallback is pointed at a fast fake to avoid the real tool's hang
        # (lines 99-105).
        tmp = tempfile.mkdtemp()
        fake_ok = _write_script(
            os.path.join(tmp, 'fake-swift-ok'),
            '#!/bin/sh\necho "fallback swift dump"\nexit 0\n')
        app_dir = tempfile.mkdtemp()
        bogus_bin = Path(tmp) / 'does-not-exist-binary'
        with override_settings(CLASSDUMP_SWIFT_BINARY=fake_ok):
            out = get_class_dump(
                'h' * 32, TOOLS_DIR, bogus_bin, app_dir, 'Objective-C')
        self.assertIn(b'fallback swift dump', out)

    def test_source_null_triggers_failsafe_rerun(self):
        # First successful dump's output literally contains
        # 'Source: (null)' -> fail-safe re-run via class-dump-swift
        # (lines 106-116). Real class-dump/class-dump-swift rarely emit
        # this on our small real sample binary, so both the first attempt
        # and the fail-safe rerun are pointed at fast fakes for
        # determinism; still real subprocess execs, real file writes.
        tmp = tempfile.mkdtemp()
        fake_null = _write_script(
            os.path.join(tmp, 'fake-null-source'),
            '#!/bin/sh\necho "Source: (null)"\nexit 0\n')
        app_dir = tempfile.mkdtemp()
        bogus_bin = Path(tmp) / 'unused-bin'
        with override_settings(CLASSDUMP_SWIFT_BINARY=fake_null):
            out = get_class_dump(
                'i' * 32, TOOLS_DIR, bogus_bin, app_dir, 'Swift')
        self.assertIn(b'Source: (null)', out)

    def test_linux_platform_branch(self):
        # platform.system() patched to 'Linux' -> classdump_linux() is
        # invoked for real, which genuinely fails to exec the real Linux
        # ELF jtool.ELF64 on this macOS host (lines 117-118).
        tmp = tempfile.mkdtemp()
        app_dir = tempfile.mkdtemp()
        bogus_bin = Path(tmp) / 'unused-bin'
        with mock.patch(
                'mobinspect.StaticAnalyzer.views.ios.classdump.platform.'
                'system', return_value='Linux'):
            out = get_class_dump(
                'j' * 32, TOOLS_DIR, bogus_bin, app_dir, 'Objective-C')
        self.assertEqual(out, b'')
        self.assertTrue(
            os.path.exists(os.path.join(app_dir, 'classdump.txt')))

    def test_unsupported_platform_branch(self):
        # platform.system() patched to something else entirely -> warning
        # branch, empty cdump (lines 121-123).
        app_dir = tempfile.mkdtemp()
        bogus_bin = Path('/unused/bin')
        with mock.patch(
                'mobinspect.StaticAnalyzer.views.ios.classdump.platform.'
                'system', return_value='SunOS'):
            out = get_class_dump(
                'k' * 32, TOOLS_DIR, bogus_bin, app_dir, 'Objective-C')
        self.assertEqual(out, b'')

    def test_outer_exception_branch_bad_app_dir(self):
        # app_dir points at a nonexistent directory -> the real
        # `open(os.path.join(app_dir, 'classdump.txt'), 'wb')` genuinely
        # raises FileNotFoundError -> the function's own outer except
        # (lines 127-131).
        tmp = tempfile.mkdtemp()
        fake_ok = _write_script(
            os.path.join(tmp, 'fake-swift-ok2'),
            '#!/bin/sh\necho "ok"\nexit 0\n')
        bogus_bin = Path(tmp) / 'unused-bin'
        with override_settings(CLASSDUMP_SWIFT_BINARY=fake_ok):
            result = get_class_dump(
                'l' * 32, TOOLS_DIR, bogus_bin,
                '/nonexistent/app_dir/path', 'Swift')
        # The dump itself succeeded (cdump == b'ok\n'); only the classdump.txt
        # write fails, so the outer except returns the already-dumped bytes.
        self.assertEqual(result, b'ok\n')
