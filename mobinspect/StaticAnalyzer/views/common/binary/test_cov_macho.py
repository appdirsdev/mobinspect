# -*- coding: utf_8 -*-
"""Real-execution coverage tests for common/binary/macho.py.

STRICT preference for real artifacts: real compiled Mach-O binaries
(built with the real ``clang`` on this host, exactly the technique the
sibling ``test_cov_elf.py`` uses ``lief`` for -- constructing genuine
binaries with a specific real property, e.g. ``-Wl,-rpath,...`` for a
real RPATH load command, ``-g`` for real un-stripped debug symbols,
``strip`` for a genuinely fully-stripped binary), the committed
``test_files/macho.dylib`` / ``macho_static_lib.a`` objects, and the real
extracted ``ios.ipa`` Payload binary (a real non-PIE, non-dylib
executable).

Two properties have no real, obtainable sample on this host and are
noted as narrow, single-method monkeypatches (per project convention):
NX-bit-unset (every modern compiler enables it unconditionally) and
FairPlay encryption (Apple DRM requires an App-Store-signed binary we
cannot fabricate or legitimately obtain).
"""
import os
import shutil
import subprocess
import tempfile
import warnings
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase

from mobinspect.StaticAnalyzer.views.common.binary.macho import (
    MachOChecksec,
)

SAMPLES_DIR = os.path.normpath(
    os.path.join(settings.BASE_DIR, '..', 'test_files'))
CLANG = shutil.which('clang')


def _extract_real_macho_object(tmp):
    """A real Mach-O .o object file (from the committed static lib).

    Confirmed via direct lief inspection: is_pie=False (object files are
    never position-independent executables), has_nx=True, and its
    symbol types are all clean/valid lief enum members (unlike a
    DWARF-debug-info-carrying executable, which can carry STAB symbols
    whose masked lief ``Symbol.type`` is a raw int lief doesn't map to
    an enum member -- see the ``raw_type``-based fix in
    ``is_symbols_stripped()`` and the regression test below).
    """
    lib_path = os.path.join(SAMPLES_DIR, 'macho_static_lib.a')
    subprocess.run(['ar', 'x', lib_path], cwd=tmp, check=True)
    return Path(tmp) / 'add.o'


class MachoChecksecInvalidFileTests(SimpleTestCase):
    """A real, non-Mach-O file (lief.parse() genuinely returns None)."""

    def test_checksec_not_macho_returns_empty_dict(self):
        # is_macho() False -> checksec() returns {} (line 46).
        chk = MachOChecksec(Path('/etc/hosts'), 'hosts')
        self.assertEqual(chk.checksec(), {})

    def test_get_libraries_empty_when_macho_none(self):
        # self.macho is None (lief.parse failed) -> early return (line 310).
        chk = MachOChecksec(Path('/etc/hosts'), 'hosts')
        self.assertIsNone(chk.macho)
        self.assertEqual(chk.get_libraries(), [])

    def test_get_symbols_swallows_exception_when_macho_none(self):
        # self.macho.symbols on None raises AttributeError -> caught,
        # returns [] (lines 327-328).
        chk = MachOChecksec(Path('/etc/hosts'), 'hosts')
        self.assertEqual(chk.get_symbols(), [])


class MachoChecksecRealSampleTests(SimpleTestCase):
    """Uses the committed test_files/ samples directly."""

    def test_pie_not_set_high_severity_real_macho_object(self):
        # Real Mach-O object file (is_pie=False for any .o -- object
        # files are never PIE executables), plain '.o' name (not .dylib,
        # not .framework) -> stays 'high' severity (lines 111-112).
        tmp = tempfile.mkdtemp()
        real_obj = _extract_real_macho_object(tmp)
        chk = MachOChecksec(real_obj, real_obj.name)
        result = chk.checksec()
        self.assertFalse(result['pie']['has_pie'])
        self.assertEqual(result['pie']['severity'], 'high')


class MachoChecksecCompiledBinaryTests(SimpleTestCase):
    """Real binaries compiled at test time with the real clang toolchain."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not CLANG:
            return
        cls.build_dir = tempfile.mkdtemp()
        src = os.path.join(cls.build_dir, 't.c')
        with open(src, 'w') as fh:
            fh.write('int main(void) { return 0; }\n')
        # A real binary with a real RPATH load command and real,
        # un-stripped debug symbols (has_canary is False for this trivial
        # program -- no stack-protected functions).
        cls.rpath_debug_bin = os.path.join(cls.build_dir, 'rpath_debug')
        subprocess.run(
            [CLANG, '-g', '-o', cls.rpath_debug_bin, src,
             '-Wl,-rpath,/usr/lib/custom'], check=True)
        # A genuinely fully-stripped binary (real `strip` invocation) --
        # its only remaining symbol is __mh_execute_header.
        cls.stripped_bin = os.path.join(cls.build_dir, 'stripped_bin')
        shutil.copy2(cls.rpath_debug_bin, cls.stripped_bin)
        subprocess.run(['strip', cls.stripped_bin], check=True)
        # A real binary with a genuine stack canary: -fstack-protector-all
        # over a strcpy-into-fixed-buffer function makes clang really
        # import ___stack_chk_fail/___stack_chk_guard.
        canary_src = os.path.join(cls.build_dir, 'canary.c')
        with open(canary_src, 'w') as fh:
            fh.write(
                '#include <string.h>\n'
                'void vuln(const char *input) {\n'
                '    char buf[16];\n'
                '    strcpy(buf, input);\n'
                '}\n'
                'int main(int argc, char **argv) {\n'
                '    if (argc > 1) vuln(argv[1]);\n'
                '    return 0;\n'
                '}\n')
        cls.canary_bin = os.path.join(cls.build_dir, 'canary_bin')
        subprocess.run(
            [CLANG, '-fstack-protector-all', '-o', cls.canary_bin,
             canary_src], check=True)

    def setUp(self):
        if not CLANG:
            self.skipTest('clang is not available on this host')

    def test_rpath_set_warning_severity(self):
        # has_rpath True -> warning severity (lines 173-174).
        chk = MachOChecksec(Path(self.rpath_debug_bin), 'rpath_debug')
        result = chk.checksec()
        self.assertTrue(result['rpath']['has_rpath'])
        self.assertEqual(result['rpath']['severity'], 'warning')

    def test_stack_canary_present_info_severity(self):
        # A real binary genuinely importing ___stack_chk_fail and
        # ___stack_chk_guard -> has_canary True -> 'info' severity with
        # the "has a stack canary" description (lines 111-112).
        chk = MachOChecksec(Path(self.canary_bin), 'canary_bin')
        result = chk.checksec()
        self.assertTrue(result['stack_canary']['has_canary'])
        self.assertEqual(result['stack_canary']['severity'], 'info')
        self.assertIn('has a stack canary value',
                      result['stack_canary']['description'])

    def test_libswift_named_binary_downgrades_canary_severity_to_warning(self):
        # No canary, not stripped (real debug symbols present), name
        # contains 'libswift' -> severity downgraded to 'warning' with
        # the Swift-specific message (lines 127-128).
        chk = MachOChecksec(
            Path(self.rpath_debug_bin), 'Frameworks/libswiftCore.dylib')
        result = chk.checksec()
        self.assertFalse(result['stack_canary']['has_canary'])
        self.assertEqual(result['stack_canary']['severity'], 'warning')
        self.assertIn('pure Swift dylibs',
                      result['stack_canary']['description'])

    def test_symbols_stripped_manual_fallback_early_return_false(self):
        # objdump made genuinely unavailable (empty PATH) -> the real
        # exception handler falls into the manual symbol-table scan; a
        # real, non-stripped Mach-O object file's defined symbols (type
        # N_SECT/0x0e) trigger the "found a debug-capable symbol" early
        # return (lines 276, 279, 282-283, 288-289 and the early
        # `return False`).
        tmp = tempfile.mkdtemp()
        real_obj = _extract_real_macho_object(tmp)
        chk = MachOChecksec(real_obj, real_obj.name)
        with mock.patch.dict(os.environ, {'PATH': ''}):
            stripped = chk.is_symbols_stripped()
        self.assertFalse(stripped)

    def test_symbols_stripped_manual_fallback_handles_dwarf_stab_symbols(self):
        # REGRESSION TEST for a fixed production bug: when objdump is
        # unavailable and the target is a real executable carrying DWARF
        # debug info (any binary built with -g, e.g. self.rpath_debug_bin),
        # the manual fallback's N_STAB check used to read `i.type.value`.
        # lief's `Symbol.type` is documented as `n_type & N_TYPE` -- the
        # n_type byte with the N_STAB bits already masked OFF -- so a) the
        # `& 0xe0` check could never detect a stab entry through it, and
        # b) many real STAB byte values (e.g. N_SO 0x64, N_OSO 0x66) mask
        # down to a raw int lief's TYPE enum does not define (4, 6),
        # which made lief emit `RuntimeWarning: 4 is not a valid TYPE.`
        # and return a plain int lacking `.value`, raising uncaught
        # `AttributeError: 'int' object has no attribute 'value'`. That
        # propagated out of checksec() entirely, so callers like
        # library_analysis() would fail the WHOLE per-file analysis
        # instead of just the symbol-stripped flag -- reproducible in
        # production whenever objdump is missing from PATH (e.g. a
        # minimal container image) and the binary retains debug info.
        #
        # Fixed by reading `i.raw_type` (the untouched, full n_type byte)
        # instead of `i.type.value`. This asserts: no crash, no warning,
        # and the correct answer (real debug info present -> not
        # stripped).
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            with mock.patch.dict(os.environ, {'PATH': ''}):
                stripped = MachOChecksec(
                    Path(self.rpath_debug_bin),
                    'rpath_debug').is_symbols_stripped()
        self.assertFalse(stripped)

    def test_symbols_stripped_manual_fallback_tail_fallthrough(self):
        # Same real objdump-unavailable fault, but on a genuinely fully
        # stripped binary whose only symbol is the skip-listed
        # __mh_execute_header -> the loop matches nothing, falls through
        # to the tail radr:// check and returns False (lines 302-305).
        chk = MachOChecksec(Path(self.stripped_bin), 'stripped_bin')
        with mock.patch.dict(os.environ, {'PATH': ''}):
            stripped = chk.is_symbols_stripped()
        self.assertFalse(stripped)

    def test_symbols_stripped_manual_fallback_radr_marker_returns_true(self):
        # The 'radr://5614542' marker (line 303-304) is a historical
        # Xcode-toolchain artifact re-added to certain old stripped
        # binaries -- no modern toolchain reproduces it, so this is a
        # narrow, single-method monkeypatch of get_symbols() (not of
        # is_symbols_stripped() itself, which still runs for real: the
        # real loop over self.macho.symbols on the real stripped binary
        # still executes and still falls through to the real
        # `if stripped_sym in self.get_symbols()` check at line 303).
        chk = MachOChecksec(Path(self.stripped_bin), 'stripped_bin')
        with mock.patch.dict(os.environ, {'PATH': ''}), mock.patch.object(
                chk, 'get_symbols', return_value=['radr://5614542']):
            stripped = chk.is_symbols_stripped()
        self.assertTrue(stripped)


class MachoChecksecNarrowMonkeypatchTests(SimpleTestCase):
    """Two properties with no obtainable real sample on this host.

    NX-bit-unset: every modern linker on any platform we have access to
    sets it unconditionally (verified across 4 real samples: macho.dylib,
    add.o, answer.o, and a fresh clang build). FairPlay-encrypted:
    requires a real App-Store-signed, Apple-DRM-encrypted binary that
    cannot be fabricated or legitimately obtained in a test environment.
    Both patch a single bound method on a MachOChecksec instance built
    from a real underlying Mach-O file; every other computation in
    checksec() still runs for real.
    """

    def test_nx_not_set_severity(self):
        chk = MachOChecksec(
            Path(os.path.join(SAMPLES_DIR, 'macho.dylib')), 'macho.dylib')
        with mock.patch.object(chk, 'has_nx', return_value=False):
            result = chk.checksec()
        self.assertFalse(result['nx']['has_nx'])
        self.assertIn('does not have NX bit set', result['nx']['description'])

    def test_encrypted_severity(self):
        chk = MachOChecksec(
            Path(os.path.join(SAMPLES_DIR, 'macho.dylib')), 'macho.dylib')
        with mock.patch.object(chk, 'is_encrypted', return_value=True):
            result = chk.checksec()
        self.assertTrue(result['encrypted']['is_encrypted'])
        self.assertEqual(
            result['encrypted']['description'], 'This binary is encrypted.')
