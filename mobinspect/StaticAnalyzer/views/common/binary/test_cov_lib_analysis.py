# -*- coding: utf_8 -*-
"""Real-execution coverage tests for common/binary/lib_analysis.py.

Real files throughout: the committed macho_static_lib.a is extracted with
a real `ar` invocation to get real Mach-O object files (add.o/answer.o),
test_files/android.so (real ELF) and test_files/macho.dylib (real
universal Mach-O) drive the arch-specific branches, and real `lief`
detection (lief.is_macho/is_elf) classifies them. Real fault injection
for the except branches: a `src` tree deliberately NOT rooted under
`settings.UPLD_DIR/<checksum>` makes `Path.relative_to()` genuinely raise
ValueError.

``settings_enabled()`` (in mobinspect/MobInspect/utils.py) reads
``DYLIB_ANALYSIS_ENABLED``/``SO_ANALYSIS_ENABLED`` through the same raw
``mobinspect.MobInspect.settings`` module import discussed in
test_cov_pdf.py (NOT ``django.conf.settings``), so
``@override_settings`` has no effect on it either; tests patch the raw
module attribute directly.
"""
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase, override_settings

from mobinspect.MobInspect import settings as raw_settings
from mobinspect.StaticAnalyzer.views.common.binary.lib_analysis import (
    frameworks_analysis,
    library_analysis,
)

SAMPLES_DIR = os.path.normpath(
    os.path.join(settings.BASE_DIR, '..', 'test_files'))


def _extract_real_macho_objects(dest_dir):
    """Extract real Mach-O .o object files from the committed static lib."""
    lib_path = os.path.join(SAMPLES_DIR, 'macho_static_lib.a')
    subprocess.run(['ar', 'x', lib_path], cwd=dest_dir, check=True)
    return [os.path.join(dest_dir, n) for n in ('add.o', 'answer.o')]


class LibraryAnalysisDisabledTests(SimpleTestCase):

    def test_macho_dylib_analysis_disabled_returns_early(self):
        # settings_enabled('DYLIB_ANALYSIS_ENABLED') False -> line 39.
        with mock.patch.object(
                raw_settings, 'DYLIB_ANALYSIS_ENABLED', '0'):
            res = library_analysis('a' * 32, tempfile.mkdtemp(), 'macho')
        self.assertEqual(res['macho_analysis'], [])

    def test_elf_so_analysis_disabled_returns_early(self):
        # settings_enabled('SO_ANALYSIS_ENABLED') False -> line 44.
        with mock.patch.object(raw_settings, 'SO_ANALYSIS_ENABLED', '0'):
            res = library_analysis('b' * 32, tempfile.mkdtemp(), 'elf')
        self.assertEqual(res['elf_analysis'], [])


class LibraryAnalysisRealFilesTests(SimpleTestCase):

    def test_macosx_path_skipped(self):
        # A real .so under a __MACOSX directory is skipped (line 55).
        checksum = 'c' * 32
        tmp = tempfile.mkdtemp()
        with override_settings(UPLD_DIR=tmp):
            base_dir = Path(tmp) / checksum
            macosx_dir = base_dir / '__MACOSX'
            macosx_dir.mkdir(parents=True)
            shutil.copy2(
                os.path.join(SAMPLES_DIR, 'android.so'),
                macosx_dir / 'skip_me.so')
            res = library_analysis(checksum, str(base_dir), 'elf')
        self.assertEqual(res['elf_analysis'], [])

    def test_ar_file_neither_macho_nor_elf_is_skipped(self):
        # A plain-text .o "object file" -> neither is_macho nor is_elf ->
        # continue (line 69).
        checksum = 'd' * 32
        tmp = tempfile.mkdtemp()
        with override_settings(UPLD_DIR=tmp):
            base_dir = Path(tmp) / checksum
            base_dir.mkdir(parents=True)
            (base_dir / 'plain.o').write_text('not an object file at all')
            res = library_analysis(checksum, str(base_dir), 'ar')
        self.assertEqual(res['ar_analysis'], [])
        self.assertEqual(res['ar_a'], '')

    def test_ar_real_macho_and_elf_objects_detected(self):
        # Real Mach-O .o (extracted from the committed static lib) and a
        # real ELF (android.so, renamed .o) both get correctly classified
        # via real lief detection (lines 62-67).
        checksum = 'e' * 32
        tmp = tempfile.mkdtemp()
        with override_settings(UPLD_DIR=tmp):
            base_dir = Path(tmp) / checksum
            base_dir.mkdir(parents=True)
            objs = _extract_real_macho_objects(str(base_dir))
            shutil.copy2(
                os.path.join(SAMPLES_DIR, 'android.so'),
                base_dir / 'real_elf.o')
            res = library_analysis(checksum, str(base_dir), 'ar')
        self.assertTrue(objs)
        self.assertIn(res['ar_a'], ('MachO', 'ELF'))
        self.assertTrue(res['ar_analysis'])

    def test_library_analysis_outer_exception_relative_to_mismatch(self):
        # `src` is real but deliberately NOT rooted under
        # settings.UPLD_DIR/<checksum> -> Path.relative_to() genuinely
        # raises ValueError -> the function's own outer except
        # (lines 89-92).
        checksum = 'f' * 32
        wrong_uplddir = tempfile.mkdtemp()
        real_src = tempfile.mkdtemp()
        shutil.copy2(
            os.path.join(SAMPLES_DIR, 'android.so'), Path(real_src) / 'x.so')
        with override_settings(UPLD_DIR=wrong_uplddir):
            res = library_analysis(checksum, real_src, 'elf')
        # Exception caught internally; res is still the initial skeleton.
        self.assertEqual(res['elf_analysis'], [])


class FrameworksAnalysisTests(SimpleTestCase):

    def test_framework_real_macho_binary_and_non_framework_files_skipped(self):
        # A real Mach-O binary at Foo.framework/Foo (name matches parent,
        # no suffix) is analyzed for real (lines 111-121); a sibling
        # Info.plist (has a suffix) is skipped (lines 108-109); a file
        # sitting outside any .framework dir is skipped (105-106, already
        # covered elsewhere).
        checksum = 'g' * 32
        tmp = tempfile.mkdtemp()
        with override_settings(UPLD_DIR=tmp):
            base_dir = Path(tmp) / checksum
            fw_dir = base_dir / 'Frameworks' / 'Foo.framework'
            fw_dir.mkdir(parents=True)
            shutil.copy2(
                os.path.join(SAMPLES_DIR, 'macho.dylib'), fw_dir / 'Foo')
            (fw_dir / 'Info.plist').write_text('<plist/>')
            res = {
                'macho_analysis': [], 'macho_strings': [], 'macho_symbols': [],
                'framework_analysis': [], 'framework_strings': [],
                'framework_symbols': [],
            }
            frameworks_analysis(checksum, str(base_dir), base_dir, res)
        self.assertTrue(res['framework_analysis'])

    def test_dylib_arch_extends_strings_with_framework_strings(self):
        # A full library_analysis(arch='macho') run whose src contains a
        # real Frameworks/Foo.framework/Foo binary exercises the
        # framework_strings -> macho_strings extend at line 87 (assuming
        # the real binary yields extractable strings).
        checksum = 'h' * 32
        tmp = tempfile.mkdtemp()
        with override_settings(UPLD_DIR=tmp):
            base_dir = Path(tmp) / checksum
            base_dir.mkdir(parents=True)
            fw_dir = base_dir / 'Frameworks' / 'Foo.framework'
            fw_dir.mkdir(parents=True)
            shutil.copy2(
                os.path.join(SAMPLES_DIR, 'macho.dylib'), fw_dir / 'Foo')
            res = library_analysis(checksum, str(base_dir), 'macho')
        self.assertTrue(res['framework_analysis'])

    def test_frameworks_analysis_outer_exception_relative_to_mismatch(self):
        # A real framework binary whose actual path is NOT rooted under
        # the given base_dir -> relative_to() raises ValueError for real
        # -> the function's own outer except (lines 126-129).
        checksum = 'i' * 32
        wrong_base = Path(tempfile.mkdtemp()) / checksum
        real_src = tempfile.mkdtemp()
        fw_dir = Path(real_src) / 'Foo.framework'
        fw_dir.mkdir(parents=True)
        shutil.copy2(
            os.path.join(SAMPLES_DIR, 'macho.dylib'), fw_dir / 'Foo')
        res = {
            'macho_analysis': [], 'macho_strings': [], 'macho_symbols': [],
            'framework_analysis': [], 'framework_strings': [],
            'framework_symbols': [],
        }
        frameworks_analysis(checksum, real_src, wrong_base, res)
        self.assertEqual(res['framework_analysis'], [])
