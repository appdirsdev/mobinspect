# coding=utf-8
"""Real-execution unit tests for the ELF checksec module.

STRICT: no mocks / no monkeypatch of internal logic / no fake returns.

Every ELF fed to :class:`ELFChecksec` here is a *genuine* ELF binary:
  * ``test_files/android.so`` is a real 32-bit ARM shared object.
  * Byte-patched copies flip only the ELF header ``e_type`` field
    (a legal, real ELF mutation) to exercise the PIE/DSO/REL/EXEC branches.
  * Variants produced by ``lief`` (add RPATH/RUNPATH, add a dynamic symbol,
    remove dynamic FLAGS, inject a DT_DEBUG entry) are re-serialised to disk
    with ``lief`` and re-parsed as real ELF files.
  * A hand-assembled minimal but valid ELF header exercises the
    "everything absent" negative branches (no NX, no canary, no RELRO,
    stripped, no symbols).

No behaviour of the module under test is faked or patched.
"""
import struct
import tempfile
from pathlib import Path

import lief

import pytest

from mobinspect.StaticAnalyzer.views.common.binary.elf import (
    ELFChecksec,
    FULL_RELRO,
    NA,
    NO_RELRO,
    PARTIAL_RELRO,
    nm_is_debug_symbol_stripped,
)

# repo-root/test_files -> parents[5] from this file
TEST_FILES = Path(__file__).resolve().parents[5] / 'test_files'
ANDROID_SO = TEST_FILES / 'android.so'
STATIC_LIB = TEST_FILES / 'linux_static_lib.a'


def _minimal_elf(extra=b''):
    """Assemble a real, valid, minimal 64-bit DYN ELF header.

    No program headers, no section headers, no symbols -> exercises all
    the "feature absent" code paths without any mocking.
    """
    e = bytearray(64)
    e[0:4] = b'\x7fELF'
    e[4] = 2   # ELFCLASS64
    e[5] = 1   # ELFDATA2LSB
    e[6] = 1   # EV_CURRENT
    struct.pack_into('<H', e, 16, 3)      # e_type = ET_DYN
    struct.pack_into('<H', e, 18, 0x3e)   # e_machine = x86-64
    struct.pack_into('<I', e, 20, 1)      # e_version
    struct.pack_into('<H', e, 52, 64)     # e_ehsize
    return bytes(e) + extra


@pytest.fixture(scope='module')
def workdir():
    d = tempfile.mkdtemp(prefix='elfcov_')
    return Path(d)


@pytest.fixture(scope='module')
def variants(workdir):
    """Build every real ELF variant once for the module."""
    v = {}
    raw = bytearray(ANDROID_SO.read_bytes())

    # --- byte-patched e_type variants (32-bit LSB: e_type @ off16, 2 bytes) ---
    exec_bytes = bytearray(raw)
    exec_bytes[16], exec_bytes[17] = 2, 0   # ET_EXEC
    exec_p = workdir / 'exec.so'
    exec_p.write_bytes(exec_bytes)
    v['exec'] = exec_p

    rel_bytes = bytearray(raw)
    rel_bytes[16], rel_bytes[17] = 1, 0     # ET_REL
    rel_p = workdir / 'rel.so'
    rel_p.write_bytes(rel_bytes)
    v['rel'] = rel_p

    # --- DT_DEBUG injected -> DYN treated as PIE ---
    b = lief.parse(ANDROID_SO.as_posix())
    b.add(lief.ELF.DynamicEntry(lief.ELF.DynamicEntry.TAG.DEBUG_TAG, 0))
    pie_p = workdir / 'pie.so'
    b.write(pie_p.as_posix())
    v['pie'] = pie_p

    # --- RPATH + RUNPATH added ---
    b = lief.parse(ANDROID_SO.as_posix())
    b.add(lief.ELF.DynamicEntryRpath(['/opt/lib']))
    b.add(lief.ELF.DynamicEntryRunPath(['/opt/run']))
    rp = workdir / 'rpath.so'
    b.write(rp.as_posix())
    v['rpath'] = rp

    # --- dynamic FLAGS/FLAGS_1 removed -> Partial RELRO ---
    b = lief.parse(ANDROID_SO.as_posix())
    for tag in (lief.ELF.DynamicEntry.TAG.FLAGS,
                lief.ELF.DynamicEntry.TAG.FLAGS_1):
        entry = b.get(tag)
        if entry:
            b.remove(entry)
    partial_p = workdir / 'partial.so'
    b.write(partial_p.as_posix())
    v['partial'] = partial_p

    # --- dart dynamic symbol added -> is_dart True (symbol path) ---
    b = lief.parse(ANDROID_SO.as_posix())
    sym = lief.ELF.Symbol()
    sym.name = 'Dart_Cleanup'
    b.add_dynamic_symbol(sym)
    dart_p = workdir / 'dart.so'
    b.write(dart_p.as_posix())
    v['dart'] = dart_p

    # --- minimal ELF: no NX, no canary, no RELRO, stripped, no symbols ---
    min_p = workdir / 'min.so'
    min_p.write_bytes(_minimal_elf())
    v['min'] = min_p

    # --- minimal ELF + dart marker string -> is_dart True (strings path) ---
    dartmin_p = workdir / 'dartmin.so'
    dartmin_p.write_bytes(_minimal_elf(b'\x00Dart_Cleanup\x00padding_string'))
    v['dartmin'] = dartmin_p

    # --- genuinely unparseable "ELF" -> lief.parse() returns real None ---
    broken_p = workdir / 'broken.so'
    broken_p.write_bytes(b'not an elf file at all, just garbage bytes 123')
    v['broken'] = broken_p

    # --- real android.so + a real dynamic symbol whose name is raw,
    # invalid-UTF-8 bytes (round-tripped through a real lief write +
    # re-parse, exactly like the other lief-mutated variants above) ---
    b = lief.parse(ANDROID_SO.as_posix())
    bad_sym = lief.ELF.Symbol()
    bad_sym.name = b'\xff\xfe_chk'
    bad_sym.value = 0
    b.add_dynamic_symbol(bad_sym)
    badname_p = workdir / 'badname.so'
    b.write(badname_p.as_posix())
    v['badname'] = badname_p

    return v


def _chk(path, rel=None):
    return ELFChecksec(Path(path), rel or Path(path).name)


# --------------------------------------------------------------------------- #
# Real android.so: the "hardened" positive branches                           #
# --------------------------------------------------------------------------- #
def test_android_so_full_checksec():
    d = _chk(ANDROID_SO).checksec()
    assert d is not None
    assert set(d) == {
        'name', 'nx', 'pie', 'stack_canary', 'relocation_readonly',
        'rpath', 'runpath', 'fortify', 'symbol',
    }
    assert d['name'] == 'android.so'
    # NX set
    assert d['nx']['is_nx'] is True
    assert d['nx']['severity'] == 'info'
    # Shared object -> DSO
    assert d['pie']['is_pie'] == 'Dynamic Shared Object (DSO)'
    assert d['pie']['severity'] == 'info'
    # Canary present
    assert d['stack_canary']['has_canary'] is True
    assert d['stack_canary']['severity'] == 'info'
    # Full RELRO
    assert d['relocation_readonly']['relro'] == FULL_RELRO
    assert d['relocation_readonly']['severity'] == 'info'
    # No RPATH / RUNPATH
    assert d['rpath']['rpath'] is None
    assert d['rpath']['severity'] == 'info'
    assert d['runpath']['runpath'] is None
    assert d['runpath']['severity'] == 'info'
    # Fortified functions present
    assert d['fortify']['is_fortified'] is True
    assert d['fortify']['severity'] == 'info'
    # Symbols available
    assert d['symbol']['is_stripped'] is False
    assert d['symbol']['severity'] == 'warning'


def test_android_so_individual_methods():
    c = _chk(ANDROID_SO)
    assert c.is_elf(c.elf_path) is True
    assert c.is_nx() is True
    assert c.is_pie() == 'dso'
    assert c.is_dart() is False
    assert c.has_canary() is True
    assert c.relro() == FULL_RELRO
    assert c.rpath() is None
    assert c.runpath() is None
    assert c.is_symbols_stripped() is False
    fort = c.fortify()
    assert fort and all(str(f).endswith('_chk') for f in fort)
    syms = c.get_symbols()
    assert len(syms) > 0
    strs = c.strings()
    assert isinstance(strs, list) and len(strs) > 0


# --------------------------------------------------------------------------- #
# PIE / DSO / REL / EXEC header-type branches                                 #
# --------------------------------------------------------------------------- #
def test_pie_executable_no_pie(variants):
    d = _chk(variants['exec']).checksec()
    assert d['pie']['is_pie'] == 'No PIE'
    assert d['pie']['severity'] == 'high'


def test_pie_relocatable(variants):
    c = _chk(variants['rel'])
    assert c.is_pie() == 'rel'
    d = c.checksec()
    assert d['pie']['is_pie'] == 'Relocatable Object File'
    assert d['pie']['severity'] == 'info'


def test_pie_dyn_with_debug_tag(variants):
    c = _chk(variants['pie'])
    assert c.is_pie() == 'pie'
    d = c.checksec()
    assert d['pie']['is_pie'] == 'Position Independent Executable (PIE)'
    assert d['pie']['severity'] == 'info'


# --------------------------------------------------------------------------- #
# RPATH / RUNPATH set branches                                                #
# --------------------------------------------------------------------------- #
def test_rpath_and_runpath_present(variants):
    c = _chk(variants['rpath'])
    assert c.rpath() is not None
    assert c.runpath() is not None
    d = c.checksec()
    assert d['rpath']['severity'] == 'high'
    assert '/opt/lib' in str(d['rpath']['rpath'])
    assert d['runpath']['severity'] == 'high'
    assert '/opt/run' in str(d['runpath']['runpath'])


# --------------------------------------------------------------------------- #
# RELRO variants                                                              #
# --------------------------------------------------------------------------- #
def test_partial_relro(variants):
    c = _chk(variants['partial'])
    assert c.relro() == PARTIAL_RELRO
    d = c.checksec()
    assert d['relocation_readonly']['relro'] == PARTIAL_RELRO
    assert d['relocation_readonly']['severity'] == 'warning'


def test_no_relro_minimal(variants):
    c = _chk(variants['min'])
    assert c.relro() == NO_RELRO
    d = c.checksec()
    assert d['relocation_readonly']['relro'] == NO_RELRO
    assert d['relocation_readonly']['severity'] == 'high'


# --------------------------------------------------------------------------- #
# Dart / Flutter special-casing                                              #
# --------------------------------------------------------------------------- #
def test_dart_via_dynamic_symbol(variants):
    c = _chk(variants['dart'])
    assert c.is_dart() is True
    # Dart -> canary reported present, RELRO Not Applicable
    assert c.has_canary() is True
    assert c.relro() == NA
    d = c.checksec()
    assert d['relocation_readonly']['relro'] == NA
    assert d['relocation_readonly']['severity'] == 'info'
    assert d['stack_canary']['has_canary'] is True


def test_dart_via_strings_and_fortify_info(variants):
    c = _chk(variants['dartmin'])
    assert c.is_dart() is True
    assert c.relro() == NA
    # No fortified functions but Dart -> severity info (not warning)
    assert c.fortify() == []
    d = c.checksec()
    assert d['fortify']['is_fortified'] is False
    assert d['fortify']['severity'] == 'info'


# --------------------------------------------------------------------------- #
# Minimal ELF: all-negative branches                                          #
# --------------------------------------------------------------------------- #
def test_minimal_elf_negative_branches(variants):
    c = _chk(variants['min'])
    assert c.is_nx() is False
    assert c.has_canary() is False
    assert c.is_dart() is False
    assert c.is_symbols_stripped() is True
    assert c.fortify() == []
    assert c.get_symbols() == []
    # strings() falls back to strings_on_binary (lief has no string sections)
    assert isinstance(c.strings(), list)
    d = c.checksec()
    assert d['nx']['is_nx'] is False
    assert d['nx']['severity'] == 'high'
    assert d['stack_canary']['has_canary'] is False
    assert d['stack_canary']['severity'] == 'high'
    # not fortified + not dart -> warning
    assert d['fortify']['is_fortified'] is False
    assert d['fortify']['severity'] == 'warning'
    # stripped -> info
    assert d['symbol']['is_stripped'] is True
    assert d['symbol']['severity'] == 'info'


# --------------------------------------------------------------------------- #
# Non-ELF input -> checksec returns None                                       #
# --------------------------------------------------------------------------- #
def test_non_elf_returns_none():
    c = ELFChecksec(STATIC_LIB, 'linux_static_lib.a')
    assert c.is_elf(c.elf_path) is False
    assert c.checksec() is None


# --------------------------------------------------------------------------- #
# nm-based debug symbol check (real subprocess, real binary)                   #
# --------------------------------------------------------------------------- #
def test_nm_debug_symbol_stripped_real():
    # android.so is not stripped -> nm finds debug symbols
    assert nm_is_debug_symbol_stripped(ANDROID_SO.as_posix()) is False


# --------------------------------------------------------------------------- #
# Genuinely broken "ELF" (lief.parse() returns real None) -> every method     #
# that touches self.elf directly (outside checksec()'s is_elf() gate) hits   #
# its own except block via a real AttributeError on None, not a mock.        #
# --------------------------------------------------------------------------- #
def test_is_dart_and_has_canary_get_symbol_exception(variants):
    c = _chk(variants['broken'])
    assert c.elf is None
    # is_dart() calls self.strings() first (real AttributeError on
    # self.elf.strings -> caught -> falls back to strings_on_binary() on
    # the real, if unparsable, file), then self.elf.get_symbol() per dart
    # marker -> real AttributeError -> caught -> False (lines 281-282).
    assert c.is_dart() is False
    # has_canary()'s own get_symbol() try/except (lines 293-294).
    assert c.has_canary() is False


def test_strings_falls_back_on_broken_elf(variants):
    # self.elf.strings raises (None) -> except -> strings_on_binary()
    # fallback (lines 364-365); still returns a real list, never raises.
    c = _chk(variants['broken'])
    assert isinstance(c.strings(), list)


def test_relro_exception_on_broken_elf(variants):
    # self.elf.get(...) raises on None -> outer except -> NO_RELRO
    # (lines 321-323).
    c = _chk(variants['broken'])
    assert c.relro() == NO_RELRO


def test_is_symbols_stripped_double_exception_on_broken_elf(variants):
    # self.elf.symtab_symbols raises on None -> outer except -> falls back
    # to nm_is_debug_symbol_stripped() (lines 339-341); nm genuinely
    # cannot parse this garbage file either (real non-zero exit ->
    # subprocess.CalledProcessError) -> inner except -> True
    # (lines 343-344).
    c = _chk(variants['broken'])
    assert c.is_symbols_stripped() is True


def test_get_symbols_exception_on_broken_elf(variants):
    # self.elf.symtab_symbols raises on None -> except -> [] (lines 379-380).
    c = _chk(variants['broken'])
    assert c.get_symbols() == []


# --------------------------------------------------------------------------- #
# fortify(): a real, non-UTF-8 dynamic symbol name (round-tripped through a  #
# real lief write + re-parse) forces a genuine UnicodeDecodeError.           #
# --------------------------------------------------------------------------- #
def test_fortify_handles_real_undecodable_symbol_name(variants):
    c = _chk(variants['badname'])
    fort = c.fortify()
    # The undecodable name (b'\xff\xfe_chk') still ends with '_chk' after
    # decode(..., 'replace') substitutes the invalid lead bytes, so it is
    # counted as fortified alongside android.so's genuine __strlen_chk etc.
    assert any(isinstance(f, bytes) and f.endswith(b'_chk') for f in fort)
