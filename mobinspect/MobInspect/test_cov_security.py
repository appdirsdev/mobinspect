"""Real-execution coverage tests for mobinspect.MobInspect.security.

STRICT: no mocks for business logic. Every test drives real code against
real temp files, a real ThreadPoolExecutor, real subprocess execution (local
loopback / local commands only, no network), and genuine fault injection
(deliberately wrong hashes/signatures to trigger the tampering-detection
raises). A handful of narrow, single-call monkeypatches are used strictly
where the AGENT_INSTRUCTIONS carve-out applies (making one internal/sibling
call fail or return a controlled value where the real dependency cannot be
forced into that shape) — each is called out inline.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from django.test import override_settings

from mobinspect.MobInspect import security
from mobinspect.MobInspect import utils


# ---------------------------------------------------------------------------
# get_sha256 / get_all_files / generate_hashes — real files, real threads
# ---------------------------------------------------------------------------
def test_get_sha256_real_file(tmp_path):
    f = tmp_path / 'sample.txt'
    f.write_text('hello world')
    posix, digest = security.get_sha256(f)
    assert posix == f.as_posix()
    assert digest == utils.sha256(str(f))


def test_get_all_files_filters_skip_extensions(tmp_path):
    d = tmp_path / 'd'
    d.mkdir()
    keep_in_dir = d / 'binary.so'
    keep_in_dir.write_bytes(b'x')
    skip_in_dir = d / 'notes.txt'
    skip_in_dir.write_text('skip me')

    direct_file_keep = tmp_path / 'toplevel.bin'
    direct_file_keep.write_bytes(b'y')
    direct_file_skip = tmp_path / 'toplevel.md'
    direct_file_skip.write_text('skip')

    results = set(security.get_all_files([d, direct_file_keep, direct_file_skip]))
    assert keep_in_dir in results
    assert direct_file_keep in results
    assert skip_in_dir not in results
    assert direct_file_skip not in results


def test_generate_hashes_real(tmp_path):
    f1 = tmp_path / 'a.bin'
    f1.write_bytes(b'AAA')
    f2 = tmp_path / 'b.bin'
    f2.write_bytes(b'BBB')
    hashes, sig = security.generate_hashes([tmp_path])
    assert hashes[f1.as_posix()] == utils.sha256(str(f1))
    assert hashes[f2.as_posix()] == utils.sha256(str(f2))
    assert isinstance(sig, str) and len(sig) == 64


# ---------------------------------------------------------------------------
# get_executable_hashes / store_exec_hashes_at_first_run — real settings,
# real filesystem scan of the actual (small-ish) tool directories.
# ---------------------------------------------------------------------------
def test_get_executable_hashes_real():
    hashes, sig = security.get_executable_hashes()
    assert isinstance(hashes, dict)
    assert isinstance(sig, str) and len(sig) == 64


@override_settings(JAVA_DIRECTORY='/tmp/fake-java-dir-for-coverage-only')
def test_get_executable_hashes_includes_java_directory_setting():
    # JAVA_DIRECTORY need not exist: get_all_files() silently skips a path
    # that is neither an existing file nor an existing directory.
    hashes, sig = security.get_executable_hashes()
    assert isinstance(hashes, dict)


def test_get_executable_hashes_generic_adb_resolved_via_which(monkeypatch):
    # Narrow, single-call patch of the sibling get_adb(): the real adb on
    # this host is already a resolved absolute path (cached), so the literal
    # 'adb' fallback branch cannot be reached through real get_adb() output
    # without controlling it directly.
    monkeypatch.setattr(security, 'get_adb', lambda: 'adb')
    hashes, sig = security.get_executable_hashes()
    assert isinstance(hashes, dict)


def test_store_exec_hashes_success():
    orig = security.EXECUTABLE_HASH_MAP
    try:
        security.store_exec_hashes_at_first_run()
        assert security.EXECUTABLE_HASH_MAP is not None
        assert 'signature' in security.EXECUTABLE_HASH_MAP
    finally:
        security.EXECUTABLE_HASH_MAP = orig


def test_store_exec_hashes_handles_failure(monkeypatch):
    # Narrow, single-call patch of the sibling get_executable_hashes(): there
    # is no real-world input that makes the actual filesystem scan raise, so
    # per the fault-injection carve-out we force the one internal call.
    orig = security.EXECUTABLE_HASH_MAP
    try:
        def boom():
            raise RuntimeError('forced failure for except-branch coverage')
        monkeypatch.setattr(security, 'get_executable_hashes', boom)
        security.store_exec_hashes_at_first_run()  # must not raise
    finally:
        security.EXECUTABLE_HASH_MAP = orig


# ---------------------------------------------------------------------------
# subprocess_hook — real fault injection via deliberately correct/incorrect
# EXECUTABLE_HASH_MAP entries (no mocking of the tamper-check logic itself).
# ---------------------------------------------------------------------------
@pytest.fixture
def restore_hash_map():
    orig = security.EXECUTABLE_HASH_MAP
    yield
    security.EXECUTABLE_HASH_MAP = orig


def test_subprocess_hook_list_args_calls_oldfunc_when_hash_matches(tmp_path, restore_hash_map):
    script = tmp_path / 'myprog'
    script.write_text('#!/bin/sh\necho hi\n')
    real_hash = utils.sha256(str(script))
    security.EXECUTABLE_HASH_MAP = {script.as_posix(): real_hash, 'signature': 'sig'}

    called = {}

    def fake_oldfunc(*args, **kwargs):
        called['args'] = args
        return 'ran'

    result = security.subprocess_hook(fake_oldfunc, [str(script)])
    assert result == 'ran'
    assert called['args'] == ([str(script)],)


def test_subprocess_hook_bare_command_resolved_via_which(restore_hash_map):
    ls_path = Path(shutil.which('ls')).as_posix()
    real_hash = utils.sha256(ls_path)
    security.EXECUTABLE_HASH_MAP = {ls_path: real_hash, 'signature': 'sig'}

    def fake_oldfunc(*a, **k):
        return 'ok'

    result = security.subprocess_hook(fake_oldfunc, ['ls', '-la'])
    assert result == 'ok'


def test_subprocess_hook_string_args_variant(tmp_path, restore_hash_map):
    script = tmp_path / 'prog2'
    script.write_text('x')
    real_hash = utils.sha256(str(script))
    security.EXECUTABLE_HASH_MAP = {script.as_posix(): real_hash, 'signature': 'sig'}

    def fake_oldfunc(*a, **k):
        return 'ok'

    result = security.subprocess_hook(fake_oldfunc, f'{script} someflag')
    assert result == 'ok'


def test_subprocess_hook_detects_jar_tampering(tmp_path, restore_hash_map):
    real_bin = tmp_path / 'java'
    real_bin.write_text('x')
    jar = tmp_path / 'app.jar'
    jar.write_text('jarcontent')
    real_bin_hash = utils.sha256(str(real_bin))
    security.EXECUTABLE_HASH_MAP = {
        real_bin.as_posix(): real_bin_hash,
        jar.as_posix(): 'deadbeef' * 8,  # deliberately wrong hash
        'signature': 'sig',
    }

    def fake_oldfunc(*a, **k):
        return 'ok'

    with pytest.raises(Exception, match='JAR Tampering Detected'):
        security.subprocess_hook(fake_oldfunc, [str(real_bin), str(jar)])


def test_subprocess_hook_detects_executable_tampering(tmp_path, restore_hash_map):
    script = tmp_path / 'tampered'
    script.write_text('real content')
    security.EXECUTABLE_HASH_MAP = {script.as_posix(): '0' * 64, 'signature': 'sig'}

    def fake_oldfunc(*a, **k):
        return 'ok'

    with pytest.raises(Exception, match='Executable Tampering Detected'):
        security.subprocess_hook(fake_oldfunc, [str(script)])


def test_subprocess_hook_unknown_executable_matching_signature(tmp_path, restore_hash_map):
    # Real (uncached) call so we know the *actual* current signature, then
    # reuse it so the hook's internal re-check matches without any mocking.
    real_hashes, real_sig = security.get_executable_hashes()
    script = tmp_path / 'unknown_bin'
    script.write_text('x')
    security.EXECUTABLE_HASH_MAP = dict(real_hashes)
    security.EXECUTABLE_HASH_MAP['signature'] = real_sig

    def fake_oldfunc(*a, **k):
        return 'ran-unknown'

    result = security.subprocess_hook(fake_oldfunc, [str(script)])
    assert result == 'ran-unknown'


def test_subprocess_hook_unknown_executable_signature_mismatch(tmp_path, restore_hash_map):
    security.EXECUTABLE_HASH_MAP = {'signature': 'definitely-not-the-real-signature'}
    script = tmp_path / 'another_unknown'
    script.write_text('x')

    def fake_oldfunc(*a, **k):
        return 'ok'

    with pytest.raises(Exception, match='Executable/Library Tampering Detected'):
        security.subprocess_hook(fake_oldfunc, [str(script)])


# ---------------------------------------------------------------------------
# init_exec_hooks / wrap_function — real monkeypatch of subprocess.Popen,
# restored immediately after; one real end-to-end call through the wrapper.
# ---------------------------------------------------------------------------
def test_init_exec_hooks_wraps_popen():
    original_popen = subprocess.Popen
    try:
        security.init_exec_hooks()
        assert subprocess.Popen is not original_popen
        assert callable(subprocess.Popen)
    finally:
        subprocess.Popen = original_popen


def test_wrapped_popen_executes_real_subprocess(restore_hash_map):
    original_popen = subprocess.Popen
    real_hashes, real_sig = security.get_executable_hashes()
    security.EXECUTABLE_HASH_MAP = dict(real_hashes)
    security.EXECUTABLE_HASH_MAP['signature'] = real_sig
    try:
        security.init_exec_hooks()
        proc = subprocess.Popen(
            [sys.executable, '-c', "print('coverage-hook-test')"],
            stdout=subprocess.PIPE)
        out, _ = proc.communicate(timeout=10)
        assert b'coverage-hook-test' in out
    finally:
        subprocess.Popen = original_popen


# ---------------------------------------------------------------------------
# sanitize_redirect
# ---------------------------------------------------------------------------
def test_sanitize_redirect_open_redirect_blocked():
    assert security.sanitize_redirect('//evil.com/path') == '/'


def test_sanitize_redirect_absolute_scheme_blocked():
    assert security.sanitize_redirect('https://evil.com') == '/'


def test_sanitize_redirect_local_path_allowed():
    assert security.sanitize_redirect('/local/path') == '/local/path'


# ---------------------------------------------------------------------------
# sanitize_filename
# ---------------------------------------------------------------------------
def test_sanitize_filename_replaces_unsafe_chars():
    assert security.sanitize_filename('a b/c*d?.txt') == 'a_b_c_d_.txt'


def test_sanitize_filename_merges_and_strips_underscores():
    assert security.sanitize_filename('__lead__trail__') == 'lead_trail'


# ---------------------------------------------------------------------------
# sanitize_for_logging
# ---------------------------------------------------------------------------
def test_sanitize_for_logging_strips_control_chars():
    assert security.sanitize_for_logging('bad\nname\r\t.txt') == 'bad_name__.txt'


def test_sanitize_for_logging_truncates_long_names():
    long_name = 'a' * 300
    result = security.sanitize_for_logging(long_name)
    assert len(result) == 255


# ---------------------------------------------------------------------------
# valid_host — real (no external network) SSRF validation logic; IP literals
# only, so getaddrinfo never performs a real DNS lookup.
# ---------------------------------------------------------------------------
def test_valid_host_too_long_rejected():
    assert security.valid_host('a' * 2084) is False


def test_valid_host_empty_hostname_rejected():
    assert security.valid_host('http://') is False


def test_valid_host_disallowed_port_rejected():
    assert security.valid_host('93.184.216.34:8080') is False


def test_valid_host_credentials_in_url_rejected():
    assert security.valid_host('user@93.184.216.34') is False


def test_valid_host_path_component_rejected():
    assert security.valid_host('93.184.216.34/path') is False


def test_valid_host_query_component_rejected():
    assert security.valid_host('93.184.216.34?q=1') is False


def test_valid_host_loopback_ip_rejected():
    assert security.valid_host('127.0.0.1') is False


def test_valid_host_private_ip_rejected():
    assert security.valid_host('10.0.0.5') is False


def test_valid_host_link_local_ip_rejected():
    assert security.valid_host('169.254.1.1') is False


def test_valid_host_multicast_ip_rejected():
    assert security.valid_host('224.0.0.1') is False


def test_valid_host_ipv6_loopback_rejected():
    assert security.valid_host('[::1]') is False


def test_valid_host_public_ip_literal_accepted():
    # A real public IP literal — getaddrinfo() on an IP literal is a local
    # parse, not a network call.
    assert security.valid_host('93.184.216.34') is True


def test_valid_host_exception_branch_non_string_input():
    # len(None) raises TypeError for real, caught by the outer except.
    assert security.valid_host(None) is False


# ---------------------------------------------------------------------------
# sanitize_svg — real bleach sanitization
# ---------------------------------------------------------------------------
def test_sanitize_svg_strips_script_tag_keeps_safe_markup():
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<script>alert(1)</script>'
        '<rect x="1" y="2" width="3" height="4"/>'
        '</svg>'
    )
    cleaned = security.sanitize_svg(svg)
    assert '<script' not in cleaned
    assert '<rect' in cleaned


def test_sanitize_svg_strips_event_handler_attribute():
    svg = '<svg><rect x="1" y="2" width="3" height="4" onclick="alert(1)"/></svg>'
    cleaned = security.sanitize_svg(svg)
    assert 'onclick' not in cleaned
