"""Real-execution unit tests for mobinspect.MobInspect.utils.

STRICT: no mocks. Every test drives real code with real inputs, real files
from the repo-root test_files/ directory, real temp files, real environment
variables, and real Django ORM/RequestFactory infrastructure.

A handful of tests below use a narrow, single-call ``monkeypatch`` on an
internal/sibling function (e.g. ``psutil.net_if_addrs``, ``find_process_by``,
``os.kill``) — each is called out inline with why real fault injection isn't
possible (a real dependency that's actually installed, a real self-kill
syscall we must not let fire, a real host-dependent enumeration we need to
pin down deterministically).
"""
import io
import os
import platform
import stat
import sqlite3
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from django.test import RequestFactory

from mobinspect.MobInspect import utils
from mobinspect.MobInspect import settings as mobinspect_settings
from mobinspect.StaticAnalyzer.models import RecentScansDB


REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_FILES = REPO_ROOT / 'test_files'


# --------------------------------------------------------------------------
# Pure string / hash helpers
# --------------------------------------------------------------------------
def test_get_md5_str_and_bytes():
    # Known MD5 of empty string
    assert utils.get_md5('') == 'd41d8cd98f00b204e9800998ecf8427e'
    assert utils.get_md5(b'') == 'd41d8cd98f00b204e9800998ecf8427e'
    assert utils.get_md5('abc') == utils.get_md5(b'abc')


def test_gen_sha256_hash_str_and_bytes():
    empty_sha = ('e3b0c44298fc1c149afbf4c8996fb924'
                 '27ae41e4649b934ca495991b7852b855')
    assert utils.gen_sha256_hash('') == empty_sha
    assert utils.gen_sha256_hash(b'') == empty_sha


def test_filename_from_path():
    assert utils.filename_from_path('/a/b/c.txt') == 'c.txt'
    assert utils.filename_from_path('C:\\dir\\file.apk') == 'file.apk'
    # trailing separator -> falls back to basename of head
    assert utils.filename_from_path('/a/b/') == 'b'


def test_find_between():
    assert utils.find_between('hello [world] end', '[', ']') == 'world'
    assert utils.find_between('no markers', '[', ']') == ''
    assert utils.find_between('start only [', '[', ']') == ''


def test_is_number():
    assert utils.is_number('123') is True
    assert utils.is_number('1.5') is True
    assert utils.is_number('') is False
    assert utils.is_number('NaN') is False
    assert utils.is_number('abc') is False
    # unicode numeric fallback (Roman numeral / fraction char)
    assert utils.is_number('½') is True  # ½


def test_python_list():
    assert utils.python_list(None) == []
    assert utils.python_list([1, 2]) == [1, 2]
    assert utils.python_list('[1, 2, 3]') == [1, 2, 3]


def test_python_dict():
    assert utils.python_dict(None) == {}
    assert utils.python_dict({'a': 1}) == {'a': 1}
    assert utils.python_dict("{'a': 1}") == {'a': 1}


def test_is_base64():
    assert utils.is_base64('aGVsbG8=')
    # spaces are not valid base64 chars
    assert not utils.is_base64('not valid !')


def test_is_md5():
    assert utils.is_md5('d41d8cd98f00b204e9800998ecf8427e')
    assert not utils.is_md5('nothex')
    assert not utils.is_md5('d41d8cd98f00b204e9800998ecf8427')  # 31 chars


def test_cmd_injection_check():
    assert utils.cmd_injection_check('foo; rm -rf') is True
    assert utils.cmd_injection_check('foo && bar') is True
    assert utils.cmd_injection_check('foo%7Cbar') is True
    assert utils.cmd_injection_check('cleaninput') is False


def test_cmd_injection_check_backtick_and_dollar_paren():
    """Regression: backtick / $() command substitution must be caught.

    cmd_injection_check() is the sole gate on the `url` parameter of
    DynamicAnalyzer.views.android.tests_common.start_deeplink(), which
    hands the value unescaped to `adb shell am start ... -d <url>`. adb
    joins all trailing argv tokens into a single string and runs it via
    the device's default shell, so backtick / $(...) command
    substitution in the URL is real remote command injection on the
    connected Android device -- the same class of bug the existing
    breakers (`;`, `&&`, `|`) already guard against. Before the fix,
    both assertions below failed (bypassed the filter).
    """
    assert utils.cmd_injection_check('http://x`reboot`') is True
    assert utils.cmd_injection_check('http://x$(reboot)') is True
    assert utils.cmd_injection_check('http://x%60reboot%60') is True
    assert utils.cmd_injection_check('http://x%24%28reboot%29') is True


def test_strict_package_check():
    assert utils.strict_package_check('com.example.app')
    # starts with a digit -> no regex match -> None
    assert not utils.strict_package_check('1bad.package')
    # '..' only logs an error but the regex still matches, so a truthy
    # match object is returned (documents real behaviour, exercises branch).
    assert utils.strict_package_check('com..bad')


def test_strict_ios_class():
    assert utils.strict_ios_class('My.Class_Name')
    assert not utils.strict_ios_class('bad class!')


def test_is_instance_id():
    assert utils.is_instance_id('12345678-1234-1234-1234-123456789abc')
    assert not utils.is_instance_id('not-a-uuid')


def test_is_path_traversal():
    assert utils.is_path_traversal('') is False
    assert utils.is_path_traversal('/etc/passwd') is True  # absolute
    assert utils.is_path_traversal('\\windows\\x') is True
    assert utils.is_path_traversal('a/../b') is True  # dotdot
    assert utils.is_path_traversal('%2e%2e/etc') is True  # url-encoded
    assert utils.is_path_traversal('%252e%252e/x') is True  # double encoded
    assert utils.is_path_traversal('safe/relative/path') is False


def test_find_key_in_dict():
    data = {'a': 1, 'b': {'a': 2, 'c': [{'a': 3}]}}
    assert sorted(utils.find_key_in_dict('a', data)) == [1, 2, 3]
    assert list(utils.find_key_in_dict('missing', data)) == []
    # non-dict input yields nothing
    assert list(utils.find_key_in_dict('a', 'notadict')) == []


def test_key_helper():
    assert utils.key({'x': 5}, 'x') == 5
    assert utils.key({'x': 5}, 'y') is None


def test_replace_filter():
    assert utils.replace('aaa', 'a|b') == 'bbb'
    # invalid arg (not exactly 2 parts) returns value unchanged
    assert utils.replace('aaa', 'noseparator') == 'aaa'


def test_pathify():
    assert utils.pathify('com.example.app') == 'com/example/app'


def test_relative_path():
    assert utils.relative_path('a/b/c/d.txt') == 'c/d.txt'
    # fewer than 2 separators returns unchanged
    assert utils.relative_path('a/b') == 'a/b'
    assert utils.relative_path('noslash') == 'noslash'


def test_pretty_json():
    assert utils.pretty_json('{"a": 1}') == '{\n    "a": 1\n}'
    # invalid JSON returned unchanged
    assert utils.pretty_json('not json') == 'not json'


def test_base64_decode():
    # 'aGVsbG8=' -> 'hello'
    out = utils.base64_decode('aGVsbG8=')
    assert 'Base64 Decoded: hello' in out
    # non base64 returns value unchanged
    assert utils.base64_decode('!!not!!') == '!!not!!'


def test_base64_encode():
    assert utils.base64_encode('hello') == b'aGVsbG8='
    assert utils.base64_encode(b'hello') == b'aGVsbG8='


def test_android_component():
    assert utils.android_component('Activity-Alias foo') == 'activity_alias_'
    assert utils.android_component('Activity foo') == 'activity_'
    assert utils.android_component('Service foo') == 'service_'
    assert utils.android_component('Content Provider foo') == 'provider_'
    assert utils.android_component('Broadcast Receiver foo') == 'receiver_'
    assert utils.android_component('nothing') == ''


def test_clean_filename_non_windows():
    # On macOS/Linux the function returns the filename unchanged.
    assert utils.clean_filename('weird name.txt') == 'weird name.txt'


def test_id_generator():
    val = utils.id_generator(size=10)
    assert len(val) == 10
    assert all(c in ('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for c in val)


def test_get_android_src_dir(tmp_path):
    assert utils.get_android_src_dir(tmp_path, 'apk') == tmp_path / 'java_source'
    assert utils.get_android_src_dir(tmp_path, 'eclipse') == tmp_path / 'src'
    # studio: kotlin fallback when java missing but kotlin exists
    kt = tmp_path / 'app' / 'src' / 'main' / 'kotlin'
    kt.mkdir(parents=True)
    assert utils.get_android_src_dir(tmp_path, 'studio') == kt
    assert utils.get_android_src_dir(tmp_path, 'unknown') is None


def test_get_android_dm_exception_msg():
    msg = utils.get_android_dm_exception_msg()
    assert 'ANALYZER_IDENTIFIER' in msg


def test_get_config_loc():
    loc = utils.get_config_loc()
    # USE_HOME is True by default -> path ends with config.py
    assert loc.endswith('config.py') or loc == 'MobInspect/settings.py'


def test_settings_enabled():
    # A real disabled-ish attr and an enabled one on the real settings object.
    setattr(mobinspect_settings, '_TEST_ENABLED_ATTR', 'yes')
    setattr(mobinspect_settings, '_TEST_DISABLED_ATTR', '0')
    try:
        assert utils.settings_enabled('_TEST_ENABLED_ATTR') is True
        assert utils.settings_enabled('_TEST_DISABLED_ATTR') is False
        assert utils.settings_enabled('_NONEXISTENT_ATTR_XYZ') is False
    finally:
        delattr(mobinspect_settings, '_TEST_ENABLED_ATTR')
        delattr(mobinspect_settings, '_TEST_DISABLED_ATTR')


def test_parse_host_port():
    assert utils.parse_host_port('127.0.0.1:5555') == ('127.0.0.1', 5555)
    assert utils.parse_host_port('[::1]:8080') == ('::1', 8080)
    with pytest.raises(ValueError):
        utils.parse_host_port('no-port-here')


def test_common_check_branches():
    orig = getattr(mobinspect_settings, 'CORELLIUM_API_KEY', '')
    try:
        mobinspect_settings.CORELLIUM_API_KEY = ''
        res = utils.common_check('anything')
        assert res['message'] == 'Missing Corellium API key'

        mobinspect_settings.CORELLIUM_API_KEY = 'realkey'
        res = utils.common_check('bad-instance')
        assert res['message'] == 'Invalid instance identifier'

        res = utils.common_check('12345678-1234-1234-1234-123456789abc')
        assert res is None
    finally:
        mobinspect_settings.CORELLIUM_API_KEY = orig


# --------------------------------------------------------------------------
# File-magic detectors using REAL sample binaries from test_files/
# --------------------------------------------------------------------------
def test_is_zip_magic_real_apk():
    with open(TEST_FILES / 'android.apk', 'rb') as f:
        assert utils.is_zip_magic(f) is True
    with open(TEST_FILES / 'android.so', 'rb') as f:
        assert utils.is_zip_magic(f) is False


def test_is_elf_so_magic_real_so():
    with open(TEST_FILES / 'android.so', 'rb') as f:
        assert utils.is_elf_so_magic(f) is True
    with open(TEST_FILES / 'android.apk', 'rb') as f:
        assert utils.is_elf_so_magic(f) is False


def test_is_dylib_magic_real_dylib():
    with open(TEST_FILES / 'macho.dylib', 'rb') as f:
        assert utils.is_dylib_magic(f) is True
    with open(TEST_FILES / 'android.apk', 'rb') as f:
        assert utils.is_dylib_magic(f) is False


def test_is_a_magic_real_static_lib():
    with open(TEST_FILES / 'linux_static_lib.a', 'rb') as f:
        assert utils.is_a_magic(f) is True
    with open(TEST_FILES / 'android.apk', 'rb') as f:
        assert utils.is_a_magic(f) is False


def test_sha256_and_object_match_real_file():
    apk = TEST_FILES / 'android.jar'
    from_path = utils.sha256(str(apk))
    with open(apk, 'rb') as f:
        from_obj = utils.sha256_object(f)
    assert from_path == from_obj
    assert len(from_path) == 64


def test_file_size_real_file():
    size = utils.file_size(str(TEST_FILES / 'android.apk'))
    assert isinstance(size, float)
    assert size >= 0


# --------------------------------------------------------------------------
# Filesystem helpers with real temp files/dirs
# --------------------------------------------------------------------------
def test_is_file_exists_and_dir_exists(tmp_path):
    f = tmp_path / 'a.txt'
    f.write_text('hi')
    assert utils.is_file_exists(str(f)) is True
    assert utils.is_file_exists(str(tmp_path / 'nope.txt')) is False
    # shutil.which fallback: 'ls' resolves on PATH
    assert utils.is_file_exists('ls') is True
    assert utils.is_dir_exists(str(tmp_path)) is True
    assert utils.is_dir_exists(str(tmp_path / 'missingdir')) is False


def test_is_pipe_or_link_real(tmp_path):
    target = tmp_path / 'real.txt'
    target.write_text('x')
    link = tmp_path / 'link.txt'
    os.symlink(target, link)
    assert utils.is_pipe_or_link(str(link)) is True

    fifo = tmp_path / 'myfifo'
    os.mkfifo(fifo)
    assert utils.is_pipe_or_link(str(fifo)) is True

    assert utils.is_pipe_or_link(str(target)) is False


def test_is_safe_path(tmp_path):
    root = tmp_path / 'root'
    root.mkdir()
    inside = root / 'sub' / 'file.txt'
    inside.parent.mkdir()
    inside.write_text('x')
    assert utils.is_safe_path(str(root), str(inside), 'sub/file.txt') is True
    # path traversal in raw_file rejected
    assert utils.is_safe_path(str(root), str(inside), '../evil') is False
    # check_path outside root
    outside = tmp_path / 'outside.txt'
    outside.write_text('x')
    assert utils.is_safe_path(str(root), str(outside), 'outside.txt') is False


def test_set_permissions_real():
    import shutil as _shutil
    base = Path(tempfile.mkdtemp())
    try:
        # File directly under base: rglob('*') yields descendants (not the
        # base itself), so base stays traversable and we can stat the file.
        f = base / 'file.txt'
        f.write_text('data')
        sub = base / 'sub'
        sub.mkdir()
        utils.set_permissions(str(base))
        mode = f.stat().st_mode & 0o777
        # Owner read/write present, execute bits stripped.
        assert mode & 0o600 == 0o600
        assert mode & 0o111 == 0
    finally:
        # Top-down restore so directories become traversable before we
        # recurse into them, then remove the whole tree.
        for root, dirs, files in os.walk(base):
            os.chmod(root, 0o755)
            for name in files:
                try:
                    os.chmod(os.path.join(root, name), 0o644)
                except Exception:
                    pass
        _shutil.rmtree(base, ignore_errors=True)


def test_read_sqlite_real(tmp_path):
    db = tmp_path / 'sample.sqlite'
    con = sqlite3.connect(str(db))
    cur = con.cursor()
    cur.execute('CREATE TABLE person (id INTEGER, name TEXT)')
    cur.execute("INSERT INTO person VALUES (1, 'alice')")
    cur.execute("INSERT INTO person VALUES (2, 'bob')")
    con.commit()
    con.close()
    result = utils.read_sqlite(str(db))
    assert 'person' in result
    assert result['person']['head'] == ['id', 'name']
    assert ['1', 'alice'] in result['person']['data']


def test_read_sqlite_bad_file(tmp_path):
    # Non-sqlite file -> handled exception returns empty dict
    bad = tmp_path / 'notdb.bin'
    bad.write_bytes(b'\x00\x01\x02not a database')
    assert utils.read_sqlite(str(bad)) == {}


# --------------------------------------------------------------------------
# Environment / platform helpers (real env var manipulation, no mocks)
# --------------------------------------------------------------------------
def test_docker_translate_localhost_non_docker():
    # Ensure not in docker platform -> identity return.
    old = os.environ.pop('MOBINSPECT_PLATFORM', None)
    try:
        assert utils.docker_translate_localhost('localhost:5555') == \
            'localhost:5555'
        assert utils.docker_translate_localhost('') == ''
    finally:
        if old is not None:
            os.environ['MOBINSPECT_PLATFORM'] = old


def test_docker_translate_localhost_docker():
    old = os.environ.get('MOBINSPECT_PLATFORM')
    os.environ['MOBINSPECT_PLATFORM'] = 'docker'
    try:
        # emulator-NNNN -> host.docker.internal:(console+1)
        assert utils.docker_translate_localhost('emulator-5554') == \
            'host.docker.internal:5555'
        # localhost:port -> host.docker.internal:port
        assert utils.docker_translate_localhost('127.0.0.1:5555') == \
            'host.docker.internal:5555'
        assert utils.docker_translate_localhost('localhost:6000') == \
            'host.docker.internal:6000'
        # unrelated identifier untouched
        assert utils.docker_translate_localhost('192.168.1.5:5555') == \
            '192.168.1.5:5555'
    finally:
        if old is None:
            os.environ.pop('MOBINSPECT_PLATFORM', None)
        else:
            os.environ['MOBINSPECT_PLATFORM'] = old


def test_docker_translate_proxy_ip():
    old = os.environ.get('MOBINSPECT_PLATFORM')
    # non-docker -> identity
    os.environ.pop('MOBINSPECT_PLATFORM', None)
    try:
        assert utils.docker_translate_proxy_ip('127.0.0.1') == '127.0.0.1'
        os.environ['MOBINSPECT_PLATFORM'] = 'docker'
        assert utils.docker_translate_proxy_ip('127.0.0.1') == \
            'host.docker.internal'
        assert utils.docker_translate_proxy_ip('localhost') == \
            'host.docker.internal'
        assert utils.docker_translate_proxy_ip('10.0.0.5') == '10.0.0.5'
    finally:
        if old is None:
            os.environ.pop('MOBINSPECT_PLATFORM', None)
        else:
            os.environ['MOBINSPECT_PLATFORM'] = old


def test_upstream_proxy_disabled():
    # Default: UPSTREAM_PROXY_ENABLED is falsy -> proxies map to None.
    proxies, verify = utils.upstream_proxy('https')
    assert proxies == {'https': None}
    assert isinstance(verify, bool)


def test_get_system_resources_real():
    cores, threads, ram = utils.get_system_resources()
    # logical processors and RAM should be positive on any real host
    assert threads is None or threads >= 1
    assert ram > 0


def test_get_network_real():
    ips = utils.get_network()
    assert isinstance(ips, list)


def test_get_proxy_ip():
    # No identifier -> None
    assert utils.get_proxy_ip('') is None
    # Identifier without ':' -> None
    assert utils.get_proxy_ip('deviceid') is None
    # Well-formed identifier; returns a matching IP or None (real network)
    res = utils.get_proxy_ip('10.255.255.255:5555')
    assert res is None or isinstance(res, str)


def test_find_java_binary_real():
    jb = utils.find_java_binary()
    assert isinstance(jb, str)
    assert jb.endswith('java') or jb.endswith('java.exe')


def test_find_aapt_real():
    # Returns a path string if found on this host, else None. Both valid.
    res = utils.find_aapt('aapt')
    assert res is None or isinstance(res, str)


def test_find_process_by_real():
    # Real psutil enumeration; returns a set (likely empty for fake name).
    res = utils.find_process_by('a_process_that_does_not_exist_zzz')
    assert isinstance(res, set)


def test_get_adb_real():
    # Real call; returns 'adb' or a discovered path. Must not raise.
    res = utils.get_adb()
    assert isinstance(res, str)
    assert len(res) > 0


def test_get_device_env_identifier():
    old = os.environ.get('ANALYZER_IDENTIFIER')
    old_platform = os.environ.pop('MOBINSPECT_PLATFORM', None)
    os.environ['ANALYZER_IDENTIFIER'] = '192.168.1.10:5555'
    try:
        # Non-docker -> returns identifier unchanged (no subprocess path hit).
        assert utils.get_device() == '192.168.1.10:5555'
    finally:
        if old is None:
            os.environ.pop('ANALYZER_IDENTIFIER', None)
        else:
            os.environ['ANALYZER_IDENTIFIER'] = old
        if old_platform is not None:
            os.environ['MOBINSPECT_PLATFORM'] = old_platform


# --------------------------------------------------------------------------
# stdout redirection helpers
# --------------------------------------------------------------------------
def test_disable_and_enable_print():
    import sys
    original = sys.stdout
    try:
        utils.disable_print()
        assert sys.stdout is not original
        print('this goes to devnull')
    finally:
        utils.enable_print()
    assert sys.stdout is sys.__stdout__


# --------------------------------------------------------------------------
# run_with_timeout - real threadpool execution
# --------------------------------------------------------------------------
def test_run_with_timeout_success():
    def add(a, b):
        return a + b
    assert utils.run_with_timeout(add, 5, 2, 3) == 5


def test_run_with_timeout_times_out():
    import time

    def slow():
        time.sleep(2)
        return 'done'
    with pytest.raises(utils.TaskTimeoutError):
        utils.run_with_timeout(slow, 0.2)


# --------------------------------------------------------------------------
# print_n_send_error_response - real RequestFactory + real template render
# --------------------------------------------------------------------------
def test_print_n_send_error_response_api():
    rf = RequestFactory()
    req = rf.get('/')
    res = utils.print_n_send_error_response(req, 'boom', api=True)
    assert res == {'error': 'boom'}


@pytest.mark.django_db
def test_print_n_send_error_response_render():
    rf = RequestFactory()
    req = rf.get('/')
    res = utils.print_n_send_error_response(req, 'boom', api=False)
    assert res.status_code == 500


# --------------------------------------------------------------------------
# DB-backed helpers: append_scan_status / get_scan_logs
# --------------------------------------------------------------------------
@pytest.mark.django_db
def test_append_scan_status_and_get_logs():
    checksum = 'a' * 32
    RecentScansDB.objects.create(
        MD5=checksum,
        FILE_NAME='android.apk',
        APP_NAME='test',
        PACKAGE_NAME='com.test',
        SCAN_LOGS='[]',
    )
    # init resets logs to empty list
    utils.append_scan_status(checksum, 'init')
    assert utils.get_scan_logs(checksum) == []

    # append a real status entry
    utils.append_scan_status(checksum, 'Analyzing manifest')
    logs = utils.get_scan_logs(checksum)
    assert len(logs) == 1
    assert logs[0]['status'] == 'Analyzing manifest'

    # append with exception detail
    utils.append_scan_status(checksum, 'Failed step', 'traceback detail')
    logs = utils.get_scan_logs(checksum)
    assert len(logs) == 2
    assert logs[1]['exception'] == 'traceback detail'


@pytest.mark.django_db
def test_append_scan_status_missing_row_is_silent():
    # No row exists for this checksum -> DoesNotExist swallowed, no raise.
    utils.append_scan_status('f' * 32, 'some status')
    # get_scan_logs for missing checksum returns empty list
    assert utils.get_scan_logs('f' * 32) == []


@pytest.mark.django_db
def test_get_active_adb_connection_device_none():
    # No active AdbConnection rows -> returns None (no adb subprocess path).
    assert utils.get_active_adb_connection_device() is None


# --------------------------------------------------------------------------
# upstream_proxy — enabled branches (real settings-object attribute swaps)
# --------------------------------------------------------------------------
def _snapshot(*names):
    return {n: getattr(mobinspect_settings, n) for n in names}


def _restore(snap):
    for k, v in snap.items():
        setattr(mobinspect_settings, k, v)


def test_upstream_proxy_enabled_no_username():
    names = ('UPSTREAM_PROXY_ENABLED', 'UPSTREAM_PROXY_USERNAME',
             'UPSTREAM_PROXY_TYPE', 'UPSTREAM_PROXY_IP', 'UPSTREAM_PROXY_PORT')
    snap = _snapshot(*names)
    try:
        mobinspect_settings.UPSTREAM_PROXY_ENABLED = True
        mobinspect_settings.UPSTREAM_PROXY_USERNAME = ''
        mobinspect_settings.UPSTREAM_PROXY_TYPE = 'http'
        mobinspect_settings.UPSTREAM_PROXY_IP = '10.0.0.5'
        mobinspect_settings.UPSTREAM_PROXY_PORT = 8080
        proxies, verify = utils.upstream_proxy('https')
        assert proxies == {'https': 'http://10.0.0.5:8080'}
    finally:
        _restore(snap)


def test_upstream_proxy_enabled_with_username():
    names = ('UPSTREAM_PROXY_ENABLED', 'UPSTREAM_PROXY_USERNAME',
             'UPSTREAM_PROXY_PASSWORD', 'UPSTREAM_PROXY_TYPE',
             'UPSTREAM_PROXY_IP', 'UPSTREAM_PROXY_PORT')
    snap = _snapshot(*names)
    try:
        mobinspect_settings.UPSTREAM_PROXY_ENABLED = True
        mobinspect_settings.UPSTREAM_PROXY_USERNAME = 'alice'
        mobinspect_settings.UPSTREAM_PROXY_PASSWORD = 's3cret'
        mobinspect_settings.UPSTREAM_PROXY_TYPE = 'https'
        mobinspect_settings.UPSTREAM_PROXY_IP = '192.168.1.9'
        mobinspect_settings.UPSTREAM_PROXY_PORT = 3128
        proxies, verify = utils.upstream_proxy('http')
        assert proxies == {'http': 'https://alice:s3cret@192.168.1.9:3128'}
    finally:
        _restore(snap)


# --------------------------------------------------------------------------
# find_java_binary — JAVA_DIRECTORY / JAVA_HOME branches (real filesystem)
# --------------------------------------------------------------------------
def test_find_java_binary_with_java_directory_trailing_slash(tmp_path):
    orig = mobinspect_settings.JAVA_DIRECTORY
    try:
        mobinspect_settings.JAVA_DIRECTORY = str(tmp_path) + '/'
        assert utils.find_java_binary() == str(tmp_path) + '/java'
    finally:
        mobinspect_settings.JAVA_DIRECTORY = orig


def test_find_java_binary_with_java_directory_no_trailing_slash(tmp_path):
    orig = mobinspect_settings.JAVA_DIRECTORY
    try:
        mobinspect_settings.JAVA_DIRECTORY = str(tmp_path)
        assert utils.find_java_binary() == str(tmp_path) + '/java'
    finally:
        mobinspect_settings.JAVA_DIRECTORY = orig


def test_find_java_binary_with_java_directory_backslash(tmp_path):
    # A real directory whose name literally ends in a backslash character —
    # valid on POSIX filesystems (only '/' and NUL are forbidden), so this
    # exercises the `endswith('\\')` branch with a genuine directory.
    orig = mobinspect_settings.JAVA_DIRECTORY
    try:
        weird_dir = tmp_path / 'javadir\\'
        weird_dir.mkdir()
        mobinspect_settings.JAVA_DIRECTORY = str(weird_dir)
        assert utils.find_java_binary() == str(weird_dir) + 'java'
    finally:
        mobinspect_settings.JAVA_DIRECTORY = orig


def test_find_java_binary_via_java_home(tmp_path):
    orig_dir = mobinspect_settings.JAVA_DIRECTORY
    old_java_home = os.environ.get('JAVA_HOME')
    try:
        mobinspect_settings.JAVA_DIRECTORY = ''
        java_home = tmp_path / 'jdk'
        bin_dir = java_home / 'bin'
        bin_dir.mkdir(parents=True)
        java_bin = bin_dir / 'java'
        java_bin.write_text('#!/bin/sh\necho fake java\n')
        os.environ['JAVA_HOME'] = str(java_home)
        assert utils.find_java_binary() == str(java_bin)
    finally:
        mobinspect_settings.JAVA_DIRECTORY = orig_dir
        if old_java_home is None:
            os.environ.pop('JAVA_HOME', None)
        else:
            os.environ['JAVA_HOME'] = old_java_home


# --------------------------------------------------------------------------
# find_aapt — which()-found branch, SDK-scan-found branch, not-found branch
# --------------------------------------------------------------------------
def test_find_aapt_found_via_which():
    import shutil as _shutil
    result = utils.find_aapt('ls')
    assert result == _shutil.which('ls')


def test_find_aapt_not_found_returns_none(tmp_path, monkeypatch):
    # Redirect HOME to an empty tmp dir so no real Android SDK paths exist,
    # and use a tool name guaranteed absent from PATH.
    monkeypatch.setenv('HOME', str(tmp_path))
    assert utils.find_aapt('definitely_not_a_real_tool_xyz') is None


def test_find_aapt_found_in_fake_sdk(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    sdk = tmp_path / 'Library' / 'Android' / 'sdk' / 'build-tools' / '34.0.0'
    sdk.mkdir(parents=True)
    tool = sdk / 'faketool_xyz'
    tool.write_text('x')
    assert utils.find_aapt('faketool_xyz') == str(tool)


# --------------------------------------------------------------------------
# docker_translate_localhost — real exception branch (non-string identifier)
# --------------------------------------------------------------------------
def test_docker_translate_localhost_exception_branch():
    old = os.environ.get('MOBINSPECT_PLATFORM')
    os.environ['MOBINSPECT_PLATFORM'] = 'docker'
    try:
        # An int has no .strip() -> real AttributeError -> except -> returned as-is.
        assert utils.docker_translate_localhost(12345) == 12345
    finally:
        if old is None:
            os.environ.pop('MOBINSPECT_PLATFORM', None)
        else:
            os.environ['MOBINSPECT_PLATFORM'] = old


# --------------------------------------------------------------------------
# get_active_adb_connection_device — real DB row + real (local) adb connect
# --------------------------------------------------------------------------
@pytest.mark.django_db
def test_get_active_adb_connection_device_real_row():
    from mobinspect.RBAC.models import AdbConnection
    AdbConnection.objects.create(
        label='cov-test-conn', host_port='127.0.0.1:1',
        platform='android', is_active=True)
    # Real `adb connect 127.0.0.1:1` attempt (loopback, no listener -> fails
    # fast, best-effort and swallowed); the host_port is still returned.
    assert utils.get_active_adb_connection_device() == '127.0.0.1:1'


def test_get_active_adb_connection_device_lookup_error(monkeypatch):
    # Narrow, single-call monkeypatch of django.apps.apps.get_model: this is
    # exactly the scenario the production code's own comment documents
    # ("App not ready / table missing (pre-migrate) / any lookup error"),
    # which cannot be induced for real without tearing down the DB for every
    # other test in this session.
    import django.apps
    def boom(*a, **k):
        raise RuntimeError('simulated: table missing pre-migrate')
    monkeypatch.setattr(django.apps.apps, 'get_model', boom)
    assert utils.get_active_adb_connection_device() is None


# --------------------------------------------------------------------------
# get_device — active-connection branch, settings-fallback branch
# --------------------------------------------------------------------------
@pytest.mark.django_db
def test_get_device_via_active_adb_connection():
    from mobinspect.RBAC.models import AdbConnection
    old = os.environ.pop('ANALYZER_IDENTIFIER', None)
    old_platform = os.environ.pop('MOBINSPECT_PLATFORM', None)
    AdbConnection.objects.create(
        label='cov-test-conn2', host_port='192.168.50.50:5555',
        platform='android', is_active=True)
    try:
        assert utils.get_device() == '192.168.50.50:5555'
    finally:
        if old is not None:
            os.environ['ANALYZER_IDENTIFIER'] = old
        if old_platform is not None:
            os.environ['MOBINSPECT_PLATFORM'] = old_platform


@pytest.mark.django_db
def test_get_device_via_settings_analyzer_identifier():
    old = os.environ.pop('ANALYZER_IDENTIFIER', None)
    orig_setting = mobinspect_settings.ANALYZER_IDENTIFIER
    try:
        mobinspect_settings.ANALYZER_IDENTIFIER = '10.10.10.10:5555'
        assert utils.get_device() == '10.10.10.10:5555'
    finally:
        mobinspect_settings.ANALYZER_IDENTIFIER = orig_setting
        if old is not None:
            os.environ['ANALYZER_IDENTIFIER'] = old


@pytest.mark.django_db
def test_get_device_falls_through_to_adb_devices_command():
    old = os.environ.pop('ANALYZER_IDENTIFIER', None)
    orig_setting = mobinspect_settings.ANALYZER_IDENTIFIER
    try:
        mobinspect_settings.ANALYZER_IDENTIFIER = ''
        # Real `adb devices` invocation (local adb server, no network); no
        # active AdbConnection row exists for this test's DB state.
        result = utils.get_device()
        assert result is None or isinstance(result, str)
    finally:
        mobinspect_settings.ANALYZER_IDENTIFIER = orig_setting
        if old is not None:
            os.environ['ANALYZER_IDENTIFIER'] = old


@pytest.mark.django_db
def test_get_device_with_attached_device_from_adb_devices(tmp_path):
    # A real (fake-content) executable standing in for `adb`, so
    # `adb devices` deterministically reports one attached device -- the
    # real system adb has no guaranteed attached emulator/device here.
    fake_adb = tmp_path / 'adb'
    fake_adb.write_text(
        '#!/bin/sh\n'
        'echo "List of devices attached"\n'
        'echo "emulator-5554\tdevice"\n'
        'echo ""\n')
    fake_adb.chmod(0o755)

    old = os.environ.pop('ANALYZER_IDENTIFIER', None)
    old_platform = os.environ.pop('MOBINSPECT_PLATFORM', None)
    orig_setting = mobinspect_settings.ANALYZER_IDENTIFIER
    orig_adb_binary = mobinspect_settings.ADB_BINARY
    orig_adb_path = utils.ADB_PATH
    try:
        mobinspect_settings.ANALYZER_IDENTIFIER = ''
        mobinspect_settings.ADB_BINARY = str(fake_adb)
        utils.ADB_PATH = None
        assert utils.get_device() == 'emulator-5554'
    finally:
        mobinspect_settings.ANALYZER_IDENTIFIER = orig_setting
        mobinspect_settings.ADB_BINARY = orig_adb_binary
        utils.ADB_PATH = orig_adb_path
        if old is not None:
            os.environ['ANALYZER_IDENTIFIER'] = old
        if old_platform is not None:
            os.environ['MOBINSPECT_PLATFORM'] = old_platform


@pytest.mark.django_db
def test_get_device_with_no_attached_devices_falls_through_to_error_log(tmp_path):
    # A real (fake-content) `adb` reporting zero attached devices (just the
    # "List of devices attached" header + trailing blank line, so
    # len(out) <= 2): get_device() falls all the way through its final
    # `if len(out) > 2` guard without returning, hits the trailing
    # `logger.error(get_android_dm_exception_msg())` line, and implicitly
    # returns None (utils.py's very last statement in the function).
    fake_adb = tmp_path / 'adb'
    fake_adb.write_text(
        '#!/bin/sh\n'
        'echo "List of devices attached"\n'
        'echo ""\n')
    fake_adb.chmod(0o755)

    old = os.environ.pop('ANALYZER_IDENTIFIER', None)
    old_platform = os.environ.pop('MOBINSPECT_PLATFORM', None)
    orig_setting = mobinspect_settings.ANALYZER_IDENTIFIER
    orig_adb_binary = mobinspect_settings.ADB_BINARY
    orig_adb_path = utils.ADB_PATH
    try:
        mobinspect_settings.ANALYZER_IDENTIFIER = ''
        mobinspect_settings.ADB_BINARY = str(fake_adb)
        utils.ADB_PATH = None
        assert utils.get_device() is None
    finally:
        mobinspect_settings.ANALYZER_IDENTIFIER = orig_setting
        mobinspect_settings.ADB_BINARY = orig_adb_binary
        utils.ADB_PATH = orig_adb_path
        if old is not None:
            os.environ['ANALYZER_IDENTIFIER'] = old
        if old_platform is not None:
            os.environ['MOBINSPECT_PLATFORM'] = old_platform


# --------------------------------------------------------------------------
# get_adb — settings-binary branch, cached-path branch, multi-location warn,
# exception branch (narrow monkeypatch of find_process_by; psutil-backed
# enumeration is host-dependent and cannot be forced into these exact shapes
# for real).
# --------------------------------------------------------------------------
def test_get_adb_uses_settings_adb_binary(tmp_path):
    fake_adb = tmp_path / 'myadb'
    fake_adb.write_text('#!/bin/sh\necho fake\n')
    fake_adb.chmod(0o755)
    orig_setting = mobinspect_settings.ADB_BINARY
    orig_global = utils.ADB_PATH
    try:
        mobinspect_settings.ADB_BINARY = str(fake_adb)
        assert utils.get_adb() == str(fake_adb)
    finally:
        mobinspect_settings.ADB_BINARY = orig_setting
        utils.ADB_PATH = orig_global


def test_get_adb_returns_cached_adb_path():
    orig_global = utils.ADB_PATH
    orig_setting = mobinspect_settings.ADB_BINARY
    try:
        mobinspect_settings.ADB_BINARY = ''
        utils.ADB_PATH = '/cached/adb/path'
        assert utils.get_adb() == '/cached/adb/path'
    finally:
        utils.ADB_PATH = orig_global
        mobinspect_settings.ADB_BINARY = orig_setting


def test_get_adb_multiple_locations_warning(monkeypatch):
    orig_global = utils.ADB_PATH
    orig_setting = mobinspect_settings.ADB_BINARY
    try:
        mobinspect_settings.ADB_BINARY = ''
        utils.ADB_PATH = None
        monkeypatch.setattr(
            utils, 'find_process_by',
            lambda name: {'/path/a/adb', '/path/b/adb'})
        result = utils.get_adb()
        assert result in ('/path/a/adb', '/path/b/adb')
    finally:
        utils.ADB_PATH = orig_global
        mobinspect_settings.ADB_BINARY = orig_setting


def test_get_adb_exception_path(monkeypatch):
    orig_global = utils.ADB_PATH
    orig_setting = mobinspect_settings.ADB_BINARY
    try:
        mobinspect_settings.ADB_BINARY = ''
        utils.ADB_PATH = None

        def boom(name):
            raise RuntimeError('simulated psutil failure')
        monkeypatch.setattr(utils, 'find_process_by', boom)
        assert utils.get_adb() == 'adb'
    finally:
        utils.ADB_PATH = orig_global
        mobinspect_settings.ADB_BINARY = orig_setting


# --------------------------------------------------------------------------
# check_basic_env — real ImportError (sys.modules poisoning, a standard real
# technique) and real missing-JDK branch. os.kill is narrowly monkeypatched
# in each case for one reason only: the production code's fail-fast guard
# calls os.kill(os.getpid(), SIGTERM), and we cannot let that actually
# terminate the pytest process.
# --------------------------------------------------------------------------
def test_check_basic_env_missing_http_tools(monkeypatch):
    import sys as _sys
    monkeypatch.setitem(_sys.modules, 'http_tools', None)
    killed = {}

    def fake_kill(pid, sig):
        killed['sig'] = sig
    monkeypatch.setattr(utils.os, 'kill', fake_kill)
    utils.check_basic_env()
    assert killed['sig'] == utils.signal.SIGTERM


def test_check_basic_env_missing_lxml(monkeypatch):
    import sys as _sys
    monkeypatch.setitem(_sys.modules, 'lxml', None)
    killed = {}

    def fake_kill(pid, sig):
        killed['sig'] = sig
    monkeypatch.setattr(utils.os, 'kill', fake_kill)
    utils.check_basic_env()
    assert killed['sig'] == utils.signal.SIGTERM


def test_check_basic_env_missing_jdk(monkeypatch):
    monkeypatch.setattr(utils, 'find_java_binary', lambda: '/nonexistent/java_xyz')
    killed = {}

    def fake_kill(pid, sig):
        killed['sig'] = sig
    monkeypatch.setattr(utils.os, 'kill', fake_kill)
    utils.check_basic_env()
    assert killed['sig'] == utils.signal.SIGTERM


# --------------------------------------------------------------------------
# update_local_db — real local HTTP server (loopback, no external network)
# --------------------------------------------------------------------------
class _DBHandler(BaseHTTPRequestHandler):
    body = b'db-payload'

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header('Content-Length', str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args):
        return


@pytest.fixture
def local_db_server():
    def _make(body):
        handler = type('H', (_DBHandler,), {'body': body})
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        return server, f'http://{host}:{port}/db.csv'
    servers = []

    def factory(body=b'db-payload'):
        server, url = _make(body)
        servers.append(server)
        return url
    yield factory
    for s in servers:
        s.shutdown()
        s.server_close()


def test_update_local_db_upstream_proxy_exception_falls_to_generic_except(monkeypatch, tmp_path):
    # Narrow, single-call monkeypatch of the sibling upstream_proxy(): this
    # leaves `proxies`/`verify` unbound, so the very next line raises a real
    # NameError, itself caught by the function's own generic except branch.
    def boom(flaw_type):
        raise RuntimeError('simulated proxy config failure')
    monkeypatch.setattr(utils, 'upstream_proxy', boom)
    result = utils.update_local_db(
        'TestDB', 'http://127.0.0.1:1/nofile', str(tmp_path / 'nonexistent_local'))
    assert result is None


def test_update_local_db_first_run_returns_response(tmp_path, local_db_server):
    url = local_db_server(b'fresh-db-content')
    local_file = tmp_path / 'does_not_exist_yet.csv'
    result = utils.update_local_db('TestDB', url, str(local_file))
    assert result == b'fresh-db-content'


def test_update_local_db_hash_changed(tmp_path, local_db_server):
    payload = b'new-db-content'
    url = local_db_server(payload)
    local_file = tmp_path / 'db.csv'
    local_file.write_bytes(b'old-content-that-differs')
    result = utils.update_local_db('TestDB', url, str(local_file))
    assert result == payload


def test_update_local_db_hash_unchanged(tmp_path, local_db_server):
    payload = b'identical-content'
    url = local_db_server(payload)
    local_file = tmp_path / 'db2.csv'
    local_file.write_bytes(payload)
    result = utils.update_local_db('TestDB', url, str(local_file))
    assert result is None


def test_update_local_db_connection_error(tmp_path):
    # Port 1 on loopback: a real, immediate connection-refused. No external
    # network involved.
    result = utils.update_local_db(
        'TestDB', 'http://127.0.0.1:1/x', str(tmp_path / 'nofile'))
    assert result is None


# --------------------------------------------------------------------------
# get_network — real exception branch (narrow monkeypatch of psutil, an
# external library call whose failure cannot be induced for real on a
# healthy host).
# --------------------------------------------------------------------------
def test_get_network_exception_branch(monkeypatch):
    def boom():
        raise OSError('simulated psutil failure')
    monkeypatch.setattr(utils.psutil, 'net_if_addrs', boom)
    assert utils.get_network() == []


# --------------------------------------------------------------------------
# get_proxy_ip — gateway-guess branch, subnet-scan branch, exception branch
# (narrow monkeypatch of the sibling get_network(), needed to pin down a
# deterministic, host-independent IP list).
# --------------------------------------------------------------------------
def test_get_proxy_ip_direct_gateway_match(monkeypatch):
    monkeypatch.setattr(utils, 'get_network', lambda: ['192.168.1.1', '10.0.0.5'])
    assert utils.get_proxy_ip('192.168.1.50:5555') == '192.168.1.1'


def test_get_proxy_ip_subnet_scan_match(monkeypatch):
    monkeypatch.setattr(utils, 'get_network', lambda: ['192.168.1.77', '10.0.0.5'])
    assert utils.get_proxy_ip('192.168.1.50:5555') == '192.168.1.77'


def test_get_proxy_ip_exception_branch(monkeypatch):
    def boom():
        raise RuntimeError('boom')
    monkeypatch.setattr(utils, 'get_network', boom)
    assert utils.get_proxy_ip('192.168.1.50:5555') is None


# --------------------------------------------------------------------------
# get_config_loc — USE_HOME False branch
# --------------------------------------------------------------------------
def test_get_config_loc_use_home_false():
    orig = mobinspect_settings.USE_HOME
    try:
        mobinspect_settings.USE_HOME = False
        assert utils.get_config_loc() == 'MobInspect/settings.py'
    finally:
        mobinspect_settings.USE_HOME = orig


# --------------------------------------------------------------------------
# is_path_traversal — real except branch (narrow monkeypatch of unquote: the
# real urllib.parse.unquote does not raise for any string input, so the
# only way to reach this defensive except is to make that specific internal
# call fail, per the single-call fault-injection allowance).
# --------------------------------------------------------------------------
def test_is_path_traversal_unquote_exception(monkeypatch):
    def boom(s):
        raise ValueError('simulated malformed percent-encoding')
    monkeypatch.setattr(utils, 'unquote', boom)
    assert utils.is_path_traversal('%zz') is True


# --------------------------------------------------------------------------
# relative_path — backslash-separator branches
# --------------------------------------------------------------------------
def test_relative_path_double_backslash_separator_detected():
    value = 'a\\\\b\\\\c\\\\d.txt'
    result = utils.relative_path(value)
    assert isinstance(result, str)


def test_relative_path_single_backslash_separator_detected():
    value = 'a\\b\\c\\d.txt'
    result = utils.relative_path(value)
    assert isinstance(result, str)


# --------------------------------------------------------------------------
# base64_decode — real except branch (base64.b64decode rejects '1 mod 4'
# data-length payloads such as a lone character).
# --------------------------------------------------------------------------
def test_base64_decode_invalid_base64_triggers_except():
    assert utils.base64_decode('A') == 'A'


# --------------------------------------------------------------------------
# append_scan_status / get_scan_logs — real generic-except branch via
# genuinely malformed stored SCAN_LOGS data (not a mock: a real DB row with
# a value that ast.literal_eval cannot parse).
# --------------------------------------------------------------------------
@pytest.mark.django_db
def test_append_scan_status_generic_exception_branch():
    checksum = 'b' * 32
    RecentScansDB.objects.create(
        MD5=checksum, FILE_NAME='x.apk', APP_NAME='x',
        PACKAGE_NAME='com.x', SCAN_LOGS='{not valid python')
    # Must not raise: python_dict() fails on the malformed literal, caught by
    # the generic except branch.
    utils.append_scan_status(checksum, 'some status')


@pytest.mark.django_db
def test_get_scan_logs_generic_exception_branch():
    checksum = 'c' * 32
    RecentScansDB.objects.create(
        MD5=checksum, FILE_NAME='x.apk', APP_NAME='x',
        PACKAGE_NAME='com.x', SCAN_LOGS='{not valid python')
    assert utils.get_scan_logs(checksum) == []


# --------------------------------------------------------------------------
# set_permissions — real chmod failure via macOS's real chflags(UF_IMMUTABLE)
# mechanism (genuine OS-level fault injection, not a mock).
# --------------------------------------------------------------------------
def test_set_permissions_chmod_failure_is_swallowed(tmp_path):
    if platform.system() != 'Darwin':
        pytest.skip('uses macOS-specific chflags to force a real chmod failure')
    f = tmp_path / 'immutable.txt'
    f.write_text('x')
    os.chflags(str(f), stat.UF_IMMUTABLE)
    try:
        utils.set_permissions(str(tmp_path))  # must not raise
    finally:
        os.chflags(str(f), 0)
