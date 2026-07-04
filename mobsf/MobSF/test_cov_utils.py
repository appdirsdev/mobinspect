"""Real-execution unit tests for mobsf.MobSF.utils.

STRICT: no mocks. Every test drives real code with real inputs, real files
from the repo-root test_files/ directory, real temp files, real environment
variables, and real Django ORM/RequestFactory infrastructure.
"""
import io
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from django.test import RequestFactory

from mobsf.MobSF import utils
from mobsf.MobSF import settings as mobsf_settings
from mobsf.StaticAnalyzer.models import RecentScansDB


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
    assert loc.endswith('config.py') or loc == 'MobSF/settings.py'


def test_settings_enabled():
    # A real disabled-ish attr and an enabled one on the real settings object.
    setattr(mobsf_settings, '_TEST_ENABLED_ATTR', 'yes')
    setattr(mobsf_settings, '_TEST_DISABLED_ATTR', '0')
    try:
        assert utils.settings_enabled('_TEST_ENABLED_ATTR') is True
        assert utils.settings_enabled('_TEST_DISABLED_ATTR') is False
        assert utils.settings_enabled('_NONEXISTENT_ATTR_XYZ') is False
    finally:
        delattr(mobsf_settings, '_TEST_ENABLED_ATTR')
        delattr(mobsf_settings, '_TEST_DISABLED_ATTR')


def test_parse_host_port():
    assert utils.parse_host_port('127.0.0.1:5555') == ('127.0.0.1', 5555)
    assert utils.parse_host_port('[::1]:8080') == ('::1', 8080)
    with pytest.raises(ValueError):
        utils.parse_host_port('no-port-here')


def test_common_check_branches():
    orig = getattr(mobsf_settings, 'CORELLIUM_API_KEY', '')
    try:
        mobsf_settings.CORELLIUM_API_KEY = ''
        res = utils.common_check('anything')
        assert res['message'] == 'Missing Corellium API key'

        mobsf_settings.CORELLIUM_API_KEY = 'realkey'
        res = utils.common_check('bad-instance')
        assert res['message'] == 'Invalid instance identifier'

        res = utils.common_check('12345678-1234-1234-1234-123456789abc')
        assert res is None
    finally:
        mobsf_settings.CORELLIUM_API_KEY = orig


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
    old = os.environ.pop('MOBSF_PLATFORM', None)
    try:
        assert utils.docker_translate_localhost('localhost:5555') == \
            'localhost:5555'
        assert utils.docker_translate_localhost('') == ''
    finally:
        if old is not None:
            os.environ['MOBSF_PLATFORM'] = old


def test_docker_translate_localhost_docker():
    old = os.environ.get('MOBSF_PLATFORM')
    os.environ['MOBSF_PLATFORM'] = 'docker'
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
            os.environ.pop('MOBSF_PLATFORM', None)
        else:
            os.environ['MOBSF_PLATFORM'] = old


def test_docker_translate_proxy_ip():
    old = os.environ.get('MOBSF_PLATFORM')
    # non-docker -> identity
    os.environ.pop('MOBSF_PLATFORM', None)
    try:
        assert utils.docker_translate_proxy_ip('127.0.0.1') == '127.0.0.1'
        os.environ['MOBSF_PLATFORM'] = 'docker'
        assert utils.docker_translate_proxy_ip('127.0.0.1') == \
            'host.docker.internal'
        assert utils.docker_translate_proxy_ip('localhost') == \
            'host.docker.internal'
        assert utils.docker_translate_proxy_ip('10.0.0.5') == '10.0.0.5'
    finally:
        if old is None:
            os.environ.pop('MOBSF_PLATFORM', None)
        else:
            os.environ['MOBSF_PLATFORM'] = old


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
    old_platform = os.environ.pop('MOBSF_PLATFORM', None)
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
            os.environ['MOBSF_PLATFORM'] = old_platform


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
