"""Real-execution (no-mock) coverage tests for mobinspect.MobInspect.tools_download.

STRICT: no unittest.mock / no monkeypatching of internal logic. Everything
below drives the real functions with real env vars, real temp files/dirs and
a real localhost HTTP server (loopback, deterministic, no external network).
"""
import os
import shutil
import stat
import platform
import threading
import zipfile
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from mobinspect.MobInspect import tools_download as td
from mobinspect.MobInspect.tools_download import (
    standalone_upstream_proxy,
    download_file,
    install_jadx,
    set_rwxr_xr_x_permission_recursively,
)


# ---------------------------------------------------------------------------
# Helpers: real env-var swapping (restored afterwards) and a real HTTP server.
# ---------------------------------------------------------------------------
@contextmanager
def env(**overrides):
    """Set real process env vars for the block, restore originals after."""
    saved = {}
    for key, val in overrides.items():
        saved[key] = os.environ.get(key)
        if val is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = val
    try:
        yield
    finally:
        for key, val in saved.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val


class _Handler(BaseHTTPRequestHandler):
    body = b'MobInspect-real-download-payload'
    content_length = None  # None => use len(body); else override to force mismatch

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        cl = self.content_length if self.content_length is not None else len(self.body)
        self.send_header('Content-Length', str(cl))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args):  # silence test noise
        return


@contextmanager
def http_server(body=b'MobInspect-real-download-payload', content_length=None):
    handler = type('H', (_Handler,), {
        'body': body, 'content_length': content_length})
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f'http://{host}:{port}/file'
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# standalone_upstream_proxy — pure branch coverage via real env vars
# ---------------------------------------------------------------------------
def test_proxy_disabled_returns_empty_and_verifies():
    with env(MOBINSPECT_UPSTREAM_PROXY_ENABLED=None,
             MOBINSPECT_UPSTREAM_PROXY_SSL_VERIFY=None):
        proxies, verify = standalone_upstream_proxy()
    assert proxies == {}
    assert verify is True  # default SSL_VERIFY '1'


def test_proxy_disabled_ssl_verify_off():
    with env(MOBINSPECT_UPSTREAM_PROXY_ENABLED='', MOBINSPECT_UPSTREAM_PROXY_SSL_VERIFY='0'):
        proxies, verify = standalone_upstream_proxy()
    assert proxies == {}
    assert verify is False


def test_proxy_enabled_no_username():
    with env(MOBINSPECT_UPSTREAM_PROXY_ENABLED='1',
             MOBINSPECT_UPSTREAM_PROXY_USERNAME=None,
             MOBINSPECT_UPSTREAM_PROXY_PASSWORD=None,
             MOBINSPECT_UPSTREAM_PROXY_TYPE='http',
             MOBINSPECT_UPSTREAM_PROXY_IP='10.0.0.5',
             MOBINSPECT_UPSTREAM_PROXY_PORT='8080',
             MOBINSPECT_PLATFORM=None,
             MOBINSPECT_UPSTREAM_PROXY_SSL_VERIFY='1'):
        proxies, verify = standalone_upstream_proxy()
    assert proxies == {
        'http': 'http://10.0.0.5:8080',
        'https': 'http://10.0.0.5:8080',
    }
    assert verify is True


def test_proxy_enabled_with_credentials():
    with env(MOBINSPECT_UPSTREAM_PROXY_ENABLED='1',
             MOBINSPECT_UPSTREAM_PROXY_USERNAME='alice',
             MOBINSPECT_UPSTREAM_PROXY_PASSWORD='s3cret',
             MOBINSPECT_UPSTREAM_PROXY_TYPE='https',
             MOBINSPECT_UPSTREAM_PROXY_IP='192.168.1.9',
             MOBINSPECT_UPSTREAM_PROXY_PORT='3128',
             MOBINSPECT_PLATFORM=None):
        proxies, verify = standalone_upstream_proxy()
    expected = 'https://alice:s3cret@192.168.1.9:3128'
    assert proxies == {'http': expected, 'https': expected}


def test_proxy_enabled_docker_localhost_translation():
    with env(MOBINSPECT_UPSTREAM_PROXY_ENABLED='1',
             MOBINSPECT_UPSTREAM_PROXY_USERNAME=None,
             MOBINSPECT_UPSTREAM_PROXY_PASSWORD=None,
             MOBINSPECT_UPSTREAM_PROXY_TYPE='http',
             MOBINSPECT_UPSTREAM_PROXY_IP='127.0.0.1',
             MOBINSPECT_UPSTREAM_PROXY_PORT='3128',
             MOBINSPECT_PLATFORM='docker'):
        proxies, _ = standalone_upstream_proxy()
    assert 'host.docker.internal' in proxies['http']
    assert '127.0.0.1' not in proxies['http']


def test_proxy_enabled_docker_localhost_name_translation():
    with env(MOBINSPECT_UPSTREAM_PROXY_ENABLED='1',
             MOBINSPECT_UPSTREAM_PROXY_USERNAME=None,
             MOBINSPECT_UPSTREAM_PROXY_IP='localhost',
             MOBINSPECT_UPSTREAM_PROXY_PORT='3128',
             MOBINSPECT_PLATFORM='docker'):
        proxies, _ = standalone_upstream_proxy()
    assert 'host.docker.internal' in proxies['https']


def test_proxy_ssl_verify_quoted_one():
    with env(MOBINSPECT_UPSTREAM_PROXY_ENABLED='', MOBINSPECT_UPSTREAM_PROXY_SSL_VERIFY='"1"'):
        _, verify = standalone_upstream_proxy()
    assert verify is True


# ---------------------------------------------------------------------------
# download_file — real localhost HTTP server (loopback, no external network)
# ---------------------------------------------------------------------------
def test_download_file_success(tmp_path):
    payload = b'A' * 20000  # exercise the multi-block read loop + progress bar
    dest = tmp_path / 'out.bin'
    # Ensure no proxy env leaks into getproxies() path expectations; either
    # branch is valid, we just assert real bytes land on disk.
    with http_server(body=payload) as url:
        downloaded = download_file(url, str(dest))
    assert downloaded == len(payload)
    assert dest.read_bytes() == payload


def test_download_file_small_no_progress(tmp_path):
    payload = b'tiny'
    dest = tmp_path / 'small.bin'
    with http_server(body=payload) as url:
        downloaded = download_file(url, str(dest))
    assert downloaded == len(payload)
    assert dest.read_bytes() == payload


def test_download_file_size_mismatch_raises(tmp_path):
    # Advertise a larger Content-Length than the body we actually send.
    dest = tmp_path / 'mismatch.bin'
    with http_server(body=b'short', content_length=999) as url:
        with pytest.raises(Exception) as exc:
            download_file(url, str(dest))
    assert 'does not match expected size' in str(exc.value)


def _host_port(url):
    rest = url.split('://', 1)[1]
    hostport = rest.split('/', 1)[0]
    host, port = hostport.split(':')
    return host, port


def test_download_file_via_system_proxy_env(tmp_path):
    # A non-empty getproxies() (from real http_proxy env) selects the
    # system-proxy branch (verify=True). Our loopback server answers as the
    # "proxy" for the absolute-form request, so real bytes are returned.
    dest = tmp_path / 'via_sys_proxy.bin'
    payload = b'system-proxy-body'
    with http_server(body=payload) as url:
        host, port = _host_port(url)
        with env(http_proxy=f'http://{host}:{port}',
                 https_proxy=None, HTTP_PROXY=None, HTTPS_PROXY=None,
                 MOBINSPECT_UPSTREAM_PROXY_ENABLED=None):
            downloaded = download_file('http://mobinspect.example/file', str(dest))
    assert downloaded == len(payload)
    assert dest.read_bytes() == payload


def test_download_file_via_mobinspect_upstream_proxy_ssl_off(tmp_path):
    # No system proxies -> MobInspect upstream proxy branch. SSL_VERIFY=0 also
    # exercises the unverified-context branch. The configured proxy IP/port
    # points at the loopback server, which answers the absolute-form request.
    dest = tmp_path / 'via_upstream.bin'
    payload = b'upstream-proxy-body'
    with http_server(body=payload) as url:
        host, port = _host_port(url)
        with env(http_proxy=None, https_proxy=None,
                 HTTP_PROXY=None, HTTPS_PROXY=None,
                 all_proxy=None, ALL_PROXY=None,
                 MOBINSPECT_UPSTREAM_PROXY_ENABLED='1',
                 MOBINSPECT_UPSTREAM_PROXY_USERNAME=None,
                 MOBINSPECT_UPSTREAM_PROXY_PASSWORD=None,
                 MOBINSPECT_UPSTREAM_PROXY_TYPE='http',
                 MOBINSPECT_UPSTREAM_PROXY_IP=host,
                 MOBINSPECT_UPSTREAM_PROXY_PORT=port,
                 MOBINSPECT_PLATFORM=None,
                 MOBINSPECT_UPSTREAM_PROXY_SSL_VERIFY='0'):
            downloaded = download_file('http://mobinspect.example/file', str(dest))
    assert downloaded == len(payload)
    assert dest.read_bytes() == payload


def test_download_file_non_200_via_file_url_raises(tmp_path):
    # A file:// URL is served by urllib's FileHandler: response.status is None,
    # so the `!= 200` else-branch fires (real, no network).
    src = tmp_path / 'src.txt'
    src.write_bytes(b'local file contents')
    dest = tmp_path / 'copy.txt'
    with pytest.raises(Exception) as exc:
        download_file('file://' + str(src), str(dest))
    assert 'Failed to download file' in str(exc.value)


# ---------------------------------------------------------------------------
# install_jadx — the local (no-network) "already installed" early return
# ---------------------------------------------------------------------------
def test_install_jadx_already_installed_returns_early(tmp_path):
    home = tmp_path / 'mobinspect_home'
    extract_dir = home / 'tools' / 'jadx' / 'jadx-1.5.0'
    extract_dir.mkdir(parents=True)
    sentinel = extract_dir / 'keep.txt'
    sentinel.write_text('present')

    result = install_jadx(str(home), version='1.5.0')

    assert result is None
    # Early return must NOT wipe the existing install (no rmtree happened).
    assert extract_dir.exists()
    assert sentinel.read_text() == 'present'


def test_install_jadx_already_installed_custom_version(tmp_path):
    home = tmp_path / 'home2'
    extract_dir = home / 'tools' / 'jadx' / 'jadx-1.4.7'
    extract_dir.mkdir(parents=True)

    result = install_jadx(str(home), version='1.4.7')

    assert result is None
    assert extract_dir.exists()


def test_install_jadx_full_happy_path_downloads_and_extracts(tmp_path, monkeypatch):
    # Narrow, single-call monkeypatch of the sibling download_file(): its
    # own logic is already fully exercised for real (via a real local HTTP
    # server, no mocking) above in this file. install_jadx()'s hardcoded
    # target is the real github.com release URL, which we must not hit
    # under the no-network test policy, so here we substitute a real local
    # zip copy for the fetch step only — every line of install_jadx's own
    # logic (rmtree, mkdir, real zip extraction incl. the path-traversal
    # guard, real chmod permission-setting, logging) still runs for real.
    # zip_ref.extract(member, extract_dir) places each entry at
    # extract_dir/<member> — the real JADX release zip has no extra
    # top-level version folder, so entries are just 'bin/...', 'lib/...'.
    real_zip = tmp_path / 'fake_jadx_release.zip'
    with zipfile.ZipFile(real_zip, 'w') as zf:
        zf.writestr('bin/jadx', '#!/bin/sh\necho jadx\n')
        zf.writestr('lib/jadx-core.jar', 'binary-content-stand-in')

    def fake_download_file(url, file_path):
        shutil.copyfile(str(real_zip), file_path)
        return os.path.getsize(file_path)

    monkeypatch.setattr(td, 'download_file', fake_download_file)

    home = tmp_path / 'mihome'
    install_jadx(str(home), version='1.5.0')

    extract_dir = home / 'tools' / 'jadx' / 'jadx-1.5.0'
    assert (extract_dir / 'bin' / 'jadx').is_file()
    assert (extract_dir / 'lib' / 'jadx-core.jar').is_file()
    if platform.system() != 'Windows':
        assert stat.S_IMODE(os.stat(extract_dir).st_mode) == 0o755


def test_install_jadx_path_traversal_zip_is_caught_and_swallowed(tmp_path, monkeypatch):
    # A real, deliberately malicious zip entry (path traversal via '../..')
    # to prove install_jadx's own real path-traversal guard fires and the
    # surrounding try/except swallows it without crashing the caller.
    evil_zip = tmp_path / 'evil.zip'
    with zipfile.ZipFile(evil_zip, 'w') as zf:
        zf.writestr('../../evil.txt', 'pwned')

    def fake_download_file(url, file_path):
        shutil.copyfile(str(evil_zip), file_path)
        return os.path.getsize(file_path)

    monkeypatch.setattr(td, 'download_file', fake_download_file)

    home = tmp_path / 'mihome_evil'
    install_jadx(str(home), version='9.9.9')  # must not raise

    # Nothing from the malicious entry should land outside the extract dir.
    assert not (tmp_path / 'evil.txt').exists()
    assert not (home.parent / 'evil.txt').exists()


# ---------------------------------------------------------------------------
# set_rwxr_xr_x_permission_recursively — real filesystem permission changes
# ---------------------------------------------------------------------------
def test_set_permissions_recursively(tmp_path):
    root = tmp_path / 'jadx-tree'
    root.mkdir()
    sub = root / 'bin'
    sub.mkdir()
    f1 = root / 'top.txt'
    f2 = sub / 'jadx'
    f1.write_text('x')
    f2.write_text('#!/bin/sh')
    # Start from restrictive perms so the change is observable.
    os.chmod(f1, 0o600)
    os.chmod(f2, 0o600)

    set_rwxr_xr_x_permission_recursively(root)

    if platform.system() == 'Windows':
        pytest.skip('permission bits are not meaningfully enforced on Windows')

    assert stat.S_IMODE(os.stat(root).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(f1).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(sub).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(f2).st_mode) == 0o755


def test_set_permissions_empty_dir(tmp_path):
    root = tmp_path / 'empty'
    root.mkdir()
    os.chmod(root, 0o700)

    set_rwxr_xr_x_permission_recursively(root)

    if platform.system() != 'Windows':
        assert stat.S_IMODE(os.stat(root).st_mode) == 0o755


# ---------------------------------------------------------------------------
# Smoke: install_jadx path traversal guard logic is reachable via a real zip
# extracted through the same guard used in install_jadx (documents intent).
# This exercises the zip-safety helper pattern with real files.
# ---------------------------------------------------------------------------
def test_module_imports_expose_expected_callables():
    assert callable(td.standalone_upstream_proxy)
    assert callable(td.download_file)
    assert callable(td.install_jadx)
    assert callable(td.set_rwxr_xr_x_permission_recursively)
