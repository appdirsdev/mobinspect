"""End-to-end verification of the four Integrations connectors across a
matrix of hosts / IPs / ports.

Covers, for BOTH the AI model boxes (generation + classification) and the
device boxes (Android adb + iOS):

  1. Pure validation — which host:port / endpoint values are accepted vs
     rejected (IPv4, IPv6, hostnames, bad ports, injection charsets).
  2. The enclave gate — loopback / RFC-1918 private allowed, public and
     link-local rejected, for model endpoints.
  3. Real connectivity — a mock Ollama /api/tags server bound to BOTH
     127.0.0.1 and this host's private LAN IP, proving a probe to a
     *different* IP genuinely connects and lists models.
  4. Graceful failure — unreachable / refused endpoints return a status,
     never crash.
  5. Full view flow — POST device_save/device_test + model_save/model_test
     as an authorised user, asserting DB persistence + JSON, on the test DB.

adb device "CONNECTED" needs a live emulator, which is environment-gated;
those cases assert the code path runs and returns a valid status rather
than asserting a specific device is present.
"""
import contextlib
import http.server
import ipaddress
import json
import socket
import threading

import pytest
from django.urls import reverse

from mobsf.RBAC.models import AdbConnection, ModelIntegration
from mobsf.RBAC.views import (
    _probe_model_endpoint,
    _run_adb,
    _validate_host_port,
)
from mobsf.StaticAnalyzer.views.common.llm.client import (
    _host_is_enclave,
    parse_ai_endpoint,
)


# ───────────────────────────── mock Ollama endpoint ─────────────────────────
class _TagsHandler(http.server.BaseHTTPRequestHandler):
    MODELS = ['granite4:3b', 'nomic-embed-text']

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        if self.path == '/api/tags':
            body = json.dumps(
                {'models': [{'name': m} for m in self.MODELS]}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


@contextlib.contextmanager
def mock_ollama(bind='127.0.0.1'):
    srv = http.server.ThreadingHTTPServer((bind, 0), _TagsHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield bind, srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _candidate_private_ips():
    """All private, non-loopback, non-link-local IPv4s bound to this host.

    Probes several route targets so we discover every interface (real LAN,
    VPN/utun, etc.) — not just the default route, which on a VPN host is
    often an interface that can't self-connect.
    """
    ips = set()
    for target in ('8.8.8.8', '192.168.1.1', '10.255.255.255',
                   '172.16.0.1', '172.31.255.255'):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target, 1))
            ip = s.getsockname()[0]
            s.close()
            a = ipaddress.ip_address(ip)
            if a.is_private and not a.is_loopback and not a.is_link_local:
                ips.add(ip)
        except Exception:
            pass
    return sorted(ips)


def _closed_loopback_port():
    """A loopback port with nothing listening (fast connection-refused)."""
    s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
    return port


@pytest.fixture
def su_client(client, superuser):
    """Superuser client — bypasses require_permission('settings.manage')."""
    client.force_login(superuser)
    return client


@pytest.fixture
def reachable_lan_ip():
    """This host's private LAN IPv4, but only if it can self-connect to it.

    macOS' application firewall / VPN interfaces commonly block self-connects
    to some interface IPs; try each candidate and return the first the host
    can actually reach. Skip only if none work — the enclave unit tests
    already prove private IPs are policy-accepted, this fixture gates the
    *live* different-IP probe.
    """
    candidates = _candidate_private_ips()
    if not candidates:
        pytest.skip('no private LAN IPv4 on this host')
    for ip in candidates:
        try:
            srv = http.server.ThreadingHTTPServer((ip, 0), _TagsHandler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                socket.create_connection(
                    (ip, srv.server_address[1]), timeout=1.5).close()
                return ip
            finally:
                srv.shutdown(); srv.server_close()
        except Exception:
            continue
    pytest.skip(f'host cannot self-connect to any of {candidates} (firewall?)')


# ══════════════════════════ 1 · device host:port validation ═════════════════
@pytest.mark.parametrize('value', [
    '127.0.0.1:5555',        # ipv4 loopback
    '192.168.1.100:5555',    # ipv4 private LAN
    '10.0.0.5:5037',         # ipv4 private
    '172.16.0.9:5555',       # ipv4 private
    '8.8.8.8:5555',          # public ipv4 — devices are NOT enclave-gated
    'host.local:22',         # hostname
    'emulator-host:5554',    # hostname with dash
    '[::1]:5555',            # ipv6 loopback
    '[fe80::1]:5555',        # ipv6 link-local (charset ok)
    '[2001:db8::1]:5555',    # ipv6 global (charset ok)
])
def test_device_host_port_accepts(value):
    assert _validate_host_port(value) == value


@pytest.mark.parametrize('value', [
    '',                      # empty
    'nocolon',               # missing :port
    '127.0.0.1',             # missing port
    '127.0.0.1:0',           # port below range
    '127.0.0.1:65536',       # port above range
    '127.0.0.1:99999',       # port way out of range
    '127.0.0.1:-5',          # negative
    '127.0.0.1:abc',         # non-numeric port
    'ho st:22',              # space in host
    'host;rm -rf /:22',      # shell metacharacters
    'a' * 260 + ':22',       # over 255 chars
])
def test_device_host_port_rejects(value):
    assert _validate_host_port(value) is None


# ══════════════════════════ 2 · model endpoint parsing ══════════════════════
@pytest.mark.parametrize('url', [
    'http://127.0.0.1:11434',
    'https://192.168.1.5:443',
    'http://localhost:11434',
    'http://10.0.0.9:8080',
    'http://[::1]:11434',
])
def test_model_endpoint_parses(url):
    assert parse_ai_endpoint(url) is not None


@pytest.mark.parametrize('url', [
    '',
    'justtext',
    'ftp://127.0.0.1:11434',   # wrong scheme
    'http://127.0.0.1',        # no port
    'http://127.0.0.1:abc',    # bad port
    'http://127.0.0.1:99999',  # port out of range
    '://127.0.0.1:1',          # no scheme
])
def test_model_endpoint_parse_rejects(url):
    assert parse_ai_endpoint(url) is None


# ══════════════════════════ 3 · enclave gate ════════════════════════════════
@pytest.mark.parametrize('host', [
    '127.0.0.1', 'localhost', '192.168.1.1', '10.0.0.1',
    '172.16.0.1', '172.31.255.254', '::1',
])
def test_enclave_allows_private_and_loopback(host):
    assert _host_is_enclave(host) is True


@pytest.mark.parametrize('host', [
    '8.8.8.8', '1.1.1.1',            # public
    '169.254.10.10',                 # link-local
    '172.32.0.1',                    # just outside RFC-1918 172.16/12
    'example.com',                   # public hostname
])
def test_enclave_rejects_public_and_linklocal(host):
    assert _host_is_enclave(host) is False


# ══════════════════════════ 4 · real probe · loopback ═══════════════════════
def test_probe_connects_over_loopback():
    with mock_ollama('127.0.0.1') as (host, port):
        status, msg, models = _probe_model_endpoint(f'http://{host}:{port}')
    assert status == ModelIntegration.STATUS_CONNECTED, msg
    assert 'granite4:3b' in models and 'nomic-embed-text' in models


# ══════════════════════════ 4b · real probe · different (LAN) IP ════════════
def test_probe_connects_over_private_lan_ip(reachable_lan_ip):
    with mock_ollama(reachable_lan_ip) as (host, port):
        status, msg, models = _probe_model_endpoint(f'http://{host}:{port}')
    assert status == ModelIntegration.STATUS_CONNECTED, msg
    assert 'granite4:3b' in models


def test_probe_connects_over_alternate_loopback_ip():
    # 127.0.0.2 is a *different* address from 127.0.0.1 yet still loopback —
    # proves the probe binds/dials an arbitrary IP. macOS aliases only
    # 127.0.0.1 by default, so skip if the alt-loopback can't be bound.
    try:
        cm = mock_ollama('127.0.0.2')
        host_port = cm.__enter__()
    except OSError:
        pytest.skip('127.0.0.2 not bindable on this host (no loopback alias)')
    try:
        host, port = host_port
        status, msg, models = _probe_model_endpoint(f'http://{host}:{port}')
        assert status == ModelIntegration.STATUS_CONNECTED, msg
        assert 'granite4:3b' in models
    finally:
        cm.__exit__(None, None, None)


def test_probe_refused_endpoint_fails_gracefully():
    port = _closed_loopback_port()
    status, msg, models = _probe_model_endpoint(f'http://127.0.0.1:{port}')
    assert status == ModelIntegration.STATUS_FAILED
    assert models == []


def test_probe_public_host_blocked_before_network():
    # 8.8.8.8:11434 is not enclave — must be refused by policy, not dialed.
    status, msg, models = _probe_model_endpoint('http://8.8.8.8:11434')
    assert status == ModelIntegration.STATUS_FAILED
    assert 'enclave' in msg.lower() or 'loopback' in msg.lower()


# ══════════════════════════ 5 · full view flow · models ═════════════════════
@pytest.mark.django_db
def test_model_save_and_test_over_loopback(su_client):
    with mock_ollama('127.0.0.1') as (host, port):
        url = f'http://{host}:{port}'
        r = su_client.post(
            reverse('rbac:model_save', args=['generate']),
            {'base_url': url, 'model_name': 'granite4:3b'})
        assert r.status_code in (302, 200)
        integ = ModelIntegration.objects.get(role='generate')
        assert integ.base_url == url
        assert integ.last_status == ModelIntegration.STATUS_CONNECTED
        assert 'granite4:3b' in integ.detected_models

        r2 = su_client.post(reverse('rbac:model_test', args=['generate']))
        data = r2.json()
        assert data['success'] is True
        assert 'granite4:3b' in data['models_list']


@pytest.mark.django_db
def test_model_save_over_private_lan_ip(su_client, reachable_lan_ip):
    with mock_ollama(reachable_lan_ip) as (host, port):
        url = f'http://{host}:{port}'
        su_client.post(
            reverse('rbac:model_save', args=['classify']),
            {'base_url': url, 'model_name': 'granite4.1:3b'})
    integ = ModelIntegration.objects.get(role='classify')
    assert integ.base_url == url
    assert integ.last_status == ModelIntegration.STATUS_CONNECTED


@pytest.mark.django_db
def test_model_save_public_host_rejected(su_client):
    su_client.post(
        reverse('rbac:model_save', args=['generate']),
        {'base_url': 'http://8.8.8.8:11434', 'model_name': 'granite4:3b'})
    # Public host must never be persisted as a working integration.
    assert not ModelIntegration.objects.filter(
        base_url='http://8.8.8.8:11434').exists()


# ══════════════════════════ 5b · full view flow · devices ═══════════════════
@pytest.mark.django_db
def test_device_save_persists_and_probes(su_client):
    # 127.0.0.1:<closed> → adb connect runs and fails fast (no emulator).
    port = _closed_loopback_port()
    addr = f'127.0.0.1:{port}'
    r = su_client.post(
        reverse('rbac:device_save', args=['android']), {'host_port': addr})
    assert r.status_code in (302, 200)
    conn = AdbConnection.objects.get(platform='android')
    assert conn.host_port == addr
    # A real status was recorded (connected only if a device answered).
    assert conn.last_status in {
        AdbConnection.STATUS_CONNECTED,
        AdbConnection.STATUS_FAILED,
        AdbConnection.STATUS_TIMEOUT,
    }


@pytest.mark.django_db
def test_device_save_rejects_bad_host_port(su_client):
    su_client.post(
        reverse('rbac:device_save', args=['android']),
        {'host_port': 'not a host'})
    assert not AdbConnection.objects.filter(platform='android').exists()


@pytest.mark.django_db
def test_device_save_accepts_different_private_ip(su_client):
    addr = '192.168.1.4:5555'
    su_client.post(
        reverse('rbac:device_save', args=['ios']), {'host_port': addr})
    conn = AdbConnection.objects.get(platform='ios')
    assert conn.host_port == addr  # accepted + stored regardless of reachability


def test_run_adb_unreachable_is_graceful():
    port = _closed_loopback_port()
    status, message = _run_adb(['connect', f'127.0.0.1:{port}'])
    assert status in {AdbConnection.STATUS_FAILED, AdbConnection.STATUS_TIMEOUT}
    assert isinstance(message, str) and message


# ═══════════ 6 · "Test" button probes the TYPED value, not the stale saved one
# Regression for: Test showed CONNECTED (old saved endpoint) while Save & Test
# showed FAILED (newly-typed endpoint). Test must probe what's in the field.
@pytest.mark.django_db
def test_model_test_uses_posted_value_not_saved(su_client):
    with mock_ollama('127.0.0.1') as (host, port):
        good = f'http://{host}:{port}'
        su_client.post(reverse('rbac:model_save', args=['generate']),
                       {'base_url': good, 'model_name': 'granite4:3b'})
        assert ModelIntegration.objects.get(role='generate').last_status == \
            ModelIntegration.STATUS_CONNECTED
        # Test a DIFFERENT, dead endpoint via the form field.
        dead = f'http://127.0.0.1:{_closed_loopback_port()}'
        data = su_client.post(reverse('rbac:model_test', args=['generate']),
                              {'base_url': dead, 'model_name': 'granite4:3b'}).json()
    # Reflects the POSTED (dead) value, not the saved (good) one …
    assert data['success'] is False
    assert data['status'] == ModelIntegration.STATUS_FAILED
    # … and does NOT overwrite the saved row (only Save writes it).
    row = ModelIntegration.objects.get(role='generate')
    assert row.last_status == ModelIntegration.STATUS_CONNECTED
    assert row.base_url == good


@pytest.mark.django_db
def test_model_test_and_save_agree_on_same_value(su_client):
    with mock_ollama('127.0.0.1') as (host, port):
        url = f'http://{host}:{port}'
        tested = su_client.post(reverse('rbac:model_test', args=['classify']),
                                {'base_url': url, 'model_name': 'granite4:3b'}).json()
        su_client.post(reverse('rbac:model_save', args=['classify']),
                       {'base_url': url, 'model_name': 'granite4:3b'})
        saved = ModelIntegration.objects.get(role='classify')
    assert tested['success'] is True and tested['status'] == 'connected'
    assert saved.last_status == ModelIntegration.STATUS_CONNECTED  # they agree


@pytest.mark.django_db
def test_model_test_posted_public_host_rejected(su_client):
    data = su_client.post(
        reverse('rbac:model_test', args=['generate']),
        {'base_url': 'http://8.8.8.8:11434', 'model_name': 'granite4:3b'}).json()
    assert data['success'] is False
    assert 'enclave' in data['message'].lower() or 'loopback' in data['message'].lower()


# ── parity closers surfaced by the adversarial review ───────────────────────
@pytest.mark.django_db
def test_model_test_empty_model_name_matches_save(su_client):
    # Valid, reachable endpoint but NO model name: Save rejects it, so Test must
    # too (previously Test showed CONNECTED here — a Test/Save disagreement).
    with mock_ollama('127.0.0.1') as (host, port):
        url = f'http://{host}:{port}'
        no_model = su_client.post(reverse('rbac:model_test', args=['generate']),
                                  {'base_url': url, 'model_name': ''}).json()
        with_model = su_client.post(reverse('rbac:model_test', args=['generate']),
                                    {'base_url': url, 'model_name': 'granite4:3b'}).json()
    assert no_model['success'] is False and no_model['status'] == 'failed'
    assert with_model['success'] is True and with_model['status'] == 'connected'


@pytest.mark.django_db
def test_device_test_does_not_overwrite_saved_row(su_client):
    # Save a device (gives it a persisted status), then Test a DIFFERENT typed
    # address — the saved row's status/timestamp must be untouched.
    su_client.post(reverse('rbac:device_save', args=['android']),
                   {'host_port': '127.0.0.1:5555'})
    saved = AdbConnection.objects.get(platform='android')
    before_status, before_at = saved.last_status, saved.last_status_at
    su_client.post(reverse('rbac:device_test', args=['android']),
                   {'host_port': f'127.0.0.1:{_closed_loopback_port()}'})
    saved.refresh_from_db()
    assert saved.host_port == '127.0.0.1:5555'
    assert saved.last_status == before_status
    assert saved.last_status_at == before_at


@pytest.mark.django_db
def test_device_test_duplicate_host_rejected(su_client):
    # Same address on both device cards: Save rejects as duplicate, so Test must.
    su_client.post(reverse('rbac:device_save', args=['android']),
                   {'host_port': '10.0.0.9:5555'})
    data = su_client.post(reverse('rbac:device_test', args=['ios']),
                          {'host_port': '10.0.0.9:5555'}).json()
    assert data['success'] is False and data['status'] == 'failed'
    assert 'already used' in data['message'].lower()


@pytest.mark.django_db
def test_test_endpoints_whitespace_field_falls_back(su_client):
    # A whitespace-only field (the .strip() boundary) must behave like empty:
    # fall back to the saved row / "not configured", never crash.
    dev = su_client.post(reverse('rbac:device_test', args=['ios']),
                         {'host_port': '   '}).json()
    mod = su_client.post(reverse('rbac:model_test', args=['classify']),
                         {'base_url': '   ', 'model_name': '   '}).json()
    assert dev['status'] == 'unknown'   # nothing saved for ios
    assert mod['status'] == 'unknown'   # nothing saved for classify


@pytest.mark.django_db
def test_device_test_uses_posted_value_and_validates(su_client):
    bad = su_client.post(reverse('rbac:device_test', args=['android']),
                         {'host_port': 'not a host'}).json()
    assert bad['success'] is False and bad['status'] == 'failed'
    port = _closed_loopback_port()
    good_fmt = su_client.post(reverse('rbac:device_test', args=['android']),
                              {'host_port': f'127.0.0.1:{port}'}).json()
    assert good_fmt['status'] in {'failed', 'timeout'}  # valid format, unreachable


@pytest.mark.django_db
def test_device_test_empty_field_falls_back_to_saved(su_client):
    # Empty field + nothing saved → "not configured", not a crash.
    data = su_client.post(reverse('rbac:device_test', args=['ios']), {}).json()
    assert data['status'] == 'unknown'
