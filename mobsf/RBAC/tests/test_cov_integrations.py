"""
Coverage tests for the NEW integration views in mobsf/RBAC/views.py:

  * device_save(platform)      — upsert-and-test the single Android/iOS box
  * model_save(role)           — upsert-and-test the single AI model box
  * device_test_key(platform)  — AJAX re-test of the configured device
  * model_test_key(role)       — AJAX re-test of the configured AI model
  * adb_connections_list       — renders the four fixed integration cards
  * _probe_model_endpoint / _apply_model_probe — the AI-probe helpers these
    views depend on

Every external boundary is mocked — no real adb binary, no real subprocess,
no real network/model. ``_run_adb`` and ``_probe_model_endpoint`` (or the
``requests`` module they wrap) are monkeypatched so these tests are fast,
deterministic, and fully offline, per the security-critical nature of these
endpoints (SSRF guard on model hosts, command-injection guard on adb argv).

Fixture / auth style mirrors mobsf/RBAC/test_cov_views.py: a locally-defined
superuser fixture force_login'd via a `su_client`, plus a permission-less
`plain_user` to exercise the `settings.manage` / `settings.view` guards.
"""
from unittest.mock import MagicMock

import pytest

from django.test import override_settings
from django.urls import reverse

from mobsf.RBAC import views
from mobsf.RBAC.models import AdbConnection, AuditEvent, ModelIntegration


# ───────────────────────────────────────────── helpers / fixtures
@pytest.fixture
def superuser(db, django_user_model):
    return django_user_model.objects.create_user(
        username='cov_int_root', password='pw', is_staff=True, is_superuser=True,
    )


@pytest.fixture
def plain_user(db, django_user_model):
    """A logged-in user holding NO RBAC permissions at all."""
    return django_user_model.objects.create_user(
        username='cov_int_plain', password='pw',
    )


@pytest.fixture
def su_client(client, superuser):
    client.force_login(superuser)
    return client


# A loopback address — resolves locally (no DNS/network) and passes
# `_host_is_enclave`.
LOOPBACK_URL = 'http://127.0.0.1:11434'
# A well-known public IP literal — resolves purely by parsing (no DNS/
# network call), and correctly fails the enclave/private-address check.
PUBLIC_URL = 'http://8.8.8.8:11434'


# ═══════════════════════════════════════════════════════ device_save
@pytest.mark.django_db
def test_device_save_invalid_platform_redirects(su_client):
    resp = su_client.post(
        reverse('rbac:device_save', args=['windows']),
        {'host_port': '127.0.0.1:5555'},
    )
    assert resp.status_code == 302
    assert not AdbConnection.objects.exists()


@pytest.mark.django_db
def test_device_save_invalid_host_port_rejected(su_client):
    resp = su_client.post(
        reverse('rbac:device_save', args=['android']),
        {'host_port': 'garbage$(rm -rf /)'},
        follow=True,
    )
    assert resp.status_code == 200
    assert not AdbConnection.objects.exists()
    assert b'Invalid device address' in resp.content


@pytest.mark.django_db
def test_device_save_host_port_collision_rejected(su_client, superuser):
    AdbConnection.objects.create(
        label='iOS device', host_port='127.0.0.1:6000',
        platform=AdbConnection.PLATFORM_IOS, created_by=superuser,
    )
    resp = su_client.post(
        reverse('rbac:device_save', args=['android']),
        {'host_port': '127.0.0.1:6000'},
        follow=True,
    )
    assert resp.status_code == 200
    assert not AdbConnection.objects.filter(
        platform=AdbConnection.PLATFORM_ANDROID).exists()
    assert b'already used by another device' in resp.content


@pytest.mark.django_db
def test_device_save_android_happy_path(su_client, monkeypatch):
    mock_run = MagicMock(return_value=(AdbConnection.STATUS_CONNECTED, 'connected to device'))
    monkeypatch.setattr(views, '_run_adb', mock_run)

    resp = su_client.post(
        reverse('rbac:device_save', args=['android']),
        {'host_port': '127.0.0.1:5555'},
    )
    assert resp.status_code == 302
    conn = AdbConnection.objects.get(platform=AdbConnection.PLATFORM_ANDROID)
    assert conn.host_port == '127.0.0.1:5555'
    assert conn.label == 'Android device'
    assert conn.is_active is True
    assert conn.last_status == AdbConnection.STATUS_CONNECTED
    assert conn.last_status_message == 'connected to device'
    assert conn.last_status_at is not None
    mock_run.assert_called_once_with(['connect', '127.0.0.1:5555'])
    ev = AuditEvent.objects.filter(action='integration.adb.save').first()
    assert ev is not None
    assert ev.metadata['platform'] == 'android'
    assert ev.metadata['host_port'] == '127.0.0.1:5555'


@pytest.mark.django_db
def test_device_save_ios_happy_path(su_client, monkeypatch):
    monkeypatch.setattr(
        views, '_run_adb',
        MagicMock(return_value=(AdbConnection.STATUS_FAILED, 'unable to connect')))
    resp = su_client.post(
        reverse('rbac:device_save', args=['ios']),
        {'host_port': '192.168.1.50:22'},
    )
    assert resp.status_code == 302
    conn = AdbConnection.objects.get(platform=AdbConnection.PLATFORM_IOS)
    assert conn.label == 'iOS device'
    assert conn.last_status == AdbConnection.STATUS_FAILED


@pytest.mark.django_db
def test_device_save_android_and_ios_coexist(su_client, monkeypatch):
    monkeypatch.setattr(
        views, '_run_adb',
        MagicMock(return_value=(AdbConnection.STATUS_CONNECTED, 'ok')))
    su_client.post(reverse('rbac:device_save', args=['android']),
                    {'host_port': '10.0.0.1:5555'})
    su_client.post(reverse('rbac:device_save', args=['ios']),
                    {'host_port': '10.0.0.2:22'})
    assert AdbConnection.objects.count() == 2
    android = AdbConnection.objects.get(platform=AdbConnection.PLATFORM_ANDROID)
    ios = AdbConnection.objects.get(platform=AdbConnection.PLATFORM_IOS)
    assert android.host_port == '10.0.0.1:5555'
    assert ios.host_port == '10.0.0.2:22'
    assert android.pk != ios.pk


@pytest.mark.django_db
def test_device_save_upsert_updates_existing_row(su_client, monkeypatch):
    """One row per platform: re-saving updates in place, never duplicates."""
    monkeypatch.setattr(
        views, '_run_adb',
        MagicMock(return_value=(AdbConnection.STATUS_CONNECTED, 'ok')))
    su_client.post(reverse('rbac:device_save', args=['android']),
                    {'host_port': '10.0.0.1:5555'})
    first = AdbConnection.objects.get(platform=AdbConnection.PLATFORM_ANDROID)

    su_client.post(reverse('rbac:device_save', args=['android']),
                    {'host_port': '10.0.0.9:5555'})
    assert AdbConnection.objects.filter(
        platform=AdbConnection.PLATFORM_ANDROID).count() == 1
    second = AdbConnection.objects.get(platform=AdbConnection.PLATFORM_ANDROID)
    assert second.pk == first.pk
    assert second.host_port == '10.0.0.9:5555'


@pytest.mark.django_db
def test_device_save_resave_same_host_port_not_self_collision(su_client, monkeypatch):
    """Excluding the row's own pk means re-saving the same host:port is fine."""
    monkeypatch.setattr(
        views, '_run_adb',
        MagicMock(return_value=(AdbConnection.STATUS_CONNECTED, 'ok')))
    su_client.post(reverse('rbac:device_save', args=['android']),
                    {'host_port': '10.0.0.1:5555'})
    resp = su_client.post(reverse('rbac:device_save', args=['android']),
                           {'host_port': '10.0.0.1:5555'})
    assert resp.status_code == 302
    assert AdbConnection.objects.filter(
        platform=AdbConnection.PLATFORM_ANDROID).count() == 1


@pytest.mark.django_db
def test_device_save_denied_for_plain_user(client, plain_user):
    client.force_login(plain_user)
    resp = client.post(
        reverse('rbac:device_save', args=['android']),
        {'host_port': '127.0.0.1:5555'},
    )
    assert resp.status_code == 403
    assert not AdbConnection.objects.exists()


@pytest.mark.django_db
def test_device_save_get_not_allowed(su_client):
    resp = su_client.get(reverse('rbac:device_save', args=['android']))
    assert resp.status_code == 405


# ═══════════════════════════════════════════════════════ model_save
@pytest.mark.django_db
def test_model_save_invalid_role_redirects(su_client):
    resp = su_client.post(
        reverse('rbac:model_save', args=['bogus']),
        {'base_url': LOOPBACK_URL, 'model_name': 'granite4:3b'},
    )
    assert resp.status_code == 302
    assert not ModelIntegration.objects.exists()


@pytest.mark.django_db
def test_model_save_missing_model_name_rejected(su_client, monkeypatch):
    probe = MagicMock()
    monkeypatch.setattr(views, '_probe_model_endpoint', probe)
    resp = su_client.post(
        reverse('rbac:model_save', args=['generate']),
        {'base_url': LOOPBACK_URL, 'model_name': ''},
        follow=True,
    )
    assert resp.status_code == 200
    assert not ModelIntegration.objects.exists()
    assert b'Provide a valid endpoint' in resp.content
    probe.assert_not_called()


@pytest.mark.django_db
def test_model_save_invalid_url_format_rejected(su_client):
    resp = su_client.post(
        reverse('rbac:model_save', args=['generate']),
        {'base_url': 'not-a-url', 'model_name': 'granite4:3b'},
        follow=True,
    )
    assert resp.status_code == 200
    assert not ModelIntegration.objects.exists()
    assert b'Provide a valid endpoint' in resp.content


@pytest.mark.django_db
def test_model_save_enclave_reject_public_host(su_client, monkeypatch):
    """SSRF guard: a public-IP endpoint must never be persisted or probed."""
    probe = MagicMock()
    monkeypatch.setattr(views, '_probe_model_endpoint', probe)
    resp = su_client.post(
        reverse('rbac:model_save', args=['generate']),
        {'base_url': PUBLIC_URL, 'model_name': 'granite4:3b'},
        follow=True,
    )
    assert resp.status_code == 200
    assert not ModelIntegration.objects.exists()
    assert b'must be loopback' in resp.content
    probe.assert_not_called()


@pytest.mark.django_db
def test_model_save_generate_happy_path(su_client, monkeypatch):
    probe = MagicMock(return_value=(
        ModelIntegration.STATUS_CONNECTED, '1 model(s) available', ['granite4:3b']))
    monkeypatch.setattr(views, '_probe_model_endpoint', probe)
    resp = su_client.post(
        reverse('rbac:model_save', args=['generate']),
        {'base_url': LOOPBACK_URL, 'model_name': 'granite4:3b'},
    )
    assert resp.status_code == 302
    integ = ModelIntegration.objects.get(role=ModelIntegration.ROLE_GENERATE)
    assert integ.base_url == LOOPBACK_URL
    assert integ.model_name == 'granite4:3b'
    assert integ.label == 'Generation model'
    assert integ.is_active is True
    assert integ.last_status == ModelIntegration.STATUS_CONNECTED
    assert integ.detected_models == 'granite4:3b'
    probe.assert_called_once_with(LOOPBACK_URL)
    ev = AuditEvent.objects.filter(action='integration.model.save').first()
    assert ev is not None
    assert ev.metadata['role'] == 'generate'


@pytest.mark.django_db
def test_model_save_classify_happy_path(su_client, monkeypatch):
    monkeypatch.setattr(
        views, '_probe_model_endpoint',
        MagicMock(return_value=(ModelIntegration.STATUS_FAILED, 'HTTP 500', [])))
    resp = su_client.post(
        reverse('rbac:model_save', args=['classify']),
        {'base_url': LOOPBACK_URL, 'model_name': 'granite4:1b'},
    )
    assert resp.status_code == 302
    integ = ModelIntegration.objects.get(role=ModelIntegration.ROLE_CLASSIFY)
    assert integ.label == 'Classification model'
    assert integ.last_status == ModelIntegration.STATUS_FAILED


@pytest.mark.django_db
def test_model_save_update_or_create_by_role(su_client, monkeypatch):
    """update_or_create(role=...) means a second save for the same role
    updates the single row rather than creating a sibling."""
    monkeypatch.setattr(
        views, '_probe_model_endpoint',
        MagicMock(return_value=(ModelIntegration.STATUS_CONNECTED, 'ok', [])))
    su_client.post(reverse('rbac:model_save', args=['generate']),
                    {'base_url': LOOPBACK_URL, 'model_name': 'granite4:3b'})
    first = ModelIntegration.objects.get(role=ModelIntegration.ROLE_GENERATE)

    su_client.post(reverse('rbac:model_save', args=['generate']),
                    {'base_url': 'http://127.0.0.1:9999', 'model_name': 'granite4:8b'})
    assert ModelIntegration.objects.filter(
        role=ModelIntegration.ROLE_GENERATE).count() == 1
    second = ModelIntegration.objects.get(role=ModelIntegration.ROLE_GENERATE)
    assert second.pk == first.pk
    assert second.base_url == 'http://127.0.0.1:9999'
    assert second.model_name == 'granite4:8b'


@pytest.mark.django_db
def test_model_save_generate_and_classify_share_endpoint(su_client, monkeypatch):
    """The base_url unique constraint was dropped in migration 0012 so the
    generate and classify roles can point at the same Ollama endpoint."""
    monkeypatch.setattr(
        views, '_probe_model_endpoint',
        MagicMock(return_value=(ModelIntegration.STATUS_CONNECTED, 'ok', [])))
    r1 = su_client.post(reverse('rbac:model_save', args=['generate']),
                         {'base_url': LOOPBACK_URL, 'model_name': 'granite4:3b'})
    r2 = su_client.post(reverse('rbac:model_save', args=['classify']),
                         {'base_url': LOOPBACK_URL, 'model_name': 'granite4:1b'})
    assert r1.status_code == 302
    assert r2.status_code == 302
    assert ModelIntegration.objects.filter(base_url=LOOPBACK_URL).count() == 2
    roles = set(ModelIntegration.objects.filter(
        base_url=LOOPBACK_URL).values_list('role', flat=True))
    assert roles == {ModelIntegration.ROLE_GENERATE, ModelIntegration.ROLE_CLASSIFY}


@pytest.mark.django_db
def test_model_save_denied_for_plain_user(client, plain_user):
    client.force_login(plain_user)
    resp = client.post(
        reverse('rbac:model_save', args=['generate']),
        {'base_url': LOOPBACK_URL, 'model_name': 'granite4:3b'},
    )
    assert resp.status_code == 403
    assert not ModelIntegration.objects.exists()


@pytest.mark.django_db
def test_model_save_get_not_allowed(su_client):
    resp = su_client.get(reverse('rbac:model_save', args=['generate']))
    assert resp.status_code == 405


# ═══════════════════════════════════════════════════════ device_test_key
@pytest.mark.django_db
def test_device_test_key_not_configured(su_client):
    resp = su_client.post(reverse('rbac:device_test', args=['android']))
    assert resp.status_code == 200
    data = resp.json()
    assert data == {
        'success': False, 'status': 'unknown', 'message': 'Not configured yet.',
    }


@pytest.mark.django_db
def test_device_test_key_configured(su_client, superuser, monkeypatch):
    conn = AdbConnection.objects.create(
        label='Android device', host_port='127.0.0.1:5555',
        platform=AdbConnection.PLATFORM_ANDROID, created_by=superuser,
    )
    mock_run = MagicMock(return_value=(AdbConnection.STATUS_CONNECTED, 'connected'))
    monkeypatch.setattr(views, '_run_adb', mock_run)

    resp = su_client.post(reverse('rbac:device_test', args=['android']))
    assert resp.status_code == 200
    data = resp.json()
    assert data['success'] is True
    assert data['status'] == AdbConnection.STATUS_CONNECTED
    assert data['message'] == 'connected'
    assert 'last_status_at' in data
    mock_run.assert_called_once_with(['connect', '127.0.0.1:5555'])
    conn.refresh_from_db()
    assert conn.last_status == AdbConnection.STATUS_CONNECTED


@pytest.mark.django_db
def test_device_test_key_failure_status(su_client, superuser, monkeypatch):
    AdbConnection.objects.create(
        label='iOS device', host_port='127.0.0.1:6000',
        platform=AdbConnection.PLATFORM_IOS, created_by=superuser,
    )
    monkeypatch.setattr(
        views, '_run_adb',
        MagicMock(return_value=(AdbConnection.STATUS_TIMEOUT, 'timed out')))
    resp = su_client.post(reverse('rbac:device_test', args=['ios']))
    data = resp.json()
    assert data['success'] is False
    assert data['status'] == AdbConnection.STATUS_TIMEOUT


@pytest.mark.django_db
def test_device_test_key_denied_for_plain_user(client, plain_user):
    client.force_login(plain_user)
    resp = client.post(reverse('rbac:device_test', args=['android']))
    assert resp.status_code == 403


@pytest.mark.django_db
def test_device_test_key_get_not_allowed(su_client):
    resp = su_client.get(reverse('rbac:device_test', args=['android']))
    assert resp.status_code == 405


# ═══════════════════════════════════════════════════════ model_test_key
@pytest.mark.django_db
def test_model_test_key_not_configured(su_client):
    resp = su_client.post(reverse('rbac:model_test', args=['generate']))
    assert resp.status_code == 200
    data = resp.json()
    assert data == {
        'success': False, 'status': 'unknown', 'message': 'Not configured yet.',
    }


@pytest.mark.django_db
def test_model_test_key_configured(su_client, superuser, monkeypatch):
    integ = ModelIntegration.objects.create(
        role=ModelIntegration.ROLE_GENERATE, base_url=LOOPBACK_URL,
        model_name='granite4:3b', label='Generation model', created_by=superuser,
    )
    monkeypatch.setattr(
        views, '_probe_model_endpoint',
        MagicMock(return_value=(
            ModelIntegration.STATUS_CONNECTED, '2 model(s) available',
            ['granite4:3b', 'nomic-embed-text'])))

    resp = su_client.post(reverse('rbac:model_test', args=['generate']))
    assert resp.status_code == 200
    data = resp.json()
    assert data['success'] is True
    assert data['status'] == ModelIntegration.STATUS_CONNECTED
    assert data['models_list'] == ['granite4:3b', 'nomic-embed-text']
    assert 'last_status_at' in data
    integ.refresh_from_db()
    assert integ.detected_models == 'granite4:3b, nomic-embed-text'


@pytest.mark.django_db
def test_model_test_key_failure_status(su_client, superuser, monkeypatch):
    ModelIntegration.objects.create(
        role=ModelIntegration.ROLE_CLASSIFY, base_url=LOOPBACK_URL,
        model_name='granite4:1b', created_by=superuser,
    )
    monkeypatch.setattr(
        views, '_probe_model_endpoint',
        MagicMock(return_value=(ModelIntegration.STATUS_FAILED, 'HTTP 503', [])))
    resp = su_client.post(reverse('rbac:model_test', args=['classify']))
    data = resp.json()
    assert data['success'] is False
    assert data['status'] == ModelIntegration.STATUS_FAILED
    assert data['models_list'] == []


@pytest.mark.django_db
def test_model_test_key_denied_for_plain_user(client, plain_user):
    client.force_login(plain_user)
    resp = client.post(reverse('rbac:model_test', args=['generate']))
    assert resp.status_code == 403


@pytest.mark.django_db
def test_model_test_key_get_not_allowed(su_client):
    resp = su_client.get(reverse('rbac:model_test', args=['generate']))
    assert resp.status_code == 405


# ═══════════════════════════════════════════════════════ adb_connections_list
@pytest.mark.django_db
def test_adb_connections_list_renders_four_cards_empty(su_client):
    resp = su_client.get(reverse('rbac:adb_connections'))
    assert resp.status_code == 200
    for card_id in ('card-android', 'card-ios', 'card-generate', 'card-classify'):
        assert card_id.encode() in resp.content
    assert resp.context['android'] is None
    assert resp.context['ios'] is None
    assert resp.context['gen_model'] is None
    assert resp.context['classify_model'] is None


@pytest.mark.django_db
def test_adb_connections_list_with_rows(su_client, superuser):
    AdbConnection.objects.create(
        label='Android device', host_port='127.0.0.1:5555',
        platform=AdbConnection.PLATFORM_ANDROID, created_by=superuser)
    AdbConnection.objects.create(
        label='iOS device', host_port='127.0.0.1:6000',
        platform=AdbConnection.PLATFORM_IOS, created_by=superuser)
    ModelIntegration.objects.create(
        role=ModelIntegration.ROLE_GENERATE, base_url=LOOPBACK_URL,
        model_name='granite4:3b', created_by=superuser)
    ModelIntegration.objects.create(
        role=ModelIntegration.ROLE_CLASSIFY, base_url=LOOPBACK_URL,
        model_name='granite4:1b', created_by=superuser)

    resp = su_client.get(reverse('rbac:adb_connections'))
    assert resp.status_code == 200
    assert resp.context['android'].host_port == '127.0.0.1:5555'
    assert resp.context['ios'].host_port == '127.0.0.1:6000'
    assert resp.context['gen_model'].model_name == 'granite4:3b'
    assert resp.context['classify_model'].model_name == 'granite4:1b'
    assert b'127.0.0.1:5555' in resp.content
    assert b'127.0.0.1:6000' in resp.content
    assert b'granite4:3b' in resp.content
    assert b'granite4:1b' in resp.content


@pytest.mark.django_db
@override_settings(
    MOBINSPECT_AI_BASE_URL='http://127.0.0.1:11434',
    MOBINSPECT_AI_MODEL_GENERATE='env-gen-model',
    MOBINSPECT_AI_MODEL_CLASSIFY='env-clf-model',
    ANALYZER_IDENTIFIER='127.0.0.1:5037',
)
def test_adb_connections_list_env_prefills(su_client):
    """When no DB row exists yet, the card inputs prefill from settings."""
    resp = su_client.get(reverse('rbac:adb_connections'))
    assert resp.status_code == 200
    assert resp.context['ai_base_url_default'] == 'http://127.0.0.1:11434'
    assert resp.context['gen_model_default'] == 'env-gen-model'
    assert resp.context['classify_model_default'] == 'env-clf-model'
    assert resp.context['android_identifier_default'] == '127.0.0.1:5037'
    assert b'env-gen-model' in resp.content
    assert b'env-clf-model' in resp.content
    assert b'127.0.0.1:5037' in resp.content


@pytest.mark.django_db
def test_adb_connections_list_missing_settings_default_to_empty(su_client, settings):
    """Guarded via getattr(...,'') so a bare settings module (no AI/adb env
    vars configured) never raises AttributeError."""
    for attr in ('MOBINSPECT_AI_BASE_URL', 'MOBINSPECT_AI_MODEL_GENERATE',
                 'MOBINSPECT_AI_MODEL_CLASSIFY', 'ANALYZER_IDENTIFIER'):
        if hasattr(settings, attr):
            delattr(settings, attr)
    resp = su_client.get(reverse('rbac:adb_connections'))
    assert resp.status_code == 200
    assert resp.context['ai_base_url_default'] == ''
    assert resp.context['gen_model_default'] == ''
    assert resp.context['classify_model_default'] == ''
    assert resp.context['android_identifier_default'] == ''


@pytest.mark.django_db
def test_adb_connections_list_denied_without_settings_view(client, plain_user):
    client.force_login(plain_user)
    resp = client.get(reverse('rbac:adb_connections'))
    assert resp.status_code == 403


# ═══════════════════════════════════════ _probe_model_endpoint (pure-ish)
def test_probe_model_endpoint_invalid_url_format():
    status, message, models = views._probe_model_endpoint('not-a-url')
    assert status == ModelIntegration.STATUS_FAILED
    assert 'http(s)://host:port' in message
    assert models == []


def test_probe_model_endpoint_rejects_public_host():
    """SSRF guard exercised directly: a public IP literal is rejected
    without any network call (ip_address parsing is purely local)."""
    status, message, models = views._probe_model_endpoint(PUBLIC_URL)
    assert status == ModelIntegration.STATUS_FAILED
    assert 'loopback/private' in message
    assert models == []


def test_probe_model_endpoint_success(monkeypatch):
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        'models': [{'name': 'granite4:3b'}, {'name': ''}, {}],
    }
    mock_get = MagicMock(return_value=fake_resp)
    monkeypatch.setattr('requests.get', mock_get)

    status, message, models = views._probe_model_endpoint(LOOPBACK_URL)
    assert status == ModelIntegration.STATUS_CONNECTED
    assert message == '1 model(s) available'
    # Falsy/missing "name" entries are filtered out.
    assert models == ['granite4:3b']
    mock_get.assert_called_once()
    called_url = mock_get.call_args.args[0]
    assert called_url == LOOPBACK_URL + '/api/tags'
    assert mock_get.call_args.kwargs['allow_redirects'] is False


def test_probe_model_endpoint_non_200(monkeypatch):
    fake_resp = MagicMock()
    fake_resp.status_code = 404
    monkeypatch.setattr('requests.get', MagicMock(return_value=fake_resp))

    status, message, models = views._probe_model_endpoint(LOOPBACK_URL)
    assert status == ModelIntegration.STATUS_FAILED
    assert message == 'HTTP 404'
    assert models == []


def test_probe_model_endpoint_timeout(monkeypatch):
    import requests

    def _raise(*a, **kw):
        raise requests.exceptions.Timeout('slow')

    monkeypatch.setattr('requests.get', _raise)
    status, message, models = views._probe_model_endpoint(LOOPBACK_URL)
    assert status == ModelIntegration.STATUS_TIMEOUT
    assert message == 'Connection timed out'
    assert models == []


def test_probe_model_endpoint_generic_exception(monkeypatch):
    def _raise(*a, **kw):
        raise ValueError('boom')

    monkeypatch.setattr('requests.get', _raise)
    status, message, models = views._probe_model_endpoint(LOOPBACK_URL)
    assert status == ModelIntegration.STATUS_FAILED
    assert message == 'ValueError'
    assert models == []


def test_probe_model_endpoint_strips_trailing_slash(monkeypatch):
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {'models': []}
    mock_get = MagicMock(return_value=fake_resp)
    monkeypatch.setattr('requests.get', mock_get)

    views._probe_model_endpoint(LOOPBACK_URL + '/')
    called_url = mock_get.call_args.args[0]
    assert called_url == LOOPBACK_URL + '/api/tags'


# ═══════════════════════════════════════ _apply_model_probe (pure-ish)
@pytest.mark.django_db
def test_apply_model_probe_persists_result(superuser, monkeypatch):
    integ = ModelIntegration.objects.create(
        role=ModelIntegration.ROLE_GENERATE, base_url=LOOPBACK_URL,
        model_name='granite4:3b', created_by=superuser,
    )
    monkeypatch.setattr(
        views, '_probe_model_endpoint',
        MagicMock(return_value=(
            ModelIntegration.STATUS_CONNECTED, 'all good',
            ['granite4:3b', 'nomic-embed-text'])))

    status, message, models = views._apply_model_probe(integ)
    assert status == ModelIntegration.STATUS_CONNECTED
    assert message == 'all good'
    assert models == ['granite4:3b', 'nomic-embed-text']
    integ.refresh_from_db()
    assert integ.last_status == ModelIntegration.STATUS_CONNECTED
    assert integ.last_status_message == 'all good'
    assert integ.detected_models == 'granite4:3b, nomic-embed-text'
    assert integ.last_status_at is not None


@pytest.mark.django_db
def test_apply_model_probe_truncates_long_message(superuser, monkeypatch):
    integ = ModelIntegration.objects.create(
        role=ModelIntegration.ROLE_GENERATE, base_url=LOOPBACK_URL,
        model_name='granite4:3b', created_by=superuser,
    )
    long_message = 'x' * 5000
    monkeypatch.setattr(
        views, '_probe_model_endpoint',
        MagicMock(return_value=(ModelIntegration.STATUS_FAILED, long_message, [])))

    views._apply_model_probe(integ)
    integ.refresh_from_db()
    assert len(integ.last_status_message) == 2000
