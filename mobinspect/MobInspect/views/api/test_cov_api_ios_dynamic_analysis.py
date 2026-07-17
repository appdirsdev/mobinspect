"""Real-execution coverage tests for the iOS Dynamic Analysis REST API.

STRICT: no mocks. These drive the real view functions in
``mobinspect.MobInspect.views.api.api_ios_dynamic_analysis`` with real Django
requests (RequestFactory), a real created superuser, and a real per-user
RBAC ApiKey row. We exercise only the reachable request-validation and
error branches:

  * Missing-parameter guards -> HTTP 422.
  * ``common_check`` short-circuit (no ``CORELLIUM_API_KEY`` configured in
    the test settings) -> the underlying corellium helper returns
    ``{'status': 'failed', 'message': 'Missing Corellium API key'}`` which
    the view maps to HTTP 500. No Corellium device / network is touched.
  * Local validation failures (invalid bundle id, invalid hash, invalid
    VM flavor, missing dynamic report) -> HTTP 500.
  * A genuinely reachable success path: reading an on-disk app-container
    file -> HTTP 200.
  * HTTP method guard (GET on a POST-only endpoint) -> HTTP 405.

Device-only lines (anything that requires a live Corellium/Frida instance,
an SSH tunnel, or a real network call) are intentionally left uncovered
and reported as ceiling-gap.
"""
import json

import pytest

from django.conf import settings
from django.test import RequestFactory

from mobinspect.RBAC.models import ApiKey
from mobinspect.MobInspect.views.api import api_ios_dynamic_analysis as mod


# ---------------------------------------------------------------- fixtures
@pytest.fixture
def superuser(db, django_user_model):
    """Real Django superuser (is_staff -> passes permission_required)."""
    return django_user_model.objects.create_user(
        username='ios_dyn_root',
        password='root-pw-not-used',
        is_staff=True,
        is_superuser=True,
    )


@pytest.fixture
def api_key(db, superuser):
    """Real per-user RBAC ApiKey bound to the superuser (plaintext)."""
    _inst, plaintext = ApiKey.generate(user=superuser, name='ios-dyn-test')
    return plaintext


@pytest.fixture
def rf():
    return RequestFactory()


def _authed_post(rf, superuser, api_key, data):
    """Build a POST request that the auth decorators will accept.

    The view helpers are decorated with ``login_required`` /
    ``permission_required`` / ``require_permission``; those resolve the
    principal from ``request.api_user`` (falling back to ``request.user``)
    and honor ``request.is_api``. RequestFactory does not run middleware,
    so we set those attributes the way RestApiAuthMiddleware would after a
    successful per-user key auth.
    """
    request = rf.post('/api/v1/ios/anything', data=data)
    request.user = superuser
    request.api_user = superuser
    request.api = True
    request.is_api = True
    request.api_key = ApiKey.lookup(api_key)
    return request


def _body(resp):
    return json.loads(resp.content.decode('utf-8'))


VALID_INSTANCE = 'a1b2c3d4-1111-2222-3333-444455556666'
VALID_BUNDLE = 'com.example.app'


# ------------------------------------------------------- 422 missing params
# Each entry: (view function, POST data that is a strict subset of required).
MISSING_PARAM_CASES = [
    (mod.api_ios_dynamic_analyzer, {'instance_id': VALID_INSTANCE}),
    (mod.api_corellium_get_supported_ios_versions, {}),
    (mod.api_corellium_create_ios_instance, {'name': 'x'}),
    (mod.api_corellium_start_instance, {}),
    (mod.api_corellium_stop_instance, {}),
    (mod.api_corellium_unpause_instance, {}),
    (mod.api_corellium_reboot_instance, {}),
    (mod.api_corellium_destroy_instance, {}),
    (mod.api_corellium_instance_list_apps, {}),
    (mod.api_setup_environment, {'instance_id': VALID_INSTANCE}),
    (mod.api_run_app, {'instance_id': VALID_INSTANCE}),
    (mod.api_stop_app, {'instance_id': VALID_INSTANCE}),
    (mod.api_remove_app, {'instance_id': VALID_INSTANCE}),
    (mod.api_take_screenshot, {}),
    (mod.api_get_app_container_path, {}),
    (mod.api_network_capture, {'instance_id': VALID_INSTANCE}),
    (mod.api_live_pcap_download, {}),
    (mod.api_ssh_execute, {'instance_id': VALID_INSTANCE}),
    (mod.api_download_app_data, {'instance_id': VALID_INSTANCE}),
    (mod.api_instance_input, {}),
    (mod.api_system_logs, {}),
    (mod.api_device_file_upload, {}),
    (mod.api_device_file_download, {'instance_id': VALID_INSTANCE}),
    (mod.api_ios_instrument, {'instance_id': VALID_INSTANCE}),
    (mod.api_ios_view_report, {'instance_id': VALID_INSTANCE}),
]


@pytest.mark.django_db
@pytest.mark.parametrize('view, data', MISSING_PARAM_CASES)
def test_missing_params_returns_422(rf, superuser, api_key, view, data):
    request = _authed_post(rf, superuser, api_key, data)
    resp = view(request)
    assert resp.status_code == 422
    assert _body(resp)['error'] == 'Missing Parameters'


# ------------------------------------------ 500 via common_check short-circuit
# CORELLIUM_API_KEY is empty in test settings, so common_check() returns
# {'status':'failed','message':'Missing Corellium API key'} before any
# network/device access -> view maps to 500.
COMMON_CHECK_500_CASES = [
    (mod.api_corellium_start_instance,
     {'instance_id': VALID_INSTANCE}),
    (mod.api_corellium_stop_instance,
     {'instance_id': VALID_INSTANCE}),
    (mod.api_corellium_unpause_instance,
     {'instance_id': VALID_INSTANCE}),
    (mod.api_corellium_reboot_instance,
     {'instance_id': VALID_INSTANCE}),
    (mod.api_corellium_destroy_instance,
     {'instance_id': VALID_INSTANCE}),
    (mod.api_corellium_instance_list_apps,
     {'instance_id': VALID_INSTANCE}),
    (mod.api_take_screenshot,
     {'instance_id': VALID_INSTANCE}),
    (mod.api_network_capture,
     {'instance_id': VALID_INSTANCE, 'state': 'on'}),
    (mod.api_live_pcap_download,
     {'instance_id': VALID_INSTANCE}),
    (mod.api_instance_input,
     {'instance_id': VALID_INSTANCE}),
    (mod.api_system_logs,
     {'instance_id': VALID_INSTANCE}),
    (mod.api_device_file_upload,
     {'instance_id': VALID_INSTANCE}),
    (mod.api_device_file_download,
     {'instance_id': VALID_INSTANCE, 'file': '/tmp/x'}),
    (mod.api_run_app,
     {'instance_id': VALID_INSTANCE, 'bundle_id': VALID_BUNDLE}),
    (mod.api_stop_app,
     {'instance_id': VALID_INSTANCE, 'bundle_id': VALID_BUNDLE}),
    (mod.api_remove_app,
     {'instance_id': VALID_INSTANCE, 'bundle_id': VALID_BUNDLE}),
    (mod.api_download_app_data,
     {'instance_id': VALID_INSTANCE, 'bundle_id': VALID_BUNDLE}),
    (mod.api_ssh_execute,
     {'instance_id': VALID_INSTANCE, 'cmd': 'ls'}),
    (mod.api_ios_instrument,
     {'instance_id': VALID_INSTANCE,
      'bundle_id': VALID_BUNDLE,
      'hash': 'a' * 32,
      'default_hooks': 'true',
      'dump_hooks': 'true',
      'auxiliary_hooks': 'false',
      'frida_code': ''}),
]


@pytest.mark.django_db
@pytest.mark.parametrize('view, data', COMMON_CHECK_500_CASES)
def test_common_check_missing_corellium_key_returns_500(
        rf, superuser, api_key, view, data):
    request = _authed_post(rf, superuser, api_key, data)
    resp = view(request)
    assert resp.status_code == 500
    body = _body(resp)
    assert body.get('status') == 'failed'
    assert 'Corellium API key' in body.get('message', '')


# ------------------------------------------- 500 via local validation failures
@pytest.mark.django_db
def test_dynamic_analyzer_invalid_bundle_id_returns_500(
        rf, superuser, api_key):
    # '1bad' fails strict_package_check (must start with a letter).
    request = _authed_post(
        rf, superuser, api_key,
        {'instance_id': VALID_INSTANCE, 'bundle_id': '1bad'})
    resp = mod.api_ios_dynamic_analyzer(request)
    assert resp.status_code == 500
    assert 'Invalid iOS Bundle id' in _body(resp)['error']


@pytest.mark.django_db
def test_setup_environment_invalid_hash_returns_500(rf, superuser, api_key):
    request = _authed_post(
        rf, superuser, api_key,
        {'instance_id': VALID_INSTANCE, 'hash': 'not-a-real-md5'})
    resp = mod.api_setup_environment(request)
    assert resp.status_code == 500
    assert _body(resp)['message'] == 'Invalid Hash'


@pytest.mark.django_db
def test_create_ios_instance_invalid_flavor_returns_500(
        rf, superuser, api_key):
    request = _authed_post(
        rf, superuser, api_key,
        {'name': 'MyVM', 'project_id': VALID_INSTANCE,
         'flavor': 'not-an-iphone', 'version': '15.0'})
    resp = mod.api_corellium_create_ios_instance(request)
    assert resp.status_code == 500
    assert _body(resp)['message'] == 'Invalid iOS flavor'


@pytest.mark.django_db
def test_get_app_container_path_invalid_bundle_returns_500(
        rf, superuser, api_key):
    request = _authed_post(
        rf, superuser, api_key, {'bundle_id': '1bad'})
    resp = mod.api_get_app_container_path(request)
    assert resp.status_code == 500
    assert _body(resp)['message'] == 'Invalid iOS Bundle id'


@pytest.mark.django_db
def test_get_app_container_path_no_file_returns_500(rf, superuser, api_key):
    # Valid bundle id but no on-disk container file -> stays failed -> 500.
    request = _authed_post(
        rf, superuser, api_key, {'bundle_id': 'com.no.such.app.here'})
    resp = mod.api_get_app_container_path(request)
    assert resp.status_code == 500
    assert _body(resp)['status'] == 'failed'


@pytest.mark.django_db
def test_get_app_container_path_existing_file_returns_200(
        rf, superuser, api_key, tmp_path):
    """Reachable success branch: read a real on-disk container-path file."""
    from pathlib import Path
    from mobinspect.MobInspect.utils import get_md5

    bundle_id = 'com.example.container'
    checksum = get_md5(bundle_id.encode('utf-8'))
    app_dir = Path(settings.UPLD_DIR) / checksum
    app_dir.mkdir(parents=True, exist_ok=True)
    container_file = app_dir / 'mobinspect_app_container_path.txt'
    container_file.write_text(
        '/var/containers/Bundle/Application/ABC\n', encoding='utf-8')
    try:
        request = _authed_post(
            rf, superuser, api_key, {'bundle_id': bundle_id})
        resp = mod.api_get_app_container_path(request)
        assert resp.status_code == 200
        body = _body(resp)
        assert body['status'] == 'ok'
        assert body['message'] == '/var/containers/Bundle/Application/ABC'
    finally:
        container_file.unlink()


@pytest.mark.django_db
def test_ssh_execute_denied_command_returns_200(rf, superuser, api_key):
    """A command not on the SSH allowlist returns a 'denied' status (200).

    'rm -rf /' is not in SSH_CMD_ALLOWLIST, so the underlying helper
    returns {'status': 'denied', ...} which is neither FAILED nor an
    HttpResponse -> the view returns it with 200.
    """
    request = _authed_post(
        rf, superuser, api_key,
        {'instance_id': VALID_INSTANCE, 'cmd': 'rm -rf /'})
    resp = mod.api_ssh_execute(request)
    assert resp.status_code == 200
    assert _body(resp)['status'] == 'denied'


@pytest.mark.django_db
def test_view_report_no_report_returns_500(rf, superuser, api_key):
    # Valid bundle id, but no dynamic-analysis artifacts on disk.
    request = _authed_post(
        rf, superuser, api_key,
        {'instance_id': VALID_INSTANCE,
         'bundle_id': 'com.example.noreport'})
    resp = mod.api_ios_view_report(request)
    assert resp.status_code == 500
    assert 'error' in _body(resp)


@pytest.mark.django_db
def test_view_report_invalid_bundle_returns_500(rf, superuser, api_key):
    request = _authed_post(
        rf, superuser, api_key,
        {'instance_id': VALID_INSTANCE, 'bundle_id': '1bad'})
    resp = mod.api_ios_view_report(request)
    assert resp.status_code == 500
    assert 'Invalid iOS Bundle id' in _body(resp)['error']


# --------------------------------------------------------- entrypoint (no key)
@pytest.mark.django_db
def test_dynamic_analysis_entrypoint_returns_200_context(
        rf, superuser, api_key):
    """The iOS DA entrypoint returns a 200 context when Corellium is not
    configured (api_ready() is False without a key) -> no 'error' key."""
    request = _authed_post(rf, superuser, api_key, {})
    resp = mod.api_ios_dynamic_analysis(request)
    assert resp.status_code == 200
    body = _body(resp)
    # Corellium disabled -> dynamic_analyzer flag is falsy, apps list present.
    assert body.get('dynamic_analyzer') in (False, None, '')
    assert 'apps' in body


# --------------------------------------------------------- HTTP method guard
@pytest.mark.django_db
def test_get_method_not_allowed(rf, superuser, api_key):
    request = rf.get('/api/v1/ios/start_analysis')
    request.user = superuser
    request.api_user = superuser
    request.api = True
    request.is_api = True
    resp = mod.api_ios_dynamic_analysis(request)
    assert resp.status_code == 405
