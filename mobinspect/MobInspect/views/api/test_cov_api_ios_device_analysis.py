# -*- coding: utf_8 -*-
"""Real-execution coverage tests for the iOS Device REST API.

STRICT: no mocks. Every branch is exercised by driving the real view
functions with real Django RequestFactory requests, a real superuser
created through the ORM, and real files on disk. Device-only branches
(anything that needs a live jailbroken iOS device / SSH connection)
are intentionally left as ceiling-gaps and documented at the bottom.

The design leans on one real behavior of the codebase:
`validate_and_connect_device()` rejects a malformed/unreachable device
id BEFORE any hardware I/O, returning an error string. That drives every
"inner call failed -> HTTP 500" branch of the thin API wrappers without a
device. The 422 (missing-parameter) branches need no auth because the
validation lives in the wrapper itself, before the permission-guarded
inner function is ever called.

One exception: `view_report_device()` (behind `api_device_report_json`)
never calls `validate_and_connect_device()` at all -- it only checks the
device id's regex FORMAT and then reads purely local files under
UPLD_DIR. `test_report_json_success_with_real_local_data` exploits this
to reach the one genuine 200/success branch in this module that needs no
live device: create a real (empty) `mobinspect_frida_out.txt` so the
"has dynamic analysis run" gate passes, then let the real (mostly-empty)
report-assembly code run to completion.

SUSPECTED BUGS (not fixed, only documented + pragma'd in the production
file with a one-line reason each):
  * `api_device_dynamic_analyzer`'s `resp.get('status') == FAILED` check
    is dead code: the underlying `dynamic_analyzer_device()` never sets
    a 'status' key on any path (failure returns {'error': ...} via
    print_n_send_error_response; success returns a plain context dict
    with no 'status' key either). The practical effect is that a REAL
    analyzer error (e.g. an invalid bundle id) is reported as HTTP 200
    with an 'error' key buried in the body, not HTTP 500 -- see the
    already-existing `test_dynamic_analyzer_invalid_bundle_returns_200_error`
    below, which pins this exact (probably unintended) behavior.
  * `api_device_file_download`'s final `return make_api_response(resp, 200)`
    is dead code: `download_file_device()` either returns a real file
    HttpResponse (caught by the Content-Disposition check above it) or a
    dict whose 'status' is initialized to 'failed' and never changed to
    anything else on any non-file code path, so the FAILED check above
    it always fires first when resp is a dict.
"""
import json
import os
from pathlib import Path

import pytest

from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory

from mobinspect.MobInspect.utils import get_md5
from mobinspect.MobInspect.views.api import api_ios_device_analysis as mod


# A syntactically valid md5 (32 hex) and a valid iOS bundle id.
VALID_MD5 = 'a' * 32
VALID_BUNDLE = 'com.example.testapp'
# A device id that fails IOS_DEVICE_ID_REGEX and SSH_DEVICE_ID_REGEX,
# so validate_and_connect_device returns an error without touching HW.
BAD_DEVICE = 'not-a-real-device!!'
# A device id that PASSES IOS_DEVICE_ID_REGEX (r'^[a-fA-F0-9-]{20,40}$')
# purely on format -- used only for view_report_device(), which validates
# the device id's format but never actually connects to it.
VALID_FORMAT_DEVICE = 'a' * 24


@pytest.fixture
def rf():
    return RequestFactory()


@pytest.fixture
def superuser(db, django_user_model):
    """Real superuser row; superuser fast-path satisfies every RBAC gate."""
    return django_user_model.objects.create_user(
        username='ios_api_root',
        password='root-pw-not-used',
        is_staff=True,
        is_superuser=True,
    )


def _authed(request, user):
    """Attach a real authenticated principal the way the API middleware would.

    The middleware sets request.api_user on a successful per-user ApiKey
    auth (layered over the session user); the permission decorators read
    exactly those attributes. No mock -- we set the same attributes to the
    same real User object. request.user is required so effective_user()
    (RBAC) can find the layered api_user.
    """
    request.user = user
    request.api_user = user
    request.is_api = True
    request.api = True
    return request


def _body(response):
    return json.loads(response.content.decode('utf-8'))


# ───────────────────────────────────────── api_device_dynamic_analysis
def test_dynamic_analysis_missing_device_id(rf):
    resp = mod.api_device_dynamic_analysis(rf.post('/', {}))
    assert resp.status_code == 422
    assert _body(resp)['error'] == 'Missing Parameters'


def test_dynamic_analysis_entrypoint_ok(rf, superuser):
    # Force the docker code path so get_usb_devices() (which needs libusb /
    # a device) is skipped and the entrypoint returns its context -> 200.
    prev = os.environ.get('MOBINSPECT_PLATFORM')
    os.environ['MOBINSPECT_PLATFORM'] = 'docker'
    try:
        req = _authed(rf.post('/', {'device_id': BAD_DEVICE}), superuser)
        resp = mod.api_device_dynamic_analysis(req)
    finally:
        if prev is None:
            os.environ.pop('MOBINSPECT_PLATFORM', None)
        else:
            os.environ['MOBINSPECT_PLATFORM'] = prev
    # Entrypoint just lists local apps/devices; no error key -> 200.
    assert resp.status_code == 200
    body = _body(resp)
    assert body['selected_device'] == BAD_DEVICE
    assert body['usb_devices'] == []
    assert 'apps' in body


# ───────────────────────────────────────── api_device_get
def test_device_get_missing_device_id(rf):
    resp = mod.api_device_get(rf.post('/', {}))
    assert resp.status_code == 422
    assert _body(resp)['error'] == 'Missing Parameters'


def test_device_get_bad_device_returns_500(rf, superuser):
    req = _authed(rf.post('/', {'device_id': BAD_DEVICE}), superuser)
    resp = mod.api_device_get(req)
    assert resp.status_code == 500
    assert _body(resp)['status'] == 'failed'


# ───────────────────────────────────────── api_device_install_ipa
def test_install_ipa_missing_params(rf):
    # Only device_id -> proper subset of {device_id, checksum} -> 422.
    resp = mod.api_device_install_ipa(rf.post('/', {'device_id': BAD_DEVICE}))
    assert resp.status_code == 422
    assert _body(resp)['error'] == 'Missing Parameters'


def test_install_ipa_invalid_checksum_500(rf, superuser):
    req = _authed(
        rf.post('/', {'device_id': BAD_DEVICE, 'checksum': 'nothex'}),
        superuser)
    resp = mod.api_device_install_ipa(req)
    assert resp.status_code == 500
    assert _body(resp)['message'] == 'Invalid checksum format'


def test_install_ipa_valid_checksum_bad_device_500(rf, superuser):
    req = _authed(
        rf.post('/', {'device_id': BAD_DEVICE, 'checksum': VALID_MD5}),
        superuser)
    resp = mod.api_device_install_ipa(req)
    assert resp.status_code == 500
    assert _body(resp)['status'] == 'failed'


# ───────────────────────────────────────── api_device_dynamic_analyzer
def test_dynamic_analyzer_missing_params(rf):
    resp = mod.api_device_dynamic_analyzer(
        rf.post('/', {'device_id': BAD_DEVICE}))
    assert resp.status_code == 422
    assert _body(resp)['error'] == 'Missing Parameters'


def test_dynamic_analyzer_invalid_bundle_returns_200_error(rf, superuser):
    # Invalid bundle id is rejected inside dynamic_analyzer_device with an
    # {'error': ...} dict (no 'status' key), so the wrapper falls through
    # to the 200 return path.
    req = _authed(
        rf.post('/', {'device_id': BAD_DEVICE, 'bundle_id': 'not valid!!'}),
        superuser)
    resp = mod.api_device_dynamic_analyzer(req)
    assert resp.status_code == 200
    assert _body(resp)['error'] == 'Invalid iOS Bundle id'


# ───────────────────────────────────────── api_device_file_upload
def test_file_upload_missing_device_id(rf):
    resp = mod.api_device_file_upload(rf.post('/', {}))
    assert resp.status_code == 422
    assert _body(resp)['error'] == 'Missing Parameters'


def test_file_upload_missing_file(rf):
    resp = mod.api_device_file_upload(
        rf.post('/', {'device_id': BAD_DEVICE}))
    assert resp.status_code == 422
    assert _body(resp)['error'] == 'Missing File'


def test_file_upload_bad_device_500(rf, superuser):
    upload = SimpleUploadedFile(
        'payload.txt', b'hello real bytes', content_type='text/plain')
    req = _authed(
        rf.post('/', {'device_id': BAD_DEVICE, 'file': upload}),
        superuser)
    resp = mod.api_device_file_upload(req)
    assert resp.status_code == 500
    assert _body(resp)['status'] == 'failed'


# ───────────────────────────────────────── api_device_ssh_execute
def test_ssh_execute_missing_params(rf):
    resp = mod.api_device_ssh_execute(
        rf.post('/', {'device_id': BAD_DEVICE}))
    assert resp.status_code == 422
    assert _body(resp)['error'] == 'Missing Parameters'


def test_ssh_execute_allowed_cmd_bad_device_500(rf, superuser):
    # 'ls' is on the SSH allowlist, so execution proceeds to device
    # connect, which fails on the bad id -> status failed -> 500.
    req = _authed(
        rf.post('/', {'device_id': BAD_DEVICE, 'cmd': 'ls'}), superuser)
    resp = mod.api_device_ssh_execute(req)
    assert resp.status_code == 500
    assert _body(resp)['status'] == 'failed'


def test_ssh_execute_denied_cmd_returns_200(rf, superuser):
    # A command not on the allowlist yields a {'status': 'denied'} dict
    # (not 'failed'), so the wrapper returns 200.
    req = _authed(
        rf.post('/', {'device_id': BAD_DEVICE, 'cmd': 'rm -rf /'}), superuser)
    resp = mod.api_device_ssh_execute(req)
    assert resp.status_code == 200
    assert _body(resp)['status'] == 'denied'


# ───────────────────────────────────────── api_device_instrument
def test_instrument_missing_params(rf):
    resp = mod.api_device_instrument(
        rf.post('/', {'device_id': BAD_DEVICE, 'bundle_id': VALID_BUNDLE}))
    assert resp.status_code == 422
    assert _body(resp)['error'] == 'Missing Parameters'


def test_instrument_all_params_bad_device_500(rf, superuser):
    req = _authed(rf.post('/', {
        'device_id': BAD_DEVICE,
        'bundle_id': VALID_BUNDLE,
        'default_hooks': 'true',
        'dump_hooks': 'false',
        'auxiliary_hooks': '',
        'frida_code': '',
    }), superuser)
    resp = mod.api_device_instrument(req)
    assert resp.status_code == 500
    assert _body(resp)['status'] == 'failed'


# ───────────────────────────────────────── api_device_system_logs
def test_system_logs_missing_device_id(rf):
    resp = mod.api_device_system_logs(rf.post('/', {}))
    assert resp.status_code == 422
    assert _body(resp)['error'] == 'Missing Parameters'


def test_system_logs_bad_device_500(rf, superuser):
    req = _authed(rf.post('/', {'device_id': BAD_DEVICE}), superuser)
    resp = mod.api_device_system_logs(req)
    assert resp.status_code == 500
    assert _body(resp)['status'] == 'failed'


# ───────────────────────────────────────── api_device_ps
def test_ps_missing_device_id(rf):
    resp = mod.api_device_ps(rf.post('/', {}))
    assert resp.status_code == 422
    assert _body(resp)['error'] == 'Missing Parameters'


def test_ps_bad_device_500(rf, superuser):
    req = _authed(rf.post('/', {'device_id': BAD_DEVICE}), superuser)
    resp = mod.api_device_ps(req)
    assert resp.status_code == 500
    assert _body(resp)['status'] == 'failed'


# ───────────────────────────────────────── api_device_file_download
def test_file_download_missing_params(rf):
    resp = mod.api_device_file_download(
        rf.post('/', {'device_id': BAD_DEVICE}))
    assert resp.status_code == 422
    assert _body(resp)['error'] == 'Missing Parameters'


def test_file_download_bad_device_500(rf, superuser):
    req = _authed(
        rf.post('/', {'device_id': BAD_DEVICE, 'file': '/tmp/x'}), superuser)
    resp = mod.api_device_file_download(req)
    # No Content-Disposition header (it's a dict), status failed -> 500.
    assert resp.status_code == 500
    assert _body(resp)['status'] == 'failed'


# ───────────────────────────────────────── api_device_api_monitor
def test_api_monitor_missing_checksum(rf):
    resp = mod.api_device_api_monitor(rf.post('/', {}))
    assert resp.status_code == 422
    assert _body(resp)['error'] == 'Missing Parameters'


def test_api_monitor_invalid_checksum_500(rf):
    resp = mod.api_device_api_monitor(
        rf.post('/', {'checksum': 'nothex'}))
    assert resp.status_code == 500
    assert _body(resp)['message'] == 'Invalid checksum format'


def test_api_monitor_valid_checksum_no_data_returns_200(rf):
    # Valid md5 but no dump file on disk -> {'message': 'Data does not
    # exist.'} with no 'status' key -> wrapper returns 200.
    checksum = get_md5(b'no-such-app-data')
    resp = mod.api_device_api_monitor(
        rf.post('/', {'checksum': checksum}))
    assert resp.status_code == 200
    assert _body(resp)['message'] == 'Data does not exist.'


def test_api_monitor_with_real_dump_file_returns_200(rf, tmp_path):
    # Create a real dump file so the JSON-parsing branch runs and returns
    # parsed data (no 'status' key) -> 200.
    checksum = get_md5(b'has-real-dump-data')
    app_dir = Path(settings.UPLD_DIR) / checksum
    app_dir.mkdir(parents=True, exist_ok=True)
    dump = app_dir / 'mobinspect_dump_file.txt'
    dump.write_text(
        json.dumps({'cookies': 'c=1'}) + '\n'
        + json.dumps({'network': 'GET /'}) + '\n'
        + 'not-json-line\n',
        encoding='utf-8')
    try:
        resp = mod.api_device_api_monitor(
            rf.post('/', {'checksum': checksum}))
        assert resp.status_code == 200
        body = _body(resp)
        apis = {row['api'] for row in body['data']}
        assert 'Cookies' in apis
        assert 'Network Request' in apis
    finally:
        dump.unlink(missing_ok=True)
        try:
            app_dir.rmdir()
        except OSError:
            pass


# ───────────────────────────────────────── api_device_download_app_data
def test_download_app_data_missing_params(rf):
    resp = mod.api_device_download_app_data(
        rf.post('/', {'device_id': BAD_DEVICE}))
    assert resp.status_code == 422
    assert _body(resp)['error'] == 'Missing Parameters'


def test_download_app_data_bad_device_500(rf, superuser):
    req = _authed(
        rf.post('/', {'device_id': BAD_DEVICE, 'bundle_id': VALID_BUNDLE}),
        superuser)
    resp = mod.api_device_download_app_data(req)
    assert resp.status_code == 500
    assert _body(resp)['status'] == 'failed'


# ───────────────────────────────────────── api_device_report_json
def test_report_json_missing_params(rf):
    resp = mod.api_device_report_json(
        rf.post('/', {'device_id': BAD_DEVICE}))
    assert resp.status_code == 422
    assert _body(resp)['error'] == 'Missing Parameters'


def test_report_json_bad_device_500(rf, superuser):
    req = _authed(
        rf.post('/', {'device_id': BAD_DEVICE, 'bundle_id': VALID_BUNDLE}),
        superuser)
    resp = mod.api_device_report_json(req)
    # view_report_device rejects the malformed device id -> {'error': ...}
    # -> wrapper returns 500.
    assert resp.status_code == 500
    assert 'error' in _body(resp)


def test_report_json_success_with_real_local_data(rf, superuser):
    # KEY INSIGHT: unlike every other endpoint in this module,
    # view_report_device() never calls validate_and_connect_device() --
    # it only checks the device_id's REGEX FORMAT (no live SSH/USB
    # connection at all) and then reads real, purely local files under
    # UPLD_DIR. A real (empty) mobinspect_frida_out.txt is enough to pass
    # the "has dynamic analysis been run" gate and fall through to a real
    # (mostly-empty) success context with no 'error' key -> 200. This is
    # the ONE report/success branch in this module reachable without a
    # live jailbroken device.
    checksum = get_md5(VALID_BUNDLE.encode('utf-8'))
    app_dir = Path(settings.UPLD_DIR) / checksum
    app_dir.mkdir(parents=True, exist_ok=True)
    frida_log = app_dir / 'mobinspect_frida_out.txt'
    frida_log.write_text('', encoding='utf-8')
    try:
        req = _authed(
            rf.post('/', {
                'device_id': VALID_FORMAT_DEVICE,
                'bundle_id': VALID_BUNDLE}),
            superuser)
        resp = mod.api_device_report_json(req)
        assert resp.status_code == 200
        body = _body(resp)
        assert 'error' not in body
        assert body['bundleid'] == VALID_BUNDLE
        assert body['hash'] == checksum
    finally:
        frida_log.unlink(missing_ok=True)
        try:
            app_dir.rmdir()
        except OSError:
            pass
