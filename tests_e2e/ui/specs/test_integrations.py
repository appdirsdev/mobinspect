"""UI spec for the Integrations page (`/rbac/integrations/adb/`).

Covers the four fixed, self-contained integration cards defined in
``mobinspect/templates/rbac/adb_connections.html``:

    1. Android device            (adb host:port)
    2. iOS device                (SSH host:port)
    3. AI · Generation model     (endpoint + model name)
    4. AI · Classification model (endpoint + model name)

There is intentionally NO listing table on this page (that's the legacy
``integrations/adb/add`` / by-id flow, superseded by these four fixed
cards) — tests assert the table is absent.

"Save & Test" is a server-side upsert keyed by platform/role (one row per
platform, one row per model role), so re-submitting the Android or
Generation-model card with the same values is idempotent and safe to run
repeatedly against the shared dev server. The inline ".js-int-test" button
is a read-only AJAX probe (POST with no body) that never mutates the saved
host_port / endpoint — only the last_status* bookkeeping columns.
"""
import json
import re
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from playwright.sync_api import expect

from tests_e2e.ui.pages.integrations_page import IntegrationsPage

INTEGRATIONS_URL = '/rbac/integrations/adb/'

CARD_TITLES = [
    'Android device',
    'iOS device',
    'AI · Generation model',
    'AI · Classification model',
]

# Any status pill the server may render for a freshly-tested integration.
# (No real adb / Ollama endpoint is guaranteed to be reachable in CI, so we
# accept the full set of legitimate outcomes rather than asserting a single
# status — what matters is that testing occurred and updated the pill.)
KNOWN_STATUS_TEXT = re.compile(
    r'Connected|Failed|Timeout|Not configured|Untested')


def _assert_no_traceback(page):
    assert 'Traceback (most recent call last)' not in page.content()


@pytest.mark.positive
def test_integrations_page_shows_exactly_four_fixed_cards(admin_page):
    """The page renders exactly the 4 fixed integration cards, no table."""
    page = admin_page
    page.goto(INTEGRATIONS_URL, wait_until='domcontentloaded')

    expect(page.locator('h1', has_text='Integrations')).to_be_visible()

    # The four fixed cards, by id, each carrying its expected heading text.
    card_ids = ['card-android', 'card-ios', 'card-generate', 'card-classify']
    for card_id, title in zip(card_ids, CARD_TITLES):
        card = page.locator(f'#{card_id}')
        expect(card).to_be_visible()
        expect(card.locator('h3.text-h4')).to_have_text(title)

    # Exactly 4 cards inside the integrations grid — no 5th / legacy card.
    grid_cards = page.locator(
        '.grid.grid-cols-1.xl\\:grid-cols-2 > div.card')
    expect(grid_cards).to_have_count(4)

    # No listing table anywhere on this page (superseded by fixed cards).
    expect(page.locator('table')).to_have_count(0)

    _assert_no_traceback(page)


@pytest.mark.positive
def test_android_card_has_expected_controls(admin_page):
    """Android card exposes the host:port input + inline Test + Save & Test."""
    page = admin_page
    page.goto(INTEGRATIONS_URL, wait_until='domcontentloaded')

    card = page.locator('#card-android')
    expect(card).to_be_visible()
    expect(card.locator('#id_android_host')).to_be_visible()
    expect(card.locator('#id_android_host')).to_have_attribute(
        'placeholder', '192.168.1.100:5555')

    test_btn = card.locator('button.js-int-test')
    expect(test_btn).to_be_visible()
    expect(test_btn).to_have_attribute('data-card', 'card-android')

    save_btn = card.locator('button[type=submit]', has_text='Save')
    expect(save_btn).to_be_visible()

    # Status pill + "last checked" cell are present (some badge, any status).
    expect(card.locator('[data-cell="status"] .badge')).to_be_visible()
    expect(card.locator('[data-cell="last-checked"]')).to_be_visible()

    _assert_no_traceback(page)


@pytest.mark.positive
def test_android_card_save_and_test_persists_and_updates_status(admin_page):
    """Filling + Save&Test the Android card upserts the row (idempotent) and
    the value survives the resulting page reload, with a status pill shown."""
    page = admin_page
    page.goto(INTEGRATIONS_URL, wait_until='domcontentloaded')

    card = page.locator('#card-android')
    host_input = card.locator('#id_android_host')
    host_input.fill('127.0.0.1:5555')

    save_btn = card.locator('button[type=submit]', has_text='Save')
    with page.expect_navigation(wait_until='domcontentloaded'):
        save_btn.click()

    # Redirected back to the Integrations page (device_save -> redirect).
    expect(page).to_have_url(re.compile(r'/rbac/integrations/adb/$'))

    # A success toast for the save is rendered via Django messages.
    expect(page.locator('#mi-toasts')).to_contain_text('Android device saved.')

    # The value persisted through the save + redirect + re-render cycle.
    card = page.locator('#card-android')
    expect(card.locator('#id_android_host')).to_have_value('127.0.0.1:5555')

    # A status pill is shown (adb ran a connect attempt as part of the save).
    status_badge = card.locator('[data-cell="status"] .badge')
    expect(status_badge).to_be_visible()
    expect(status_badge).to_have_text(KNOWN_STATUS_TEXT)

    # "Never tested" placeholder must have been replaced by a real timestamp.
    expect(card.locator('[data-cell="last-checked"]')).to_contain_text('Checked')

    _assert_no_traceback(page)


@pytest.mark.positive
def test_android_card_inline_test_button_updates_status_or_toast(admin_page):
    """Clicking the inline .js-int-test AJAX probe on the Android card either
    shows a toast or patches the status pill in place (no full reload)."""
    page = admin_page
    page.goto(INTEGRATIONS_URL, wait_until='domcontentloaded')

    card = page.locator('#card-android')
    test_btn = card.locator('button.js-int-test')
    label = test_btn.locator('.js-int-test-label')
    expect(label).to_have_text('Test')

    # Wait for the underlying AJAX POST to the per-platform test endpoint
    # to complete so we assert on settled state, not a mid-flight one.
    with page.expect_response(
            lambda r: '/rbac/integrations/device/android/test/' in r.url
            and r.request.method == 'POST') as resp_info:
        test_btn.click()
    response = resp_info.value
    assert response.status == 200
    body = response.json()
    assert 'status' in body

    # Button re-enables and its label reverts once the request settles.
    expect(label).to_have_text('Test')
    expect(test_btn).to_be_enabled()

    # Either a toast announced the outcome, or the pill now reflects it
    # (the page JS does both, but assert on the toast which is unambiguous).
    toast = page.locator('#mi-toasts .card p.text-small').last
    expect(toast).to_be_visible()
    expect(toast).to_have_text(re.compile(r'Connected:|Test failed:'))

    # Status pill reflects a known status value after the probe.
    status_badge = card.locator('[data-cell="status"] .badge')
    expect(status_badge).to_have_text(KNOWN_STATUS_TEXT)

    _assert_no_traceback(page)


@pytest.mark.positive
def test_ios_card_has_expected_controls(admin_page):
    """iOS card renders with its own host:port input, distinct placeholder."""
    page = admin_page
    page.goto(INTEGRATIONS_URL, wait_until='domcontentloaded')

    card = page.locator('#card-ios')
    expect(card).to_be_visible()
    host_input = card.locator('#id_ios_host')
    expect(host_input).to_be_visible()
    expect(host_input).to_have_attribute('placeholder', '192.168.1.120:22')

    expect(card.locator('button.js-int-test')).to_have_attribute(
        'data-card', 'card-ios')
    expect(card.locator('button[type=submit]', has_text='Save')).to_be_visible()
    expect(card.locator('[data-cell="status"] .badge')).to_be_visible()

    _assert_no_traceback(page)


@pytest.mark.positive
def test_generation_model_card_save_and_test_persists_and_updates_status(
        admin_page):
    """Filling + Save&Test the Generation-model card upserts that role's row
    (idempotent) and both endpoint + model persist after the reload."""
    page = admin_page
    page.goto(INTEGRATIONS_URL, wait_until='domcontentloaded')

    card = page.locator('#card-generate')
    expect(card.locator('h3.text-h4')).to_have_text('AI · Generation model')

    url_input = card.locator('#id_gen_url')
    model_input = card.locator('#id_gen_model')
    url_input.fill('http://127.0.0.1:11500')
    model_input.fill('granite4:3b')

    save_btn = card.locator('button[type=submit]', has_text='Save')
    with page.expect_navigation(wait_until='domcontentloaded'):
        save_btn.click()

    expect(page).to_have_url(re.compile(r'/rbac/integrations/adb/$'))
    expect(page.locator('#mi-toasts')).to_contain_text(
        'Generation model saved.')

    card = page.locator('#card-generate')
    expect(card.locator('#id_gen_url')).to_have_value('http://127.0.0.1:11500')
    expect(card.locator('#id_gen_model')).to_have_value('granite4:3b')

    status_badge = card.locator('[data-cell="status"] .badge')
    expect(status_badge).to_be_visible()
    expect(status_badge).to_have_text(KNOWN_STATUS_TEXT)
    expect(card.locator('[data-cell="last-checked"]')).to_contain_text('Checked')

    _assert_no_traceback(page)


@pytest.mark.positive
def test_classification_model_card_has_expected_controls(admin_page):
    """Classification-model card renders with its own endpoint/model inputs
    (not exercised via Save&Test here — Generation-model flow above already
    proves the shared model_save/model_test code path end to end)."""
    page = admin_page
    page.goto(INTEGRATIONS_URL, wait_until='domcontentloaded')

    card = page.locator('#card-classify')
    expect(card).to_be_visible()
    expect(card.locator('h3.text-h4')).to_have_text('AI · Classification model')
    expect(card.locator('#id_clf_url')).to_be_visible()
    expect(card.locator('#id_clf_model')).to_be_visible()
    expect(card.locator('button.js-int-test')).to_have_attribute(
        'data-card', 'card-classify')
    expect(card.locator('button[type=submit]', has_text='Save')).to_be_visible()
    expect(card.locator('[data-cell="status"] .badge')).to_be_visible()

    _assert_no_traceback(page)


# ═══════════════════════ negative: model integration validation ═══════════
# RBAC/views.py::model_save (and the AJAX twin model_test_key, which shares
# _probe_model_endpoint) enforce three checks before ever writing a DB row:
#   1. parse_ai_endpoint() rejects a malformed URL,
#   2. an empty model name is rejected,
#   3. _host_is_enclave() rejects a host that isn't loopback/private -- a real
#      security control (no exfiltrating scan data to a public endpoint).
# All three redirect back to the Integrations page with a Django message
# rendered into #mi-toasts (see model_save, RBAC/views.py:571-599) rather
# than persisting anything, so these tests never mutate the shared
# gen_model / classify_model rows.

@pytest.mark.negative
def test_model_save_rejects_non_enclave_public_host(admin_page):
    """A public (non-enclave) host must be REJECTED by model_save, not
    silently accepted -- see RBAC/views.py::model_save -> _host_is_enclave."""
    page = admin_page
    ip = IntegrationsPage(page).goto()

    before_url = ip.model_url_value('classify')
    before_model = ip.model_name_value('classify')

    ip.save_model('classify', base_url='http://8.8.8.8:11434',
                  model_name='granite4:3b')

    expect(page).to_have_url(re.compile(r'/rbac/integrations/adb/$'))
    expect(page.locator('#mi-toasts')).to_contain_text(
        'Endpoint host must be loopback or a private/in-enclave address.')

    # Rejected input was never persisted -- the card still shows whatever was
    # saved before this test ran (not the rejected public host).
    ip2 = IntegrationsPage(page)
    assert ip2.model_url_value('classify') == before_url
    assert ip2.model_name_value('classify') == before_model
    assert ip2.model_url_value('classify') != 'http://8.8.8.8:11434'

    _assert_no_traceback(page)


@pytest.mark.negative
def test_model_save_rejects_malformed_url(admin_page):
    """A non-URL string must be rejected by parse_ai_endpoint(), not crash."""
    page = admin_page
    ip = IntegrationsPage(page).goto()

    before_url = ip.model_url_value('classify')

    ip.save_model('classify', base_url='not-a-url', model_name='granite4:3b')

    expect(page).to_have_url(re.compile(r'/rbac/integrations/adb/$'))
    expect(page.locator('#mi-toasts')).to_contain_text(
        'Provide a valid endpoint (http(s)://host:port) and a model.')

    assert IntegrationsPage(page).model_url_value('classify') == before_url

    _assert_no_traceback(page)


@pytest.mark.negative
def test_model_save_rejects_empty_model_name(admin_page):
    """A valid enclave endpoint with an empty model name must be rejected --
    model_save requires both fields together (RBAC/views.py:580)."""
    page = admin_page
    ip = IntegrationsPage(page).goto()

    before_model = ip.model_name_value('classify')

    ip.save_model('classify', base_url='http://127.0.0.1:11434', model_name='')

    expect(page).to_have_url(re.compile(r'/rbac/integrations/adb/$'))
    expect(page.locator('#mi-toasts')).to_contain_text(
        'Provide a valid endpoint (http(s)://host:port) and a model.')

    assert IntegrationsPage(page).model_name_value('classify') == before_model

    _assert_no_traceback(page)


@pytest.mark.negative
def test_adb_save_rejects_invalid_host_port(admin_page):
    """An address that doesn't match host:port / [ipv6]:port must be
    rejected by _validate_host_port (RBAC/views.py:394), not saved. Uses the
    iOS card, which has no saved row yet in this environment, so a clean
    'Invalid device address' message with nothing persisted is verifiable."""
    page = admin_page
    ip = IntegrationsPage(page).goto()

    ip.save_adb('ios', host_port='not-a-host-port')

    expect(page).to_have_url(re.compile(r'/rbac/integrations/adb/$'))
    expect(page.locator('#mi-toasts')).to_contain_text(
        'Invalid device address. Use host:port or [ipv6]:port')

    assert IntegrationsPage(page).device_host_value('ios') != 'not-a-host-port'

    _assert_no_traceback(page)


# ═══════════════ regression: model status pills differentiate states ══════
# _apply_model_probe / _probe_model_endpoint (RBAC/views.py:730-785) return
# one of STATUS_CONNECTED / STATUS_FAILED / STATUS_TIMEOUT, and the template
# (rbac/_integration_status.html) renders a DISTINCT pill per status, plus a
# 5th "Not configured" pill when no row exists at all (`status=='notset'`) --
# these must never collapse into one generic "Untested" state.

class _FakeOllamaHandler(BaseHTTPRequestHandler):
    """Minimal stand-in for a real Ollama host's /api/tags -- the AI model
    provider is the external system this integration probes; simulating
    *it* (not the MobInspect app/server, which stays real) is the only way
    to deterministically exercise the STATUS_CONNECTED branch of
    _probe_model_endpoint without a real GPU host on the test machine."""

    def do_GET(self):
        if self.path == '/api/tags':
            body = json.dumps({'models': [{'name': 'granite4.1:3b'}]}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):  # silence default stderr logging
        pass


@contextmanager
def _fake_ollama_server():
    httpd = HTTPServer(('127.0.0.1', 0), _FakeOllamaHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{port}'
    finally:
        httpd.shutdown()
        thread.join(timeout=5)


@pytest.mark.regression
def test_model_status_pill_differentiates_connected_failed_and_notset(
        admin_page):
    """Three real, distinct pill states on the same page load:

    1. iOS device card has no AdbConnection row in this environment -> the
       'notset' branch renders 'Not configured' (not 'Untested').
    2. The inline Test AJAX probe against a real local HTTP server that
       speaks the Ollama /api/tags contract returns STATUS_CONNECTED and
       patches the pill to 'Connected'.
    3. The same probe against an address nothing listens on returns
       STATUS_FAILED and patches the pill to 'Failed' -- a different pill,
       not the same 'Untested' bucket as case 1.
    """
    page = admin_page
    ip = IntegrationsPage(page).goto()

    # 1. Not configured (no AdbConnection row for iOS).
    ios_badge = ip.device_status_badge('ios')
    expect(ios_badge).to_have_text('Not configured')
    expect(ios_badge).to_have_class(re.compile('badge-unknown'))

    # 2. Connected -- probe a real local fake-Ollama HTTP server.
    with _fake_ollama_server() as base_url:
        resp = ip.test_model('classify', base_url=base_url,
                             model_name='granite4.1:3b')
        assert resp.status == 200
        body = resp.json()
        assert body['status'] == 'connected', body
        assert body['success'] is True

        connected_badge = ip.model_status_badge('classify')
        expect(connected_badge).to_have_text('Connected')
        expect(connected_badge).to_have_class(re.compile('badge-passed'))

    # 3. Failed -- probe a loopback port nothing is listening on. Test is
    # typed/unsaved (model_test_key never persists a posted value -- see
    # RBAC/views.py:662-691), so this cannot collide with a real service.
    resp = ip.test_model('classify', base_url='http://127.0.0.1:1',
                         model_name='granite4.1:3b')
    assert resp.status == 200
    body = resp.json()
    assert body['status'] == 'failed', body
    assert body['success'] is False

    failed_badge = ip.model_status_badge('classify')
    expect(failed_badge).to_have_text('Failed')
    expect(failed_badge).to_have_class(re.compile('badge-critical'))

    _assert_no_traceback(page)
