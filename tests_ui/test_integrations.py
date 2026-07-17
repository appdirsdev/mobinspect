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
import re

from playwright.sync_api import expect

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
