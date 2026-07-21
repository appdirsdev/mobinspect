"""Page Object Model — Integrations page (`/rbac/integrations/adb/`).

Wraps the four fixed cards (Android device, iOS device, AI · Generation
model, AI · Classification model) described in
``mobinspect/templates/rbac/adb_connections.html``. See
``tests_e2e/ui/specs/test_integrations.py`` module docstring for the
idempotent-upsert semantics that make Save & Test safe to call repeatedly
against the shared dev server.
"""
from playwright.sync_api import expect

INTEGRATIONS_URL = '/rbac/integrations/adb/'

_MODEL_CARD_IDS = {
    'generate': 'card-generate',
    'classify': 'card-classify',
}
_MODEL_FIELD_PREFIX = {
    'generate': 'gen',
    'classify': 'clf',
}
_DEVICE_CARD_IDS = {
    'android': 'card-android',
    'ios': 'card-ios',
}
_DEVICE_FIELD_PREFIX = {
    'android': 'android',
    'ios': 'ios',
}


class IntegrationsPage:
    def __init__(self, page):
        self.page = page

    def goto(self):
        self.page.goto(INTEGRATIONS_URL, wait_until='domcontentloaded')
        return self

    # ─────────────────────────── model cards ───────────────────────────
    def model_card(self, role):
        return self.page.locator(f'#{_MODEL_CARD_IDS[role]}')

    def fill_model(self, role, base_url=None, model_name=None):
        card = self.model_card(role)
        prefix = _MODEL_FIELD_PREFIX[role]
        if base_url is not None:
            card.locator(f'#id_{prefix}_url').fill(base_url)
        if model_name is not None:
            card.locator(f'#id_{prefix}_model').fill(model_name)
        return self

    def save_model(self, role, base_url=None, model_name=None, expect_nav=True):
        """Fill (optionally) + click Save & Test on the model card.

        Returns the page (still on /rbac/integrations/adb/ after the
        server-side redirect, whether it succeeded or was rejected —
        both paths redirect back to this page with a Django message).
        """
        self.fill_model(role, base_url=base_url, model_name=model_name)
        card = self.model_card(role)
        save_btn = card.locator('button[type=submit]', has_text='Save')
        if expect_nav:
            with self.page.expect_navigation(wait_until='domcontentloaded'):
                save_btn.click()
        else:
            save_btn.click()
        return self

    def test_model(self, role, base_url=None, model_name=None):
        """Click the inline AJAX Test button for a model card, waiting for
        the underlying POST to `/rbac/integrations/model/<role>/test/` to
        settle. Returns the parsed JSON body."""
        self.fill_model(role, base_url=base_url, model_name=model_name)
        card = self.model_card(role)
        test_btn = card.locator('button.js-int-test')
        with self.page.expect_response(
                lambda r: f'/rbac/integrations/model/{role}/test/' in r.url
                and r.request.method == 'POST') as resp_info:
            test_btn.click()
        return resp_info.value

    def model_status_badge(self, role):
        return self.model_card(role).locator('[data-cell="status"] .badge')

    def model_url_value(self, role):
        prefix = _MODEL_FIELD_PREFIX[role]
        return self.model_card(role).locator(f'#id_{prefix}_url').input_value()

    def model_name_value(self, role):
        prefix = _MODEL_FIELD_PREFIX[role]
        return self.model_card(role).locator(f'#id_{prefix}_model').input_value()

    # ─────────────────────────── device cards ───────────────────────────
    def device_card(self, platform):
        return self.page.locator(f'#{_DEVICE_CARD_IDS[platform]}')

    def fill_adb(self, platform, host_port):
        prefix = _DEVICE_FIELD_PREFIX[platform]
        self.device_card(platform).locator(f'#id_{prefix}_host').fill(host_port)
        return self

    def save_adb(self, platform, host_port=None, expect_nav=True):
        if host_port is not None:
            self.fill_adb(platform, host_port)
        card = self.device_card(platform)
        save_btn = card.locator('button[type=submit]', has_text='Save')
        if expect_nav:
            with self.page.expect_navigation(wait_until='domcontentloaded'):
                save_btn.click()
        else:
            save_btn.click()
        return self

    def test_adb(self, platform, host_port=None):
        """Click the inline AJAX Test button for a device card, waiting for
        the underlying POST to settle. Returns the parsed JSON body."""
        if host_port is not None:
            self.fill_adb(platform, host_port)
        card = self.device_card(platform)
        test_btn = card.locator('button.js-int-test')
        with self.page.expect_response(
                lambda r: f'/rbac/integrations/device/{platform}/test/' in r.url
                and r.request.method == 'POST') as resp_info:
            test_btn.click()
        return resp_info.value

    def device_status_badge(self, platform):
        return self.device_card(platform).locator('[data-cell="status"] .badge')

    def device_host_value(self, platform):
        prefix = _DEVICE_FIELD_PREFIX[platform]
        return self.device_card(platform).locator(f'#id_{prefix}_host').input_value()

    # ─────────────────────────── shared toast helper ───────────────────
    def toast_text(self):
        return self.page.locator('#mi-toasts').inner_text()
