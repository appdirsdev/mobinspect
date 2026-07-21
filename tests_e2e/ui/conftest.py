"""Playwright UI (end-to-end) test harness for MobInspect.

These tests drive a REAL running MobInspect server with a headless browser.
See ``tests_e2e/README.md`` for how to start one and run the suite.

The `admin_page` fixture returns a logged-in Playwright Page; `admin_context`
gives a reusable authenticated storage state for the whole session so we
don't re-login for every test.
"""
import pytest

from tests_e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, BASE_URL

BASE = BASE_URL
USER = ADMIN_USERNAME
PWD = ADMIN_PASSWORD


@pytest.fixture(scope='session')
def base_url():
    return BASE


def _login(page, username=USER, password=PWD):
    page.goto(f'{BASE}/login/', wait_until='domcontentloaded')
    page.fill('#id_username', username)
    page.fill('#id_password', password)
    page.click('button[type=submit]')
    page.wait_for_url(lambda u: '/login' not in u, timeout=20000)


@pytest.fixture(scope='session')
def storage_state(browser, tmp_path_factory):
    """Log in once per session (via the plugin's browser fixture) and persist
    the auth cookies to a Playwright storage-state file for reuse."""
    state = tmp_path_factory.mktemp('pw') / 'admin_state.json'
    ctx = browser.new_context(base_url=BASE)
    page = ctx.new_page()
    _login(page)
    ctx.storage_state(path=str(state))
    ctx.close()
    return str(state)


@pytest.fixture
def admin_context(browser, storage_state):
    """A browser context already authenticated as admin (reuses session state)."""
    ctx = browser.new_context(storage_state=storage_state, base_url=BASE)
    yield ctx
    ctx.close()


@pytest.fixture
def admin_page(admin_context):
    page = admin_context.new_page()
    yield page
    page.close()
