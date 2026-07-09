"""Playwright UI (end-to-end) test harness for MobInspect.

These tests drive a REAL running MobInspect server with a headless browser.
They are intentionally OUTSIDE pyproject `testpaths` so the normal unit suite
never collects them; run them explicitly, e.g.:

    poetry run pytest tests_ui/ --browser chromium -q

Environment:
    MOBINSPECT_UI_BASE       base URL of a running server (default 127.0.0.1:8000)
    MOBINSPECT_ADMIN_USERNAME / MOBINSPECT_ADMIN_PASSWORD  admin creds (admin/admin)

The `admin_page` fixture returns a logged-in Playwright Page; `admin_context`
gives a reusable authenticated storage state for the whole session so we don't
re-login for every test.
"""
import os

import pytest

BASE = os.environ.get('MOBINSPECT_UI_BASE', 'http://127.0.0.1:8000').rstrip('/')
USER = os.environ.get('MOBINSPECT_ADMIN_USERNAME', 'admin')
PWD = os.environ.get('MOBINSPECT_ADMIN_PASSWORD', 'admin')


@pytest.fixture(scope='session')
def base_url():
    return BASE


def _login(page):
    page.goto(f'{BASE}/login/', wait_until='domcontentloaded')
    page.fill('#id_username', USER)
    page.fill('#id_password', PWD)
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
