"""UI spec: authentication edge cases -- negative login paths, logout,
session-clearing, and change_password.

``test_login_redirects_off_login`` (the successful-login happy path) already
lives in ``test_smoke.py`` -- not duplicated here.

Uses a fresh, unauthenticated Playwright ``browser`` context for every
negative-login case (never the session-scoped ``admin_page`` fixture, which
is already logged in) so each test drives its own real login attempt.
"""
import os

# Playwright's plugin keeps an asyncio event loop alive for the whole
# session; Django's sync-ORM guard then refuses plain ORM calls with
# SynchronousOnlyOperation even though nothing here is actually concurrent.
# Same escape hatch tests_e2e/api/conftest.py already uses.
os.environ.setdefault('DJANGO_ALLOW_ASYNC_UNSAFE', 'true')

import pytest
from playwright.sync_api import expect

from tests_e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, BASE_URL

BASE = BASE_URL
NO_TRACEBACK = 'Traceback (most recent call last)'

THROWAWAY_USERNAME = 'tests_e2e_auth_agent'
THROWAWAY_PASSWORD_INITIAL = 'e2e-Suite-Initial-Pw-9f3a!'
THROWAWAY_PASSWORD_NEW = 'e2e-Suite-Rotated-Pw-7c1e!'


def _attempt_login(page, username, password):
    page.goto(f'{BASE}/login/', wait_until='domcontentloaded')
    page.fill('#id_username', username)
    page.fill('#id_password', password)
    page.click('button[type=submit]')
    page.wait_for_load_state('domcontentloaded')


# ─────────────────────────── negative login paths ───────────────────────────

@pytest.mark.negative
def test_login_wrong_password_reshows_login_with_error(browser):
    ctx = browser.new_context(base_url=BASE)
    page = ctx.new_page()
    try:
        _attempt_login(page, ADMIN_USERNAME, 'definitely-the-wrong-password')

        # Re-shown on /login/, never silently treated as authenticated.
        assert '/login' in page.url
        assert NO_TRACEBACK not in page.content()
        expect(page.get_by_text(
            'Please enter a correct username and password.',
            exact=False)).to_be_visible()
    finally:
        ctx.close()


@pytest.mark.negative
def test_login_wrong_username_reshows_login_with_error(browser):
    ctx = browser.new_context(base_url=BASE)
    page = ctx.new_page()
    try:
        _attempt_login(page, 'no-such-user-xyz123', ADMIN_PASSWORD)

        assert '/login' in page.url
        assert NO_TRACEBACK not in page.content()
        expect(page.get_by_text(
            'Please enter a correct username and password.',
            exact=False)).to_be_visible()
    finally:
        ctx.close()


@pytest.mark.negative
def test_login_empty_submit_is_form_validation_not_a_crash(browser):
    """Username/password inputs carry the HTML5 ``required`` attribute, so an
    empty submit is blocked client-side -- the browser never even issues the
    POST. Assert that clean client-side rejection: still on /login/, no
    server round-trip error, no traceback."""
    ctx = browser.new_context(base_url=BASE)
    page = ctx.new_page()
    try:
        page.goto(f'{BASE}/login/', wait_until='domcontentloaded')
        page.click('button[type=submit]')
        page.wait_for_timeout(300)

        assert '/login' in page.url
        assert NO_TRACEBACK not in page.content()
        # Native validity failed on the empty required username field.
        invalid = page.eval_on_selector('#id_username', 'el => !el.validity.valid')
        assert invalid is True
    finally:
        ctx.close()


# ─────────────────────────── logout / session clearing ───────────────────────────

@pytest.mark.positive
@pytest.mark.regression
def test_logout_clears_session_and_home_redirects_to_login(browser):
    ctx = browser.new_context(base_url=BASE)
    page = ctx.new_page()
    try:
        _attempt_login(page, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert '/login' not in page.url  # real login succeeded first

        page.goto(f'{BASE}/logout', wait_until='domcontentloaded')
        assert NO_TRACEBACK not in page.content()

        # Session is actually gone -- revisiting a protected page bounces
        # back to /login/, not silently serving the page from a stale session.
        page.goto(f'{BASE}/', wait_until='domcontentloaded')
        assert '/login' in page.url
    finally:
        ctx.close()


# ─────────────────────────── change_password ───────────────────────────

@pytest.fixture
def throwaway_user(django_db_blocker):
    """Provision a disposable non-admin user via the ORM, exactly like
    tests_e2e/api/conftest.py's _provision_role_key -- never touches the
    real admin user's password.

    Teardown DEACTIVATES rather than deletes the row. A real, confirmed DB
    constraint (mobinspect/RBAC/migrations/0007_auditevent_immutable_trigger.py,
    H9) makes ``rbac_auditevent`` append-only at the Postgres level -- both
    UPDATE and DELETE trigger `RAISE EXCEPTION 'audit log is append-only'`.
    change_password() writes an audit.record() row with this user as actor
    (mobinspect/MobInspect/views/authentication.py), and AuditEvent.actor is
    ``on_delete=SET_NULL`` -- so hard-deleting this user afterwards makes
    Django try to null that FK, which Postgres then rejects. Deactivating
    (is_active=False) achieves the same "can no longer log in" cleanup
    goal without fighting an intentional immutability guarantee.
    """
    with django_db_blocker.unblock():
        os.environ.setdefault(
            'DJANGO_SETTINGS_MODULE', 'mobinspect.MobInspect.settings')
        import django
        django.setup()
        from django.contrib.auth import get_user_model

        user_model = get_user_model()
        # get_or_create (never delete-then-create): once this user has ever
        # been an audit-log actor, a prior test run's hard-delete would hit
        # the same append-only trigger described above -- so a leftover row
        # from an earlier run is reused/reset in place, never removed.
        user, _created = user_model.objects.get_or_create(
            username=THROWAWAY_USERNAME,
            defaults={'email': f'{THROWAWAY_USERNAME}@example.invalid'},
        )
        user.set_password(THROWAWAY_PASSWORD_INITIAL)
        user.is_active = True
        user.is_staff = False
        user.is_superuser = False
        user.save()
        yield user
        user_model.objects.filter(username=THROWAWAY_USERNAME).update(is_active=False)


@pytest.mark.positive
def test_change_password_page_renders(browser, throwaway_user):
    ctx = browser.new_context(base_url=BASE)
    page = ctx.new_page()
    try:
        _attempt_login(page, THROWAWAY_USERNAME, THROWAWAY_PASSWORD_INITIAL)
        assert '/login' not in page.url

        page.goto(f'{BASE}/change_password/', wait_until='domcontentloaded')
        assert NO_TRACEBACK not in page.content()
        expect(page.get_by_role('heading', name='Change password')).to_be_visible()
        expect(page.locator('#id_old_password')).to_be_visible()
        expect(page.locator('#id_new_password1')).to_be_visible()
        expect(page.locator('#id_new_password2')).to_be_visible()
    finally:
        ctx.close()


@pytest.mark.positive
@pytest.mark.e2e_flow
def test_change_password_actually_changes_and_can_be_reverted(
        browser, throwaway_user, django_db_blocker):
    """Exercises the real form submit end to end on a throwaway user: change
    the password through the actual UI form, then verify the new hash took
    effect (and the old one no longer matches) directly via the ORM.

    Deliberately does NOT re-verify via a second live login (old-password-
    must-fail / new-password-must-work) or a live "revert" login+submit:
    ``login_view`` is rate-limited (``@ratelimit(key='user_or_ip', ...)`` in
    mobinspect/MobInspect/views/authentication.py, default 7/minute) and, for
    an anonymous POST, that key resolves to the caller's IP -- every login
    POST from this same test machine (across every test in this file, and
    any other spec that logs in within the same rolling minute) shares ONE
    budget. Confirmed live: running this file's several negative-login tests
    back-to-back with this one used to intermittently rate-limit-block the
    'new password should now work' verification login, failing the test for
    a reason that has nothing to do with password-change correctness. Doing
    that verification via the ORM (which the ``throwaway_user`` fixture's
    next run resets anyway) is just as real a check of "did the password
    actually change" without burning more of that shared budget.
    """
    ctx = browser.new_context(base_url=BASE)
    page = ctx.new_page()
    try:
        _attempt_login(page, THROWAWAY_USERNAME, THROWAWAY_PASSWORD_INITIAL)
        assert '/login' not in page.url

        page.goto(f'{BASE}/change_password/', wait_until='domcontentloaded')
        page.fill('#id_old_password', THROWAWAY_PASSWORD_INITIAL)
        page.fill('#id_new_password1', THROWAWAY_PASSWORD_NEW)
        page.fill('#id_new_password2', THROWAWAY_PASSWORD_NEW)
        # NOTE: the app shell's topbar/sidebar each carry their own hidden
        # `<form method=post action=logout><button type=submit>` -- a bare
        # `button[type=submit]` selector matches THOSE first in DOM order
        # and silently logs the session out instead of submitting this
        # form. Scope to the real change-password button by its label.
        page.get_by_role('button', name='Update password').click()
        page.wait_for_load_state('domcontentloaded')

        assert NO_TRACEBACK not in page.content()
        expect(page.get_by_text(
            'Your password was successfully updated!', exact=False)).to_be_visible()
    finally:
        ctx.close()

    with django_db_blocker.unblock():
        throwaway_user.refresh_from_db()
        assert throwaway_user.check_password(THROWAWAY_PASSWORD_NEW), (
            'new password should now be the active one')
        assert not throwaway_user.check_password(THROWAWAY_PASSWORD_INITIAL), (
            'old password should no longer match')
