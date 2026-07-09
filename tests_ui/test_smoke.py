"""Smoke test — proves the harness (server up, login works, home renders)."""
from playwright.sync_api import expect


def test_login_redirects_off_login(admin_page):
    assert '/login' not in admin_page.url


def test_home_dashboard_renders(admin_page):
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')
    # creative dashboard hallmarks
    expect(page.locator('text=Total scans').first).to_be_visible()
    expect(page.locator('#upload_form')).to_be_attached()
    # no server-error / traceback leaked into the page
    assert 'Traceback (most recent call last)' not in page.content()


def test_theme_defaults_to_dark_for_a_first_time_visitor(admin_page):
    """A visitor who has never touched the sun/moon toggle (no 'mi-theme' in
    localStorage) must land on dark — the dashboard's design is dark-first
    and the reference it's modeled on has no light variant. The toggle must
    still let them switch away; this only pins the *default*."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')
    page.evaluate("localStorage.removeItem('mi-theme')")
    page.reload(wait_until='domcontentloaded')
    theme = page.locator('html').get_attribute('data-theme')
    assert theme == 'dark', f'expected dark by default, got {theme!r}'
    pref = page.locator('html').get_attribute('data-theme-pref')
    assert pref == 'dark', f'expected pref=dark, got {pref!r}'


def test_theme_toggle_still_cycles_and_persists(admin_page):
    """Dark-by-default must not break the toggle: light must still be
    reachable, and the choice must persist across a reload."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')
    page.evaluate("localStorage.removeItem('mi-theme')")
    page.reload(wait_until='domcontentloaded')

    # Two real toggles exist now (topbar + sidebar bottom group) — both
    # drive the same shared window.MI.theme.cycle(); test one, which proves
    # the underlying behavior for both.
    toggle = page.get_by_label('Toggle theme').first
    expect(toggle).to_be_visible()

    # cycle order is light -> dark -> system -> light...; starting from the
    # default 'dark' (unstored), one click lands on 'system' next.
    toggle.click()
    expect(page.locator('html')).to_have_attribute('data-theme-pref', 'system')
    assert page.evaluate("localStorage.getItem('mi-theme')") == 'system'

    # system -> light
    toggle.click()
    expect(page.locator('html')).to_have_attribute('data-theme', 'light')
    assert page.evaluate("localStorage.getItem('mi-theme')") == 'light'

    # light -> dark
    toggle.click()
    expect(page.locator('html')).to_have_attribute('data-theme', 'dark')
    assert page.evaluate("localStorage.getItem('mi-theme')") == 'dark'

    # explicit choice survives a reload
    page.reload(wait_until='domcontentloaded')
    expect(page.locator('html')).to_have_attribute('data-theme', 'dark')


def test_both_theme_toggles_stay_in_sync(admin_page):
    """Two independent toggle buttons exist now (sidebar + topbar), each its
    own isolated Alpine component. Clicking one must update the other's
    displayed icon/title immediately (via the shared mi:theme-change window
    event), not just on the next full reload — otherwise they'd visibly
    disagree about the current theme until the user navigates away."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')
    page.evaluate("localStorage.removeItem('mi-theme')")
    page.reload(wait_until='domcontentloaded')

    toggles = page.get_by_label('Toggle theme')
    expect(toggles).to_have_count(2)
    first, second = toggles.first, toggles.nth(1)

    expect(first).to_have_attribute('title', 'Theme: dark')
    expect(second).to_have_attribute('title', 'Theme: dark')

    first.click()  # dark -> system, via the FIRST button only
    expect(first).to_have_attribute('title', 'Theme: system')
    expect(second).to_have_attribute('title', 'Theme: system')  # synced, no reload

    second.click()  # system -> light, via the SECOND button only
    expect(second).to_have_attribute('title', 'Theme: light')
    expect(first).to_have_attribute('title', 'Theme: light')  # synced back
