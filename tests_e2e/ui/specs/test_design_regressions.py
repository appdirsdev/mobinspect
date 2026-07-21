"""Computed-style regression tests for the design-system's fixed points.

These pin down actual CSS custom-property/token drift, not just "does the
page load" — the treatment sweep across dozens of templates makes it easy
for one file to accidentally recolor a primary CTA, a focus ring, or a
sidebar active-state, and normal Playwright smoke coverage wouldn't catch
that since the page still renders and functions. Each test reads a real
computed style off a real running page rather than asserting a CSS class
name, so it survives markup refactors and only fails on an actual color
regression.
"""
from playwright.sync_api import expect


def _rgb(page, selector, prop='color'):
    return page.eval_on_selector(selector, f"el => getComputedStyle(el)['{prop}']")


def test_primary_cta_color_is_brand_blue(admin_page):
    """.btn-primary must stay on the mobinspect-500 brand blue
    (rgb(37, 99, 235)) — this is the 'operate the tool' action color and is
    deliberately NOT part of the amber/violet dashboard data-viz accent
    system (see docs/design). The API-key creation form's submit button is
    a stable, always-rendered .btn-primary instance to pin this against."""
    page = admin_page
    page.goto('/rbac/api-keys/', wait_until='domcontentloaded')
    btn = page.locator('button[type=submit].btn-primary')
    expect(btn).to_be_visible()
    color = _rgb(page, 'button[type=submit].btn-primary', 'background-color')
    assert color == 'rgb(37, 99, 235)', f'btn-primary background drifted: {color}'


def test_focus_ring_color_is_brand_blue(admin_page):
    """*:focus-visible must render the brand-blue outline (rgb(37, 99, 235))
    — this is the one global, non-page-scoped visual contract every
    template inherits from app.css. Form inputs and .btn elements each
    define their own, more specific focus treatment (a Tailwind ring/
    box-shadow, not an outline) so they don't exercise this base rule; a
    plain sidebar nav link (no component-level focus override) does."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')

    # Keyboard-driven focus is what actually triggers :focus-visible in
    # Chromium; a scripted .focus()/.click() doesn't reliably match it. Tab
    # through the page until a sidebar nav link is the active element (its
    # exact tab position isn't guaranteed, so walk to it rather than assume).
    found = False
    for _ in range(40):
        page.keyboard.press('Tab')
        found = page.evaluate(
            "document.activeElement && document.activeElement.classList.contains('mi-nav-item')"
        )
        if found:
            break
    assert found, 'could not reach a sidebar nav link via Tab navigation'

    outline_color = page.evaluate("getComputedStyle(document.activeElement)['outline-color']")
    outline_style = page.evaluate("getComputedStyle(document.activeElement)['outline-style']")
    assert outline_style == 'solid', f'focus ring not drawn: outline-style={outline_style!r}'
    assert outline_color == 'rgb(37, 99, 235)', f'focus ring color drifted: {outline_color}'


def test_sidebar_active_item_uses_theme_aware_accent(admin_page):
    """The current page's sidebar nav item must carry .is-active and render
    the active-state accent — a neutral dark chip (rgb(255, 255, 255) icon
    color on a dark fill), pixel-sampled from the CyberGuard reference
    (Dashboard.png), not a brand-blue accent. Same value in both themes
    (matches .mi-pillbtn's theme-invariant dark-neutral treatment). A
    non-active sibling item must NOT carry that color, proving this is a
    real per-item state and not a blanket rule."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')
    expect(page.locator('html')).to_have_attribute('data-theme', 'dark')

    active_item = page.locator('a.mi-nav-item.is-active[aria-current="page"]').first
    expect(active_item).to_be_visible()
    active_color = active_item.evaluate('el => getComputedStyle(el).color')
    assert active_color == 'rgb(255, 255, 255)', (
        f'sidebar active-item accent drifted in dark theme: {active_color}'
    )

    inactive_item = page.locator('a.mi-nav-item:not(.is-active)').first
    expect(inactive_item).to_be_visible()
    inactive_color = inactive_item.evaluate('el => getComputedStyle(el).color')
    assert inactive_color != active_color, (
        'inactive sidebar item incorrectly renders the active-state accent color'
    )
