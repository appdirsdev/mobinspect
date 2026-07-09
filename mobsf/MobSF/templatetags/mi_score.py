"""
MobInspect — shared security-score color tier.

Before this file existed, the </30/<40/<60/else -> red/amber/blue/green
ternary was hand-copied into 6 templates, and a 7th (Analytics) used a
DIFFERENT 3-tier scale with different boundaries and no "low" tier — so the
exact same numeric score could render a different color depending which
page you were looking at it on. This is the single source of truth both
should use instead.

Thresholds (matches the majority pre-existing scale, used by
appsec_dashboard.html and every per-app static-analysis report):
    score <  30            -> critical
    30 <= score <  40       -> medium
    40 <= score <  60       -> low
    score >= 60             -> passed

Usage in a template:
    {% load mi_score %}
    style="color: {{ security_score|score_color }}"
    -- or, if you need just the tier name (e.g. for a text label) --
    {{ security_score|score_tier }}  {# "critical" | "medium" | "low" | "passed" #}

The returned color is a CSS var reference (`rgb(var(--score-critical))`
etc.) — see the --score-* custom properties in app.css's :root / [data-theme]
blocks, which mirror the severity-* tokens' own light/dark hex pairs. This
resolves to the correct shade automatically per theme, unlike a bare hex.
"""
from django import template

register = template.Library()

_TIERS = ('critical', 'medium', 'low', 'passed')


def _tier(value):
    """Return one of _TIERS for a 0-100 score, or None if value is None
    or not a real number (fails closed to "no tier" rather than guessing)."""
    if value is None:
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if score < 30:
        return 'critical'
    if score < 40:
        return 'medium'
    if score < 60:
        return 'low'
    return 'passed'


@register.filter
def score_tier(value):
    """0-100 score -> 'critical'|'medium'|'low'|'passed', or '' if unset."""
    return _tier(value) or ''


@register.filter
def score_color(value):
    """0-100 score -> a ready-to-use, theme-aware CSS color value, or ''
    if unset (so callers can still {% if score is not None %} guard first)."""
    tier = _tier(value)
    if tier is None:
        return ''
    return f'rgb(var(--score-{tier}))'


@register.filter
def score_class(value):
    """0-100 score -> Tailwind text-color utility classes (light + dark
    variant) for the severity-* token family, or '' if unset. For callers
    that need a class string rather than an inline CSS color (score_color),
    e.g. coloring a <p> tag directly instead of an SVG/style attribute."""
    tier = _tier(value)
    if tier is None:
        return ''
    return f'text-severity-{tier} dark:text-severity-{tier}-dark'
