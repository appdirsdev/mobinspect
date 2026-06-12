"""
MobInspect — theme bootstrap template tag.

Renders an inline <script> that runs *before* paint to set
data-theme on <html>, preventing the dark/light flash on first load.

Place this AS THE FIRST THING inside <head>, before any stylesheet link.

Usage in base/app.html:
    {% load mi_theme %}
    <head>
        {% theme_bootstrap %}
        <link rel="stylesheet" href="...">
        ...
    </head>
"""
from django import template
from django.utils.safestring import mark_safe

register = template.Library()

# Single-quoted, no template literals — needs to work in oldest browsers
# we still support. Keep this script under 1 KB.
_BOOTSTRAP_JS = """
(function(){
  try {
    var KEY = 'mi-theme';
    var pref = localStorage.getItem(KEY) || 'system';
    var dark = pref === 'dark' ||
      (pref === 'system' &&
       window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme-pref', pref);
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'light');
  }
})();
""".strip()


@register.simple_tag
def theme_bootstrap():
    return mark_safe(f'<script>{_BOOTSTRAP_JS}</script>')
