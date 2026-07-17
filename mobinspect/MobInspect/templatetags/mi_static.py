"""
MobInspect — static asset cache-busting template tag.

WhiteNoise serves static files at a fixed URL (no content-hash in the
filename — STATICFILES_STORAGE is the plain Compressed variant, not the
Manifest one), with `Cache-Control: max-age=60, public`. During active
design iteration this means a browser can keep serving CSS from before the
most recent rebuild until the cache genuinely expires or the user hard-
refreshes. Appending `?v=<mtime>` forces a fresh fetch the instant the file
on disk actually changes, without disabling caching entirely.

Usage in base/app.html:
    {% load mi_static %}
    <link rel="stylesheet" href="{% static 'mobinspect/css/dist/app.css' %}?v={% asset_version 'mobinspect/css/dist/app.css' %}" />
"""
import os

from django.conf import settings
from django import template
from django.contrib.staticfiles import finders

register = template.Library()


@register.simple_tag
def asset_version(static_path):
    """Return the file's mtime as an integer, or the app version as a safe
    fallback if the file can't be located. Tries STATIC_ROOT first: in this
    project's config STATIC_ROOT *is* the source static/ dir (no separate
    collectstatic step), which staticfiles finders deliberately don't search
    (finders locate pre-collection sources, not STATIC_ROOT) — so relying on
    finders alone silently fell back to the version string on every request."""
    candidates = []
    static_root = getattr(settings, 'STATIC_ROOT', None)
    if static_root:
        candidates.append(os.path.join(static_root, static_path))
    try:
        found = finders.find(static_path)
        if found:
            candidates.append(found)
    except OSError:
        pass
    for path in candidates:
        try:
            return int(os.path.getmtime(path))
        except OSError:
            continue
    return getattr(settings, 'MOBINSPECT_VER', '1').replace('.', '')
