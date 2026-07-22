# -*- coding: utf_8 -*-
"""Find in java or smali files."""

import logging
import json
from pathlib import Path

from django.conf import settings
from django.http import JsonResponse
from django.utils.html import escape

from mobinspect.MobInspect.utils import (
    is_md5,
)
from mobinspect.StaticAnalyzer.views.common.shared_func import (
    find_java_source_folder,
)
from mobinspect.MobInspect.views.authentication import (
    login_required,
)

logger = logging.getLogger(__name__)


def _find_response(context, status=200):
    """Return the AJAX search response.

    source_tree.html's search handler parses this body with
    ``JSON.parse(JSON.parse(text))`` — i.e. it expects a DOUBLE-encoded JSON
    object carrying a ``matches`` array. BOTH the success path and every
    error path must therefore use this exact shape AND a real HttpResponse.

    Previously the error branches returned
    ``print_n_send_error_response(request, msg, api=True)``, which yields a
    bare ``dict`` — not an HttpResponse — so Django's response middleware
    raised ``AttributeError: 'dict' object has no attribute 'headers'`` and
    EVERY error path 500'd (invalid hash, missing source dir, any exception).

    (The double-encoding itself is legacy wire cruft kept for compatibility
    with the existing client; intentionally not changed here.)
    """
    return JsonResponse(json.dumps(context), safe=False, status=status)


def _find_error(msg, status):
    """A search-shaped error envelope with empty matches, so the client's
    handler degrades to 'no results' instead of throwing on ``.matches``."""
    return _find_response({
        'title': 'Search Results',
        'matches': [],
        'term': '',
        'found': '0',
        'search_type': '',
        'version': settings.MOBINSPECT_VER,
        'error': msg,
    }, status=status)


@login_required
def run(request):
    """Find filename/content in source files (ajax response)."""
    try:
        # .get() (not ['..']) so a missing field is a clean 400, not a
        # KeyError → 500. The real client (source_tree.html) always sends
        # all four via FormData; this just hardens the endpoint.
        md5 = request.POST.get('md5', '')
        if not is_md5(md5):
            return _find_error('Invalid Hash', 400)
        query = request.POST.get('q', '')
        code = request.POST.get('code', '')
        search_type = request.POST.get('search_type', '')
        if search_type not in ['content', 'filename']:
            return _find_error('Unknown search type', 400)
        matches = set()
        base = Path(settings.UPLD_DIR) / md5
        if code == 'smali':
            src = base / 'smali_source'
        else:
            try:
                src = find_java_source_folder(base)[0]
            except StopIteration:
                return _find_error('Invalid Directory Structure', 404)

        exts = ['.java', '.kt', '.smali']
        files = [p for p in src.rglob('*') if p.suffix in exts]
        for fname in files:
            file_path = fname.as_posix()
            rpath = file_path.replace(src.as_posix(), '')
            rpath = rpath[1:]
            if search_type == 'content':
                dat = fname.read_text('utf-8', 'ignore')
                if query.lower() in dat.lower():
                    matches.add(escape(rpath))
            elif search_type == 'filename' and \
                    query.lower() in fname.name.lower():
                matches.add(escape(rpath))

        flz = len(matches)
        context = {
            'title': 'Search Results',
            'matches': list(matches),
            'term': query,
            'found': str(flz),
            'search_type': search_type,
            'version': settings.MOBINSPECT_VER,
        }
        return _find_response(context)
    except Exception:
        logger.exception('Searching Failed')
        return _find_error('Searching Failed', 500)
