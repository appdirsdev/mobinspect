# -*- coding: utf_8 -*-
"""Module for manifest_view."""

import logging
from pathlib import Path

from django.conf import settings
from django.shortcuts import render

from mobinspect.MobInspect.utils import (
    is_md5,
    print_n_send_error_response,
)
from mobinspect.StaticAnalyzer.views.android.manifest_utils import (
    get_manifest_file,
)
from mobinspect.MobInspect.views.authentication import (
    login_required,
)

logger = logging.getLogger(__name__)


@login_required
def run(request, checksum):
    """View the manifest."""
    try:
        supported = ['eclipse', 'studio', 'apk', 'aar']
        # Default to 'apk' when ?type= is omitted so a bare or bookmarked
        # /manifest_view/<md5>/ URL renders the APK manifest instead of
        # raising MultiValueDictKeyError (which the outer except turned into
        # a generic "Error Viewing AndroidManifest.xml" 500 page). Every
        # in-app link already appends ?type=apk, so this only changes the
        # direct-URL case from a 500 into a working page.
        typ = request.GET.get('type', 'apk')  # APK or SOURCE
        if is_md5(checksum) and (typ in supported):
            app_dir = Path(settings.UPLD_DIR) / checksum
            app_dic = {
                'md5': checksum,
                'app_dir': app_dir,
                'app_path': app_dir / f'{checksum}.apk',
                'tools_dir': Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'tools',
                'zipped': typ,
            }
            manifest_file = get_manifest_file(app_dic)
            if manifest_file and manifest_file.exists():
                manifest = manifest_file.read_text('utf-8', 'ignore')
            else:
                manifest = ''
            context = {
                'title': 'AndroidManifest.xml',
                'file': 'AndroidManifest.xml',
                'data': manifest,
                'type': 'xml',
                'sqlite': {},
                'version': settings.MOBINSPECT_VER,
            }
            template = 'general/view.html'
            return render(request, template, context)
        return print_n_send_error_response(
            request, 'Invalid checksum or manifest type')
    except Exception:
        logger.exception('Viewing AndroidManifest.xml')
        return print_n_send_error_response(
            request,
            'Error Viewing AndroidManifest.xml')
