# -*- coding: utf_8 -*-
"""
Shared Functions.

PDF Generation
"""
import json
import logging
import os
import platform

from django.http import HttpResponse
from django.template.loader import get_template

import mobinspect.MalwareAnalyzer.views.VirusTotal as VirusTotal
from mobinspect.MobInspect import settings
from mobinspect.MobInspect.utils import (
    is_md5,
    print_n_send_error_response,
    upstream_proxy,
)
from mobinspect.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
    StaticAnalyzerWindows,
)
from mobinspect.StaticAnalyzer.views.common.appsec import (
    get_android_dashboard,
    get_ios_dashboard,
)
from mobinspect.StaticAnalyzer.views.common.shared_func import (
    get_avg_cvss,
)
from mobinspect.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry as adb)
from mobinspect.StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry as idb)
from mobinspect.StaticAnalyzer.views.windows.db_interaction import (
    get_context_from_db_entry as wdb)
from mobinspect.MobInspect.views.authentication import (
    login_required,
)

logger = logging.getLogger(__name__)
try:
    import pdfkit
except ImportError:  # pragma: no cover - pdfkit is genuinely installed here
    pdfkit = None
    logger.warning(
        'wkhtmltopdf is not installed/configured properly.'
        ' PDF Report Generation is disabled')
ctype = 'application/json; charset=utf-8'

PDF_UNAVAILABLE_MSG = (
    'PDF export requires wkhtmltopdf - install it '
    '(e.g. "apt-get install wkhtmltopdf") or set '
    'MOBINSPECT_WKHTMLTOPDF_BINARY to its path.')


def get_pdf_configuration():
    """Build a pdfkit configuration.

    Honors settings.WKHTMLTOPDF_BINARY when set; otherwise relies on PATH.
    Raises OSError/IOError if wkhtmltopdf is not available so callers can
    degrade cleanly (HTTP 503) instead of emitting an opaque 500.
    """
    if pdfkit is None:
        raise OSError('pdfkit is not installed')
    wkhtmltopdf = getattr(settings, 'WKHTMLTOPDF_BINARY', '')
    if wkhtmltopdf:
        return pdfkit.configuration(wkhtmltopdf=wkhtmltopdf)
    # Empty path -> pdfkit probes PATH and raises if the binary is missing.
    return pdfkit.configuration()


@login_required
def pdf(request, checksum, api=False, jsonres=False):
    try:
        if not is_md5(checksum):
            if api:
                return {'error': 'Invalid Hash'}
            else:
                return HttpResponse(
                    json.dumps({'md5': 'Invalid Hash'}),
                    content_type=ctype, status=500)
        # Do Lookups
        android_static_db = StaticAnalyzerAndroid.objects.filter(
            MD5=checksum)
        ios_static_db = StaticAnalyzerIOS.objects.filter(
            MD5=checksum)
        win_static_db = StaticAnalyzerWindows.objects.filter(
            MD5=checksum)

        if android_static_db.exists():
            context, template = handle_pdf_android(android_static_db)
        elif ios_static_db.exists():
            context, template = handle_pdf_ios(ios_static_db)
        elif win_static_db.exists():
            context, template = handle_pdf_win(win_static_db)
        else:
            if api:
                return {'report': 'Report not Found'}
            else:
                return HttpResponse(
                    json.dumps({'report': 'Report not Found'}),
                    content_type=ctype,
                    status=500)
        # Do VT Scan only on binaries
        context['virus_total'] = None
        ext = os.path.splitext(context['file_name'].lower())[1]
        if settings.VT_ENABLED and ext != '.zip':
            app_bin = os.path.join(  # pragma: no cover - requires a live VirusTotal network call (no-network test policy)
                settings.UPLD_DIR,
                checksum + '/',
                checksum + ext)
            vt = VirusTotal.VirusTotal(checksum)  # pragma: no cover - live VirusTotal call, see above
            context['virus_total'] = vt.get_result(app_bin)  # pragma: no cover - live VirusTotal call, see above
        # Get Local Base URL
        proto = 'file://'
        host_os = 'nix'
        if platform.system() == 'Windows':
            proto = 'file:///'
            host_os = 'windows'
        context['base_url'] = proto + settings.BASE_DIR
        context['dwd_dir'] = proto + settings.DWD_DIR
        context['host_os'] = host_os
        context['timestamp'] = RecentScansDB.objects.get(
            MD5=checksum).TIMESTAMP
        try:
            if api and jsonres:
                return {'report_dat': context}
            else:
                # Resolve wkhtmltopdf up front so a missing binary returns a
                # clear 503 instead of an opaque 500.
                try:
                    pdf_config = get_pdf_configuration()
                except (OSError, IOError) as exp:
                    logger.error(
                        'PDF export unavailable: %s', PDF_UNAVAILABLE_MSG)
                    if api:
                        return {
                            'error': PDF_UNAVAILABLE_MSG,
                            'err_details': str(exp)}
                    return HttpResponse(
                        json.dumps({'pdf_error': PDF_UNAVAILABLE_MSG}),
                        content_type=ctype,
                        status=503)
                options = {
                    'page-size': 'Letter',
                    'quiet': '',
                    'enable-local-file-access': '',
                    'no-collate': '',
                    'margin-top': '0.50in',
                    'margin-right': '0.50in',
                    'margin-bottom': '0.50in',
                    'margin-left': '0.50in',
                    'encoding': 'UTF-8',
                    'orientation': 'Landscape',
                    'custom-header': [
                        ('Accept-Encoding', 'gzip'),
                    ],
                    'no-outline': None,
                    'no-stop-slow-scripts': '',
                }
                # Added proxy support to wkhtmltopdf
                proxies, _ = upstream_proxy('https')
                if proxies['https']:
                    options['proxy'] = proxies['https']
                html = template.render(context)
                pdf_dat = pdfkit.from_string(
                    html, False, options=options, configuration=pdf_config)
                if api:
                    return {'pdf_dat': pdf_dat}
                return HttpResponse(pdf_dat,
                                    content_type='application/pdf')
        except Exception as exp:
            logger.exception('Error Generating PDF Report')
            if api:
                return {
                    'error': 'Cannot Generate PDF/JSON',
                    'err_details': str(exp)}
            else:
                err = {
                    'pdf_error': 'Cannot Generate PDF',
                    'err_details': str(exp)}
                return HttpResponse(
                    json.dumps(err),  # lgtm [py/stack-trace-exposure]
                    content_type=ctype,
                    status=500)
    except Exception as exp:
        logger.exception('Error Generating PDF Report')
        msg = str(exp)
        exp = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp)
        else:
            return print_n_send_error_response(request, msg, False, exp)


def handle_pdf_android(static_db):
    logger.info(
        'Fetching data from DB for '
        'PDF Report Generation (Android)')
    context = adb(static_db)
    context['average_cvss'] = get_avg_cvss(
        context['code_analysis'])
    context['appsec'] = get_android_dashboard(static_db)
    if context['file_name'].lower().endswith('.zip'):
        logger.info('Generating PDF report for android zip')
    else:
        logger.info('Generating PDF report for android apk')
    return context, get_template('pdf/android_report.html')


def handle_pdf_ios(static_db):
    logger.info('Fetching data from DB for '
                'PDF Report Generation (IOS)')
    context = idb(static_db)
    context['appsec'] = get_ios_dashboard(static_db)
    if context['file_name'].lower().endswith('.zip'):
        logger.info('Generating PDF report for IOS zip')
        context['average_cvss'] = get_avg_cvss(
            context['code_analysis'])
    else:
        logger.info('Generating PDF report for IOS ipa')
        context['average_cvss'] = get_avg_cvss(
            context['binary_analysis'])
    return context, get_template('pdf/ios_report.html')


def handle_pdf_win(static_db):
    logger.info(
        'Fetching data from DB for '
        'PDF Report Generation (APPX)')
    context = wdb(static_db)
    return context, get_template('pdf/windows_report.html')
