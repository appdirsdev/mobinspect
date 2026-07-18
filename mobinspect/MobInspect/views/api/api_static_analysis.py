# -*- coding: utf_8 -*-
"""MobInspect REST API V 1."""
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

from mobinspect.StaticAnalyzer.models import (
    RecentScansDB,
)
from mobinspect.MobInspect.utils import (
    get_scan_logs,
    is_md5,
)
from mobinspect.MobInspect.views.helpers import request_method
from mobinspect.MobInspect.views.home import (
    RecentScans,
    Upload,
    delete_scan,
    search,
)
from mobinspect.MobInspect.views.api.api_middleware import make_api_response
from mobinspect.RBAC.decorators import require_permission
from mobinspect.StaticAnalyzer.views.android.views import view_source
from mobinspect.StaticAnalyzer.views.android.static_analyzer import static_analyzer
from mobinspect.StaticAnalyzer.views.ios.views import view_source as ios_view_source
from mobinspect.StaticAnalyzer.views.ios.static_analyzer import static_analyzer_ios
from mobinspect.StaticAnalyzer.views.common.async_task import list_tasks
from mobinspect.StaticAnalyzer.views.common.shared_func import compare_apps
from mobinspect.StaticAnalyzer.views.common.suppression import (
    delete_suppression,
    list_suppressions,
    suppress_by_files,
    suppress_by_rule_id,
)
from mobinspect.StaticAnalyzer.views.common.pdf import (
    PDF_UNAVAILABLE_MSG,
    pdf,
)
from mobinspect.StaticAnalyzer.views.common.appsec import appsec_dashboard
from mobinspect.StaticAnalyzer.views.windows import windows


@request_method(['POST'])
@csrf_exempt
def api_upload(request):
    """POST - Upload API."""
    upload = Upload(request)
    resp, code = upload.upload_api()
    return make_api_response(resp, code)


@request_method(['GET'])
@csrf_exempt
def api_recent_scans(request):
    """GET - get recent scans."""
    scans = RecentScans(request)
    resp = scans.recent_scans()
    if 'error' in resp:
        return make_api_response(resp, 500)
    else:
        return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_scan(request):
    """POST - Scan API."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    checksum = request.POST['hash']
    if not is_md5(checksum):
        return make_api_response(
            {'error': 'Invalid Checksum'}, 500)
    robj = RecentScansDB.objects.filter(MD5=checksum)
    if not robj.exists():
        return make_api_response(
            {'error': 'The file is not uploaded/available'}, 500)
    scan_type = robj[0].SCAN_TYPE
    # APK, Source Code (Android/iOS) ZIP, SO, JAR, AAR
    if scan_type in settings.ANDROID_EXTS:
        resp = static_analyzer(request, checksum, True)
        if 'type' in resp:
            resp = static_analyzer_ios(request, checksum, True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    # IPA
    elif scan_type in settings.IOS_EXTS:
        resp = static_analyzer_ios(request, checksum, True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    # APPX
    elif scan_type in settings.WINDOWS_EXTS:
        resp = windows.staticanalyzer_windows(request, checksum, True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_scan_logs(request):
    """POST - Get Scan logs."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = get_scan_logs(request.POST['hash'])
    if not resp:
        return make_api_response(
            {'error': 'No scan logs found'}, 400)
    return make_api_response({'logs': resp}, 200)


@request_method(['POST'])
@csrf_exempt
def api_tasks(request):
    """POST - Get Scan Queue."""
    resp = list_tasks(request, True)
    if not resp:
        return make_api_response(
            {'error': 'Scan queue empty'}, 400)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_delete_scan(request):
    """POST - Delete a Scan."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = delete_scan(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
@require_permission('scan.export.pdf')
def api_pdf_report(request):
    """Generate and Download PDF."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = pdf(
        request,
        request.POST['hash'],
        api=True)
    if isinstance(resp, HttpResponse):
        # pdf() only carries @login_required, which no-ops whenever
        # api=True (see authentication.login_required) -- unlike
        # appsec_dashboard(), it has no permission decorator of its own,
        # so it can never hand back an HttpResponse here. Kept as a
        # defensive guard in case that changes.
        return make_api_response(resp)  # pragma: no cover - unreachable: pdf(api=True) never returns HttpResponse
    if 'error' in resp:
        if resp.get('error') == 'Invalid Hash':
            response = make_api_response(resp, 400)
        elif resp.get('error') == PDF_UNAVAILABLE_MSG:
            response = make_api_response(resp, 503)
        else:
            response = make_api_response(resp, 500)
    elif 'pdf_dat' in resp:
        response = HttpResponse(
            resp['pdf_dat'], content_type='application/pdf')
        response['Access-Control-Allow-Origin'] = '*'
    elif resp.get('report') == 'Report not Found':
        response = make_api_response(resp, 404)
    else:
        # Defensive fallback: pdf(api=True, jsonres=False) only ever
        # returns 'error' / 'pdf_dat' / 'report'=='Report not Found'
        # dicts, all handled above, so this is unreachable given the
        # current contract.
        response = make_api_response({'error': 'PDF Generation Error'}, 500)  # pragma: no cover - unreachable given pdf()'s current return contract
    return response


@request_method(['POST'])
@csrf_exempt
@require_permission('scan.export.json')
def api_json_report(request):
    """Generate JSON Report."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = pdf(
        request,
        request.POST['hash'],
        api=True,
        jsonres=True)
    if isinstance(resp, HttpResponse):
        # Same defensive guard as api_pdf_report -- pdf() has no
        # permission decorator of its own, so this cannot fire today.
        return make_api_response(resp)  # pragma: no cover - unreachable: pdf(api=True) never returns HttpResponse
    if 'error' in resp:
        if resp.get('error') == 'Invalid Hash':
            response = make_api_response(resp, 400)
        else:
            response = make_api_response(resp, 500)
    elif 'report_dat' in resp:
        response = make_api_response(resp['report_dat'], 200)
    elif resp.get('report') == 'Report not Found':
        response = make_api_response(resp, 404)
    else:
        # Defensive fallback: pdf(api=True, jsonres=True) only ever
        # returns 'error' / 'report_dat' / 'report'=='Report not Found'
        # dicts, all handled above, so this is unreachable given the
        # current contract.
        response = make_api_response({'error': 'JSON Generation Error'}, 500)  # pragma: no cover - unreachable given pdf()'s current return contract
    return response


@request_method(['POST'])
@csrf_exempt
def api_search(request):
    """Search by checksum or text."""
    if 'query' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = search(request, api=True)
    if 'checksum' in resp:
        request.POST = {'hash': resp['checksum']}
        return api_json_report(request)
    elif 'error' in resp:
        return make_api_response(resp, 404)


@request_method(['POST'])
@csrf_exempt
def api_view_source(request):
    """View Source for android & ios source file."""
    params = {'file', 'type', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    if request.POST['type'] in {'eclipse', 'studio',
                                'apk', 'java', 'smali'}:
        resp = view_source.run(request, api=True)
    else:
        resp = ios_view_source.run(request, api=True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_compare(request):
    """Compare 2 apps."""
    params = {'hash1', 'hash2'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = compare_apps(
        request,
        request.POST['hash1'],
        request.POST['hash2'],
        True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_scorecard(request):
    """Generate App Score Card."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = appsec_dashboard(
        request,
        request.POST['hash'],
        api=True)
    if isinstance(resp, HttpResponse):
        # scan.view denial from appsec_dashboard's decorator — forward as-is.
        return make_api_response(resp)
    if 'error' in resp:
        if resp.get('error') == 'Invalid Hash':
            response = make_api_response(resp, 400)
        else:
            response = make_api_response(resp, 500)
    elif 'hash' in resp:
        response = make_api_response(resp, 200)
    elif 'not_found' in resp:
        response = make_api_response(resp, 404)
    else:
        # Genuinely reachable (NOT dead code): if get_android_dashboard's
        # inner get_context_from_db_entry() swallows a real exception
        # (e.g. an unparsable stored CODE_ANALYSIS column) it returns
        # None, and get_android_dashboard's own `if not data: return
        # findings` guard hands back a context dict with none of
        # 'error'/'hash'/'not_found' set -- landing here rather than
        # raising up to appsec_dashboard's outer except. See
        # test_scorecard_missing_hash_key_hits_generic_fallback.
        response = make_api_response({'error': 'JSON Generation Error'}, 500)
    return response


@request_method(['POST'])
@csrf_exempt
def api_suppress_by_rule_id(request):
    """POST - Suppress a rule by id."""
    params = {'rule', 'type', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = suppress_by_rule_id(request, True)
    if resp.get('status') == 'failed':
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_suppress_by_files(request):
    """POST - Suppress a rule by files."""
    params = {'rule', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = suppress_by_files(request, True)
    if resp.get('status') == 'failed':
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_list_suppressions(request):
    """POST - View Suppressions."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = list_suppressions(request, True)
    if resp.get('status') == 'failed':
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_delete_suppression(request):
    """POST - Delete a suppression."""
    # `kind` is optional and mirrors the params suppress requires.
    params = {'type', 'rule', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = delete_suppression(request, True)
    if resp.get('status') == 'failed':
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response
