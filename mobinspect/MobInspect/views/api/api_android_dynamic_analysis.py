# -*- coding: utf_8 -*-
"""MobInspect REST API V 1."""

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from mobinspect.MobInspect.views.helpers import request_method
from mobinspect.MobInspect.views.api.api_middleware import make_api_response
from mobinspect.DynamicAnalyzer.views.android import (
    dynamic_analyzer,
    operations,
    report,
    tests_common,
    tests_frida,
)
from mobinspect.DynamicAnalyzer.views.common import device
from mobinspect.DynamicAnalyzer.views.common.frida import views as frida


def _passthrough(resp):
    """Return an already-built HTTP response, or None.

    Operations/test views are called here with `api=True`. They normally
    return a plain dict that we inspect (`resp['status']`, `resp.get(...)`,
    `'error' in resp`). But when one of those views is guarded by an RBAC
    decorator (`require_permission`/`require_role`), a denied caller gets
    back a fully-formed HTTP response instead — a JSON 403 for API callers,
    a 401, or a redirect. Subscripting / membership-testing that response
    object raises (KeyError / TypeError), which the framework turns into an
    opaque 500 and recycles the gunicorn worker, masking a clean 403.

    This helper detects that case so callers can early-return the response
    untouched. We route it through `make_api_response`, which already knows
    to pass an HttpResponse through (only decorating the CORS headers).

    The type test is intentionally `HttpResponse` (not `HttpResponseBase`):
    it must match exactly what `make_api_response` short-circuits. RBAC
    denials (JsonResponse 403/401, redirects, TemplateResponse) are all
    `HttpResponse` subclasses so they still pass through. The logcat
    success path returns a `StreamingHttpResponse`, which IS an
    `HttpResponseBase` but NOT an `HttpResponse`; it must fall through to
    `None` here so `api_logcat` streams it untouched rather than feeding it
    to `JsonResponse` (which would raise TypeError -> opaque 500).
    """
    if isinstance(resp, HttpResponse):
        return make_api_response(resp)
    return None


# Dynamic Analyzer APIs
@request_method(['GET'])
@csrf_exempt
def api_get_apps(request):
    """GET - Get Apps for dynamic analysis API."""
    resp = dynamic_analyzer.android_dynamic_analysis(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied
    if 'error' in resp:
        return make_api_response(resp, 500)  # pragma: no cover - needs a live Android device/emulator to make android_dynamic_analysis() fail
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_start_analysis(request):
    """POST - Start Dynamic Analysis."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = dynamic_analyzer.dynamic_analyzer(
        request,
        request.POST['hash'],
        True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied
    if 'error' in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)  # pragma: no cover - needs a live Android device/emulator for dynamic_analyzer() to succeed


@request_method(['POST'])
@csrf_exempt
def api_logcat(request):
    """POST - Get Logcat HTTP Streaming API."""
    if 'package' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    lcat = dynamic_analyzer.logcat(request, True)
    denied = _passthrough(lcat)
    if denied is not None:
        return denied
    if isinstance(lcat, dict):
        if 'error' in lcat:
            return make_api_response(
                lcat, 500)
    return lcat  # pragma: no cover - needs a live Android device/emulator; streams a real logcat HttpResponse


# Android Operation APIs
@request_method(['POST'])
@csrf_exempt
def api_mobinspecty(request):
    """POST - MobInspecty API."""
    if 'identifier' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = operations.mobinspecty(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)  # pragma: no cover - needs a live Android device/emulator for operations.mobinspecty() to succeed
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_screenshot(request):
    """POST - Screenshot API."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = operations.take_screenshot(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)  # pragma: no cover - needs a live Android device/emulator to capture a real screenshot
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_adb_execute(request):
    """POST - ADB execute API."""
    if 'cmd' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = operations.execute_adb(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    if resp['status'] == 'denied':
        # ADB allowlist rejection is a security denial, not a server
        # error -- surface it as 403 (the non-API/web path already does
        # this via HttpResponse(..., status=403) inside execute_adb()).
        return make_api_response(resp, 403)
    return make_api_response(resp, 500)  # pragma: no cover - execute_adb() has no code path that returns a dict with any status other than 'ok'/'denied' (subprocess failures are swallowed internally and still resolve to 'ok')


@request_method(['POST'])
@csrf_exempt
def api_root_ca(request):
    """POST - MobInspect CA actions API."""
    if 'action' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = operations.mobinspect_ca(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_global_proxy(request):
    """POST - MobInspect Global Proxy API."""
    if 'action' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = operations.global_proxy(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)  # pragma: no cover - needs a live Android device/emulator for operations.global_proxy() to succeed
    return make_api_response(resp, 500)


# Android Dynamic Tests APIs
@request_method(['POST'])
@csrf_exempt
def api_act_tester(request):
    """POST - Activity Tester."""
    params = {'test', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = tests_common.activity_tester(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_start_activity(request):
    """POST - Start Activity."""
    params = {'activity', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = tests_common.start_activity(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_tls_tester(request):
    """POST - TLS/SSL Security Tester."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = tests_common.tls_tests(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied
    if resp['status'] == 'ok':  # pragma: no cover - needs a live Android device/emulator for tests_common.tls_tests() to run
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)  # pragma: no cover - needs a live Android device/emulator for tests_common.tls_tests() to run


@request_method(['POST'])
@csrf_exempt
def api_stop_analysis(request):
    """POST - Stop Dynamic Analysis."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    logs_resp = tests_common.collect_logs(request, True)
    denied = _passthrough(logs_resp)
    if denied is not None:
        return denied
    resp = tests_common.download_data(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied  # pragma: no cover - needs a live Android device/emulator to reach a real RBAC denial from download_data()
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)  # pragma: no cover - needs a live Android device/emulator for tests_common.download_data() to succeed
    return make_api_response(resp, 500)


# Android Frida APIs
@request_method(['POST'])
@csrf_exempt
def api_instrument(request):
    """POST - Frida Instrument."""
    params = {
        'hash',
        'default_hooks',
        'auxiliary_hooks',
        'frida_code'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = tests_frida.instrument(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)  # pragma: no cover - needs a live Android device/emulator for tests_frida.instrument() to succeed
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_api_monitor(request):
    """POST - Frida API Monitor."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = tests_frida.live_api(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied  # pragma: no cover - needs a live Android device/emulator to reach a real RBAC denial from live_api()
    # live_api can be json or html
    if resp.get('data'):
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_frida_logs(request):
    """POST - Frida Logs."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = frida.frida_logs(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied  # pragma: no cover - needs a live Android device/emulator to reach a real RBAC denial from frida_logs()
    # frida logs can be json or html
    if resp.get('data') or resp.get('message'):
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_list_frida_scripts(request):
    """POST - List Frida Scripts."""
    if 'device' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = frida.list_frida_scripts(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied  # pragma: no cover - needs a live Android device/emulator to reach a real RBAC denial from list_frida_scripts()
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)  # pragma: no cover - needs a live Android device/emulator for list_frida_scripts() to fail


@request_method(['POST'])
@csrf_exempt
def api_get_script_content(request):
    """POST - Frida Get Script."""
    if not request.POST.getlist('scripts[]'):
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    if 'device' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = frida.get_script_content(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied  # pragma: no cover - needs a live Android device/emulator to reach a real RBAC denial from get_script_content()
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_get_dependencies(request):
    """POST - Frida Get Runtime Dependencies."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = tests_frida.get_runtime_dependencies(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)  # pragma: no cover - needs a live Android device/emulator for get_runtime_dependencies() to succeed
    return make_api_response(resp, 500)


# Report APIs
@request_method(['POST'])
@csrf_exempt
def api_dynamic_report(request):
    """POST - Dynamic Analysis report."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = report.view_report(
        request,
        request.POST['hash'],
        True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied
    if 'error' in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_dynamic_view_file(request):
    """POST - Dynamic Analysis report."""
    params = {'hash', 'file', 'type'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = device.view_file(request, True)
    denied = _passthrough(resp)
    if denied is not None:
        return denied  # pragma: no cover - needs a live Android device/emulator to reach a real RBAC denial from device.view_file()
    if 'error' in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)
