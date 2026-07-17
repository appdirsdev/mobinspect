# -*- coding: utf_8 -*-
"""Android Dynamic Analysis."""
import logging
import os
import subprocess
import time
from pathlib import Path
from json import dump

from shelljob import proc

import frida

from django.http import (HttpResponseRedirect,
                         StreamingHttpResponse)
from django.conf import settings
from django.shortcuts import render
from django.db.models import ObjectDoesNotExist

from mobinspect.DynamicAnalyzer.views.android.environment import (
    ANDROID_API_SUPPORTED,
    Environment,
)
from mobinspect.DynamicAnalyzer.views.android.operations import (
    get_package_name,
)
from mobinspect.DynamicAnalyzer.tools.webproxy import (
    get_http_tools_url,
    start_httptools_ui,
    stop_httptools,
)
from mobinspect.MobInspect.utils import (
    get_android_dm_exception_msg,
    get_config_loc,
    get_device,
    get_proxy_ip,
    is_md5,
    print_n_send_error_response,
    python_dict,
    python_list,
    strict_package_check,
)
from mobinspect.MobInspect.views.scanning import add_to_recent_scan
from mobinspect.StaticAnalyzer.models import StaticAnalyzerAndroid
from mobinspect.MobInspect.views.authentication import (
    login_required,
)
from mobinspect.MobInspect.views.authorization import (
    Permissions,
    permission_required,
)

logger = logging.getLogger(__name__)

# Errors that mean "the device/Frida is not reachable" rather than
# "MobInspect is broken". These should degrade to a friendly page
# (HTTP 200) instead of recycling a gunicorn worker with a raw 500.
DEVICE_UNAVAILABLE_ERRORS = (
    subprocess.CalledProcessError,
    ConnectionError,
    TimeoutError,
    frida.ServerNotRunningError,
    frida.TransportError,
    frida.TimedOutError,
    frida.InvalidArgumentError,
    frida.ProcessNotFoundError,
    frida.NotSupportedError,
)

NO_DEVICE_MSG = (
    'No device connected / dynamic analysis unavailable. '
    'The Android VM/emulator could not be reached. '
    'Start the device, ensure adb can see it, and try again.')


def device_unavailable_response(request, api=False, detail=None):
    """Render a graceful "no device" page with HTTP 200 (not a 500)."""
    msg = NO_DEVICE_MSG
    if detail:
        msg = f'{msg}\n{detail}'
    return graceful_response(request, msg, api)


def graceful_response(request, msg, api=False,
                      title='Dynamic Analysis Unavailable'):
    """Return a non-fatal failure as HTTP 200 (not a worker-recycling 500).

    Used for expected, user-actionable conditions during dynamic analysis
    (device offline, instrument not done, incompatible APK). These are not
    MobInspect bugs, so they must not surface as 500s that recycle the
    gunicorn worker. API callers get the error dict; the wrapper sees a
    plain dict (not an HttpResponse) and returns it as-is.
    """
    logger.warning('Dynamic analysis unavailable: %s', msg)
    if api:
        return {'error': msg}
    context = {
        'title': title,
        'exp': title,
        'doc': msg,
        'version': settings.MOBINSPECT_VER,
    }
    template = 'general/error.html'
    return render(request, template, context, status=200)


@login_required
@permission_required(Permissions.SCAN)
def android_dynamic_analysis(request, api=False):
    """Android Dynamic Analysis Entry point."""
    try:
        scan_apps = []
        device_packages = {}
        and_ver = None
        and_sdk = None
        apks = StaticAnalyzerAndroid.objects.filter(
            APP_TYPE='apk')

        for apk in reversed(apks):

            logcat = Path(settings.UPLD_DIR) / apk.MD5 / 'logcat.txt'
            temp_dict = {
                'ICON_PATH': apk.ICON_PATH,
                'MD5': apk.MD5,
                'APP_NAME': apk.APP_NAME,
                'VERSION_NAME': apk.VERSION_NAME,
                'FILE_NAME': apk.FILE_NAME,
                'PACKAGE_NAME': apk.PACKAGE_NAME,
                'DYNAMIC_REPORT_EXISTS': logcat.exists(),
            }
            scan_apps.append(temp_dict)
        try:
            identifier = get_device()
        except Exception:
            return print_n_send_error_response(
                request, get_android_dm_exception_msg(), api)
        try:
            if identifier:
                env = Environment(identifier)
                env.connect()
                device_packages = env.get_device_packages()
                if device_packages:
                    pkg_file = Path(settings.DWD_DIR) / 'packages.json'
                    with pkg_file.open('w', encoding='utf-8') as target:
                        dump(device_packages, target)
                and_ver = env.get_android_version()
                and_sdk = env.get_android_sdk()
        except Exception:
            pass
        context = {'apps': scan_apps,
                   'identifier': identifier,
                   'android_version': and_ver,
                   'android_sdk': and_sdk,
                   'android_supported': ANDROID_API_SUPPORTED,
                   'proxy_ip': get_proxy_ip(identifier),
                   'proxy_port': settings.PROXY_PORT,
                   'settings_loc': get_config_loc(),
                   'device_packages': device_packages,
                   'title': 'MobInspect Dynamic Analysis',
                   'version': settings.MOBINSPECT_VER}
        if api:
            return context
        template = 'dynamic_analysis/android/dynamic_analysis.html'
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Dynamic Analysis')
        return print_n_send_error_response(request, exp, api)


@login_required
@permission_required(Permissions.SCAN)
def dynamic_analyzer(request, checksum, api=False):
    """Android Dynamic Analyzer Environment."""
    try:
        identifier = None
        activities = None
        deeplinks = None
        exported_activities = None
        if api:
            reinstall = request.POST.get('re_install', '1')
            install = request.POST.get('install', '1')
        else:
            reinstall = request.GET.get('re_install', '1')
            install = request.GET.get('install', '1')
        if not is_md5(checksum):
            # We need this check since checksum is not validated
            # in REST API
            return print_n_send_error_response(
                request,
                'Invalid Hash',
                api)
        package = get_package_name(checksum)
        if not package:
            return print_n_send_error_response(
                request,
                'Cannot get package name from checksum',
                api)
        logger.info('Creating Dynamic Analysis Environment for %s', package)
        try:
            identifier = get_device()
        except Exception:
            return print_n_send_error_response(
                request, get_android_dm_exception_msg(), api)

        # Get activities from the static analyzer results
        try:
            static_android_db = StaticAnalyzerAndroid.objects.get(
                MD5=checksum)
            exported_activities = python_list(
                static_android_db.EXPORTED_ACTIVITIES)
            activities = python_list(
                static_android_db.ACTIVITIES)
            deeplinks = python_dict(
                static_android_db.BROWSABLE_ACTIVITIES)
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Activities/Deeplinks. '
                'Static Analysis not completed for the app.')
        env = Environment(identifier)
        # connect_n_mount() returns False (no exception) when the emulator
        # host is offline: `adb connect <dead-host>` exits 0 with an
        # "unable to connect" message, so nothing raises. Gate on the
        # boolean return AND an explicit device-state check so the offline
        # case degrades to a friendly HTTP 200 page instead of a raw 500
        # that recycles the gunicorn worker.
        if not env.connect_n_mount() or not env.is_device_connected():
            return device_unavailable_response(
                request, api, f'Cannot connect to {identifier}')
        version = env.get_android_version()
        logger.info('Android Version identified as %s', version)
        xposed_first_run = False
        if not env.is_mobinspectyied(version):
            msg = ('This Android instance is not instrumented/Outdated.\n'
                   'instrumenting the android runtime environment')
            logger.warning(msg)
            if not env.mobinspecty_init():
                # mobinspecty_init() returns False when the device drops out
                # mid-preparation (adb calls return None / raise inside).
                # Treat this as device unavailability (HTTP 200) rather
                # than a hard 500.
                return device_unavailable_response(
                    request, api, 'Failed to instrument the instance')
            if version < 5:
                # Start Clipboard monitor
                env.start_clipmon()
                xposed_first_run = True
        if xposed_first_run:
            msg = ('Have you instrumented the instance before'
                   ' attempting Dynamic Analysis?'
                   ' Install Framework for Xposed.'
                   ' Restart the device and enable'
                   ' all Xposed modules. And finally'
                   ' restart the device once again.')
            return graceful_response(request, msg, api)
        # Clean up previous analysis
        env.dz_cleanup(checksum)
        # Configure Web Proxy
        env.configure_proxy(package, request)
        # Supported in Android 5+
        env.enable_adb_reverse_tcp(version)
        # Apply Global Proxy to device
        env.set_global_proxy(version)
        if install == '1':
            # Install APK
            apk_path = Path(settings.UPLD_DIR) / checksum / f'{checksum}.apk'
            status, output = env.install_apk(
                apk_path.as_posix(),
                package,
                reinstall)
            if not status:
                # Unset Proxy
                env.unset_global_proxy()
                msg = (f'This APK cannot be installed. Is this APK '
                       f'compatible the Android VM/Emulator?\n{output}')
                return graceful_response(request, msg, api)
        logger.info('Testing Environment is Ready!')
        context = {'package': package,
                   'hash': checksum,
                   'android_version': version,
                   'version': settings.MOBINSPECT_VER,
                   'activities': activities,
                   'exported_activities': exported_activities,
                   'deeplinks': deeplinks,
                   'title': 'Dynamic Analyzer'}
        template = 'dynamic_analysis/android/dynamic_analyzer.html'
        if api:
            return context
        return render(request, template, context)
    except DEVICE_UNAVAILABLE_ERRORS as exp:
        # adb/Frida could not reach the device. Degrade gracefully
        # with an HTTP 200 "no device connected" page instead of a
        # raw 500 that recycles the gunicorn worker.
        logger.warning('Dynamic Analyzer device unavailable: %s', exp)
        return device_unavailable_response(request, api)
    except Exception:
        logger.exception('Dynamic Analyzer')
        return print_n_send_error_response(
            request,
            'Dynamic Analysis Failed.',
            api)


@login_required
@permission_required(Permissions.SCAN)
def httptools_start(request):
    """Start httprools UI."""
    logger.info('Starting httptools Web UI')
    try:
        httptools_url = get_http_tools_url(request)
        stop_httptools(httptools_url)
        start_httptools_ui(settings.PROXY_PORT)
        time.sleep(3)
        logger.info('httptools UI started')
        if request.GET['project']:
            project = request.GET['project']
        else:
            project = ''
        url = f'{httptools_url}/dashboard/{project}'
        return HttpResponseRedirect(url)
    except Exception:
        logger.exception('Starting httptools Web UI')
        err = 'Error Starting httptools UI'
        return print_n_send_error_response(request, err)


@login_required
@permission_required(Permissions.SCAN)
def logcat(request, api=False):
    logger.info('Starting Logcat streaming')
    try:
        pkg = request.GET.get('package')
        if pkg:
            if not strict_package_check(pkg):
                return print_n_send_error_response(
                    request,
                    'Invalid package name',
                    api)
            template = 'dynamic_analysis/android/logcat.html'
            return render(request, template, {'package': pkg})
        if api:
            app_pkg = request.POST['package']
        else:
            app_pkg = request.GET.get('app_package')
        if app_pkg:
            if not strict_package_check(app_pkg):
                return print_n_send_error_response(
                    request,
                    'Invalid package name',
                    api)
            adb = os.environ['MOBINSPECT_ADB']
            g = proc.Group()
            g.run([adb, 'logcat', app_pkg + ':V', '*:*'])

            def read_process():
                while g.is_pending():
                    lines = g.readlines()
                    for _, line in lines:
                        yield 'data:{}\n\n'.format(line)
            return StreamingHttpResponse(read_process(),
                                         content_type='text/event-stream')
        return print_n_send_error_response(
            request,
            'Invalid parameters',
            api)
    except Exception:
        logger.exception('Logcat Streaming')
        err = 'Error in Logcat streaming'
        return print_n_send_error_response(request, err, api)


@login_required
@permission_required(Permissions.SCAN)
def trigger_static_analysis(request, checksum):
    """On device APK Static Analysis."""
    try:
        identifier = None
        if not is_md5(checksum):
            return print_n_send_error_response(
                request,
                'Invalid MD5')
        package = get_package_name(checksum)
        if not package:
            return print_n_send_error_response(
                request,
                'Cannot get package name from checksum')
        try:
            identifier = get_device()
        except Exception:
            err = 'Cannot connect to Android Runtime'
            return print_n_send_error_response(request, err)
        env = Environment(identifier)
        scan_type = env.get_apk(checksum, package)
        if not scan_type:
            err = 'Failed to download APK file'
            return print_n_send_error_response(request, err)
        file_name = f'{package}.apk'
        if scan_type == 'apks':
            file_name = f'{file_name}s'
        data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': checksum,
            'scan_type': scan_type,
            'file_name': file_name,
        }
        add_to_recent_scan(data)
        return HttpResponseRedirect(f'/static_analyzer/{checksum}/')
    except Exception:
        msg = 'On device APK Static Analysis'
        logger.exception(msg)
        return print_n_send_error_response(request, msg)
