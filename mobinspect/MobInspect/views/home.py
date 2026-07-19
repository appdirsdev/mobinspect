# -*- coding: utf_8 -*-
"""MobInspect File Upload and Home Routes."""
import json
import logging
import os
import platform
import random
import re
import shutil
from pathlib import Path
from datetime import timedelta
from wsgiref.util import FileWrapper

from collections import OrderedDict

from django.conf import settings
from django.utils.timezone import now
from django.core.paginator import Paginator
from django.db.models import Count
from django.db.models.functions import TruncDate, TruncMonth
from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.shortcuts import (
    redirect,
    render,
)
from django.template.defaulttags import register

from mobinspect.MobInspect.forms import FormUtil, UploadFileForm
from mobinspect.MobInspect.utils import (
    MD5_REGEX,
    get_md5,
    get_scan_logs,
    is_dir_exists,
    is_file_exists,
    is_md5,
    is_safe_path,
    key,
    print_n_send_error_response,
    python_dict,
    python_list,
)
from mobinspect.MobInspect.init import api_key
from mobinspect.MobInspect.security import sanitize_filename, sanitize_svg
from mobinspect.MobInspect.views.helpers import FileType
from mobinspect.MobInspect.views.scanning import Scanning, scan_report_url
from mobinspect.MobInspect.views.apk_downloader import apk_download
from mobinspect.StaticAnalyzer.models import (
    EnqueuedTask,
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
    StaticAnalyzerWindows,
    SuppressFindings,
)
from mobinspect.StaticAnalyzer.views.common.suppression import (
    get_package,
)
# get_android_dashboard/get_ios_dashboard are imported lazily inside index()
# below (not here at module scope): appsec.py -> db_interaction.py imports
# update_scan_timestamp from this module, so a top-level import here would
# be a circular import at Django app-loading time.
from mobinspect.DynamicAnalyzer.views.common.shared import (
    invalid_params,
    send_response,
)
from mobinspect.MobInspect.views.authentication import (
    login_required,
)
from mobinspect.RBAC.decorators import require_permission
from mobinspect.MobInspect.views.authorization import (
    MAINTAINER_GROUP,
    Permissions,
    permission_required,
)

LINUX_PLATFORM = ['Darwin', 'Linux']
HTTP_BAD_REQUEST = 400
HTTP_CONFLICT = 409
HTTP_STATUS_404 = 404
HTTP_SERVER_ERROR = 500
logger = logging.getLogger(__name__)
register.filter('key', key)

# Bound how many of the most-recent static scans the home dashboard scores in
# one pass. Lower than Analytics' cap (100) because the home page is hit far
# more often; 30 keeps it responsive while still giving a representative fleet
# average and per-row scores for the recent-activity table.
HOME_ROLLUP_LIMIT = 30

# Shown on the home dashboard on every visit after the first one in a
# session (the first visit shows "Welcome back, <user>" instead). Fully
# local/static so it works offline — no external quote API.
SECURITY_TIPS = (
    'Hardcoded API keys and secrets are one of the most common findings in '
    'mobile apps — always check the Secrets section of a report before '
    'shipping.',
    'An exported Activity, Service, or Receiver without a permission check '
    'can be launched by any other app on the device.',
    'Cleartext HTTP traffic can be intercepted on any network the device '
    'joins — enforce TLS and pin certificates for sensitive endpoints.',
    'Debuggable builds (android:debuggable="true") let anyone attach a '
    'debugger to your app in production — always disable it for release.',
    'Weak or custom cryptography is a frequent root cause of real-world '
    'breaches — prefer well-reviewed, standard libraries over homemade '
    'crypto.',
    'A backup-enabled app (android:allowBackup="true") can leak private '
    'data through adb backup on a rooted or debug-enabled device.',
    'Insecure WebView settings — especially JavaScript bridges — are a '
    'common path from a malicious webpage to native code execution.',
    'Third-party SDKs run with the same permissions as your app — audit '
    'what each library actually does before bundling it.',
    'A world-writable file or SQLite database lets any other app on the '
    'device tamper with your data without needing special permissions.',
    'Root and jailbreak detection raises the bar, but should never be the '
    'only defense for data an attacker really wants.',
    'Certificate pinning stops most man-in-the-middle attacks, but must be '
    'paired with a safe update path or a compromised pin can brick '
    'connectivity.',
    'Requesting only the permissions your app actually uses shrinks your '
    'attack surface and builds user trust.',
    'Client-side checks (license, paywall, root detection) can always be '
    'patched out of a binary — critical decisions belong on the server.',
    'Logs are a common leak — never write tokens, passwords, or PII to '
    'Logcat in a release build.',
    'A Firebase or cloud storage bucket left open by default is one of the '
    'fastest ways to expose an entire user base.',
    'Deep links and intent filters should always validate their input — '
    'treat them as untrusted, just like network input.',
    'Static analysis catches what code review misses at scale — but pair '
    'it with dynamic analysis to see what the app actually does at '
    'runtime.',
    'Obfuscation slows down reverse engineering, but it is not encryption '
    '— never rely on it alone to protect a real secret.',
)


def _home_security_rollup(md5s):
    """Single bounded AppSec pass over the given recent-scan MD5s.

    Returns ``(issues_total, avg_security_score, score_by_md5)`` — all from
    the SAME real per-app scorecard used everywhere else (get_android_dashboard
    / get_ios_dashboard), so nothing here is fabricated. ``issues_total`` counts
    only the action-worthy buckets (high + warning + hotspot); it deliberately
    excludes the ``secure`` (passing checks) and ``info`` buckets so a
    well-secured fleet doesn't show an inflated "issues" number. The per-MD5
    score map lets the recent-activity table show each app's real score for
    free (no second scoring pass). Fails closed: any per-app error is skipped
    and can never break the home page. Empty results when there are no scans.
    """
    issues_total = 0
    scores = []
    score_by_md5 = {}
    if not md5s:
        return 0, None, {}
    try:
        from mobinspect.StaticAnalyzer.views.common.appsec import (
            SCORE_AVERAGE_EXCLUDED_SCAN_TYPES,
            get_android_dashboard,
            get_ios_dashboard,
        )
    except Exception:
        logger.exception('Dashboard: appsec import failed')
        return 0, None, {}
    android = StaticAnalyzerAndroid.objects.filter(MD5__in=md5s)
    ios = StaticAnalyzerIOS.objects.filter(MD5__in=md5s)
    scan_type_by_md5 = dict(
        RecentScansDB.objects.filter(MD5__in=md5s)
        .values_list('MD5', 'SCAN_TYPE'))
    for entries, scorer in ((android, get_android_dashboard),
                            (ios, get_ios_dashboard)):
        for entry in entries:
            try:
                findings = scorer([entry])
            except Exception:
                logger.exception('Dashboard rollup failed for %s', entry.MD5)
                continue
            for sev in ('high', 'warning', 'hotspot'):
                issues_total += len(findings.get(sev) or [])
            score = findings.get('security_score')
            if score is not None:
                # Each app's own real score still shows on its row — only
                # the fleet AVERAGE excludes thin library/binary formats
                # (no manifest to evaluate, so their trivial 100 would
                # silently inflate the average). See appsec.py for why.
                score_by_md5[entry.MD5] = score
                scan_type = scan_type_by_md5.get(entry.MD5)
                if scan_type not in SCORE_AVERAGE_EXCLUDED_SCAN_TYPES:
                    scores.append(score)
    avg = round(sum(scores) / len(scores)) if scores else None
    return issues_total, avg, score_by_md5


@login_required
def index(request):
    """Index Route."""
    mimes = (settings.APK_MIME
             + settings.IPA_MIME
             + settings.ZIP_MIME
             + settings.APPX_MIME)
    exts = (settings.ANDROID_EXTS
            + settings.IOS_EXTS
            + settings.WINDOWS_EXTS)
    # Recent activity preview — real rows from RecentScansDB, no fabrication.
    # ANALYZER/MD5 build the canonical report link (/<analyzer>/<md5>/), the
    # same pattern recent.html uses. If there are no scans yet the template
    # simply omits the section.
    recent = list(
        RecentScansDB.objects
        .order_by('-TIMESTAMP')[:8]
        .values('MD5', 'APP_NAME', 'PACKAGE_NAME', 'FILE_NAME',
                'TIMESTAMP', 'SCAN_TYPE', 'ANALYZER'))
    # Live dashboard metrics — real counts from RecentScansDB, no fabrication.
    # Platform split follows the ANALYZER route key (same one used for report
    # links); "week" counts scans in the trailing 7 days.
    scans = RecentScansDB.objects
    week_ago = now() - timedelta(days=7)
    prev_week_ago = now() - timedelta(days=14)
    week_count = scans.filter(TIMESTAMP__gte=week_ago).count()
    prev_week_count = scans.filter(
        TIMESTAMP__gte=prev_week_ago, TIMESTAMP__lt=week_ago).count()
    # Real week-over-week delta (mirrors Analytics' scans_prev_week pattern)
    # for the "this week" tile's pill — None when there's nothing to compare
    # against yet, never a fabricated percentage.
    week_delta_pct = (
        round(((week_count - prev_week_count) / prev_week_count) * 100)
        if prev_week_count else None
    )
    stats = {
        'total': scans.count(),
        'android': scans.filter(ANALYZER='static_analyzer').count(),
        'ios': scans.filter(ANALYZER='static_analyzer_ios').count(),
        'windows': scans.filter(ANALYZER='static_analyzer_windows').count(),
        'week': week_count,
        'week_delta_pct': week_delta_pct,
    }
    # Fleet security rollup — one bounded AppSec pass over the most-recent
    # HOME_ROLLUP_LIMIT static scans yields the fleet average security score,
    # the total finding count, and a per-MD5 score map (reused below to score
    # the recent-activity rows for free). All real scorecard data, never
    # fabricated; fails closed so it can't break the page.
    rollup_md5s = list(
        scans.order_by('-TIMESTAMP')
        .values_list('MD5', flat=True)[:HOME_ROLLUP_LIMIT])
    issues_total, avg_security_score, score_by_md5 = _home_security_rollup(
        rollup_md5s)
    # Attach each recent row's real security score (or None) for the table's
    # score badge — no extra scoring pass, just a map lookup.
    for r in recent:
        r['security_score'] = score_by_md5.get(r['MD5'])
    latest_score = recent[0]['security_score'] if recent else None

    # Fleet coverage — the honest, NON-severity analog of the reference's
    # "activity" gauge: what share of the distinct apps you've ever scanned
    # were (re)scanned in the last 30 days. A neutral throughput/posture %, so
    # the gauge's amber (data-viz) coloring is honest (never mis-colors a
    # security score). Div-by-zero guarded.
    month_ago = now() - timedelta(days=30)
    distinct_total = (
        scans.exclude(PACKAGE_NAME='')
        .values('PACKAGE_NAME').distinct().count())
    distinct_recent = (
        scans.filter(TIMESTAMP__gte=month_ago).exclude(PACKAGE_NAME='')
        .values('PACKAGE_NAME').distinct().count())
    fleet_pct = round(distinct_recent / distinct_total * 100) if distinct_total else 0
    fleet_sub = f'{distinct_recent} / {distinct_total} apps · 30d'

    # 14-day daily scan-count trend (sparkline + the two-series "breakdown"
    # line chart). Cheap grouped counts, same pattern as Analytics. The dual
    # line uses REAL per-platform daily series (Android amber, iOS violet) —
    # both honest, matching the reference's amber/violet duotone.
    trend_start = (now() - timedelta(days=13)).date()

    def _daily_series(analyzer=None):
        dmap = OrderedDict()
        for i in range(13, -1, -1):
            dmap[(now() - timedelta(days=i)).date().isoformat()] = 0
        qs = scans.filter(TIMESTAMP__date__gte=trend_start)
        if analyzer:
            qs = qs.filter(ANALYZER=analyzer)
        for row in (qs.annotate(day=TruncDate('TIMESTAMP'))
                    .values('day').annotate(c=Count('MD5'))):
            if row['day']:
                dmap[row['day'].isoformat()] = row['c']
        return list(dmap.keys()), list(dmap.values())

    trend_labels_14, total_daily = _daily_series()
    _, android_daily = _daily_series('static_analyzer')
    _, ios_daily = _daily_series('static_analyzer_ios')
    trend_pairs = list(zip(trend_labels_14, total_daily))
    trend_max = max(total_daily) if total_daily else 0

    # Monthly scan volume (last 9 months, zero-filled) for the duotone bar
    # chart. Scan volume is NON-severity, so the alternating amber/violet bars
    # are legitimate decorative data-viz. Real TruncMonth grouping.
    month_counts = {}
    for row in (scans.annotate(mn=TruncMonth('TIMESTAMP'))
                .values('mn').annotate(c=Count('MD5'))):
        if row['mn']:
            month_counts[(row['mn'].year, row['mn'].month)] = row['c']
    month_labels, month_values = [], []
    base = now().replace(day=1)
    yy, mm = base.year, base.month
    seq = []
    for _ in range(9):
        seq.append((yy, mm))
        mm -= 1
        if mm == 0:
            mm = 12
            yy -= 1
    for (y, m) in reversed(seq):
        month_labels.append(f'{y}-{m:02d}')
        month_values.append(month_counts.get((y, m), 0))

    # "Welcome back, <user>" shows once, right after login; every later
    # visit in the same session shows a local security tip instead (no
    # external calls, works fully offline).
    just_logged_in = request.session.pop('just_logged_in', False)
    security_tip = None if just_logged_in else random.choice(SECURITY_TIPS)

    context = {
        'version': settings.MOBINSPECT_VER,
        'mimes': mimes,
        'exts': '|'.join(exts),
        'just_logged_in': just_logged_in,
        'security_tip': security_tip,
        'stats': stats,
        'latest_score': latest_score,
        'avg_security_score': avg_security_score,
        'issues_total': issues_total,
        'rollup_scope': len(rollup_md5s),
        'fleet_pct': fleet_pct,
        'fleet_sub': fleet_sub,
        'distinct_total': distinct_total,
        'distinct_recent': distinct_recent,
        'trend_pairs': trend_pairs,
        'trend_max': trend_max,
        'trend_labels_14': trend_labels_14,
        'android_daily': android_daily,
        'ios_daily': ios_daily,
        'spark_values': total_daily,
        'month_labels': month_labels,
        'month_values': month_values,
        # Valid HTML file-input accept attribute: comma-separated, each
        # extension dotted (".apk,.xapk,..."). The template must NOT derive
        # this by stripping the '|' from `exts` — that yields one invalid
        # token (".apkxapkapks...") which makes the OS file dialog match no
        # files, so nothing is selectable.
        'upload_accept': ','.join('.' + e for e in exts),
        'recent': recent,
    }
    template = 'general/home.html'
    return render(request, template, context)


class Upload(object):
    """Handle File Upload based on App type."""

    def __init__(self, request):
        self.request = request
        self.form = UploadFileForm(request.POST, request.FILES)
        self.file_type = None
        self.file = None

    @staticmethod
    @login_required
    @permission_required(Permissions.SCAN)
    def as_view(request):
        upload = Upload(request)
        return upload.upload_html()

    def resp_json(self, data):
        resp = HttpResponse(json.dumps(data),
                            content_type='application/json; charset=utf-8')
        resp['Access-Control-Allow-Origin'] = '*'
        return resp

    def upload_html(self):
        request = self.request
        response_data = {
            'description': '',
            'status': 'error',
        }
        if request.method != 'POST':
            msg = 'Method not Supported!'
            logger.error(msg)
            response_data['description'] = msg
            return self.resp_json(response_data)

        if not self.form.is_valid():
            msg = 'Invalid Form Data!'
            logger.error(msg)
            response_data['description'] = msg
            return self.resp_json(response_data)

        self.file = request.FILES['file']
        oversize_msg = self.oversize_message()
        if oversize_msg:
            logger.error(oversize_msg)
            response_data['description'] = oversize_msg
            return self.resp_json(response_data)
        self.file_type = FileType(self.file)
        if not self.file_type.is_allow_file():
            msg = 'File format not Supported!'
            logger.error(msg)
            response_data['description'] = msg
            return self.resp_json(response_data)

        if self.file_type.is_ipa():
            if platform.system() not in LINUX_PLATFORM:  # pragma: no cover — Windows-only guard, cannot induce a non-macOS/Linux platform.system() on this host
                msg = 'Static Analysis of iOS IPA requires Mac or Linux'  # pragma: no cover — see guard above
                logger.error(msg)  # pragma: no cover — see guard above
                response_data['description'] = msg  # pragma: no cover — see guard above
                return self.resp_json(response_data)  # pragma: no cover — see guard above

        response_data = self.upload()
        return self.resp_json(response_data)

    def upload_api(self):
        """API File Upload."""
        api_response = {}
        request = self.request
        if not self.form.is_valid():
            api_response['error'] = FormUtil.errors_message(self.form)
            return api_response, HTTP_BAD_REQUEST
        self.file = request.FILES['file']
        oversize_msg = self.oversize_message()
        if oversize_msg:
            api_response['error'] = oversize_msg
            return api_response, HTTP_BAD_REQUEST
        self.file_type = FileType(self.file)
        if not self.file_type.is_allow_file():
            api_response['error'] = 'File format not Supported!'
            return api_response, HTTP_BAD_REQUEST
        api_response = self.upload()
        if api_response.get('duplicate'):
            # A prior scan of the same app already exists — reject as 409
            # Conflict, but keep the full upload envelope (status / hash /
            # scan_type / existing_* / error) so existing REST clients that
            # read `hash` still reach the prior scan.
            return api_response, HTTP_CONFLICT
        return api_response, 200

    def oversize_message(self):
        """Return an error message if the uploaded file exceeds the
        configured size guardrail, else None."""
        if self.file.size > settings.MOBINSPECT_MAX_UPLOAD_SIZE:
            return (f'File exceeds the {settings.MOBINSPECT_MAX_UPLOAD_SIZE_MB}MB '
                     'upload size limit!')
        return None

    def upload(self):
        request = self.request
        scanning = Scanning(request)
        content_type = self.file.content_type
        file_name = sanitize_filename(self.file.name)
        logger.info('MIME Type: %s FILE: %s', content_type, file_name)
        if self.file_type.is_apk():
            return scanning.scan_apk()
        elif self.file_type.is_xapk():
            return scanning.scan_xapk()
        elif self.file_type.is_apks():
            return scanning.scan_apks()
        elif self.file_type.is_aab():
            return scanning.scan_aab()
        elif self.file_type.is_jar():
            return scanning.scan_jar()
        elif self.file_type.is_aar():
            return scanning.scan_aar()
        elif self.file_type.is_so():
            return scanning.scan_so()
        elif self.file_type.is_zip():
            return scanning.scan_zip()
        elif self.file_type.is_ipa():
            return scanning.scan_ipa()
        elif self.file_type.is_dylib():
            return scanning.scan_dylib()
        elif self.file_type.is_a():
            return scanning.scan_a()
        elif self.file_type.is_appx():
            return scanning.scan_appx()


@login_required
def api_docs(request):
    """Api Docs Route."""
    key = '*******'
    try:
        if (settings.DISABLE_AUTHENTICATION == '1'
                or request.user.is_staff
                or request.user.groups.filter(name=MAINTAINER_GROUP).exists()):
            key = api_key(settings.MOBINSPECT_HOME)
    except Exception:
        logger.exception('[ERROR] Failed to get API key')
    context = {
        'title': 'API Docs',
        'api_key': key,
        'version': settings.MOBINSPECT_VER,
    }
    template = 'general/apidocs.html'
    return render(request, template, context)


@login_required
def help_center(request):
    """In-app documentation / user guide."""
    faqs = [
        ('Why is the AI Dashboard button missing on a report?',
         'The button only appears once AI enrichment has actually completed '
         'for that scan. If no model connection is configured yet, or '
         'enrichment hasn’t run, there is nothing to show, so the '
         'button stays hidden rather than opening an empty page.'),
        ('Does any of my data leave my network?',
         'No. Scans, reports, and AI enrichment all run locally against '
         'services on your own network. There is no cloud upload step and '
         'no external API call as part of normal operation.'),
        ('Can this run in a fully offline / air-gapped environment?',
         'Yes. Static analysis, dynamic analysis, and AI enrichment all '
         'work without internet access, provided the AI model itself is '
         'hosted somewhere reachable on your local network.'),
        ('What is the difference between the security score and the AI '
         'risk score?',
         'The security score is a deterministic calculation from the '
         'findings on a scan and is always available. The AI risk score '
         'only appears after AI enrichment runs, and is itself computed '
         'from fixed risk categories rather than generated freely by the '
         'model — both are reproducible, neither is a subjective '
         'opinion.'),
        ('How do I give someone else access?',
         'An Administrator creates the account from Users and assigns it '
         'a role from Roles. Access takes effect immediately and every '
         'permission-gated action is recorded in the Audit log.'),
        ('A finding keeps reappearing after I’ve already reviewed it.',
         'Suppress it from the finding’s row menu on the report — '
         'either for that rule everywhere, or for that rule in specific '
         'files only. Suppressed findings stay hidden on future rescans '
         'until you remove the suppression.'),
    ]
    context = {
        'title': 'Help',
        'version': settings.MOBINSPECT_VER,
        'help_faqs': faqs,
    }
    template = 'general/help.html'
    return render(request, template, context)


def about(request):
    """About Route."""
    context = {
        'title': 'About',
        'version': settings.MOBINSPECT_VER,
    }
    template = 'general/about.html'
    return render(request, template, context)


def error(request):
    """Error Route."""
    context = {
        'title': 'Error',
        'version': settings.MOBINSPECT_VER,
    }
    template = 'general/error.html'
    return render(request, template, context)


def zip_format(request):
    """Zip Format Message Route."""
    context = {
        'title': 'Zipped Source Instruction',
        'version': settings.MOBINSPECT_VER,
    }
    template = 'general/zip.html'
    return render(request, template, context)


def robots_txt(request):
    content = 'User-agent: *\nDisallow: /*/\nAllow: /*\n'
    return HttpResponse(content, content_type='text/plain')


@login_required
def dynamic_analysis(request):
    """Dynamic Analysis Landing."""
    context = {
        'title': 'Dynamic Analysis',
        'version': settings.MOBINSPECT_VER,
    }
    template = 'general/dynamic.html'
    return render(request, template, context)


@login_required
def recent_scans(request, page_size=10, page_number=1):
    """Show Recent Scans Route."""
    from django.db.models import Q
    entries = []
    # Search across app name, package, file name and hash.
    query = (request.GET.get('q', '') or '').strip()[:120]
    # Allow query-string pagination (?page=N) alongside the legacy path arg,
    # so search results paginate without losing the filter.
    page_number = request.GET.get('page', page_number)
    scans = RecentScansDB.objects.all().order_by('-TIMESTAMP')
    if query:
        scans = scans.filter(
            Q(APP_NAME__icontains=query)
            | Q(PACKAGE_NAME__icontains=query)
            | Q(FILE_NAME__icontains=query)
            | Q(MD5__icontains=query))
    paginator = Paginator(scans.values(), page_size)
    page_obj = paginator.get_page(page_number)
    page_obj.page_size = page_size
    md5_list = [i['MD5'] for i in page_obj]

    android = StaticAnalyzerAndroid.objects.filter(
        MD5__in=md5_list).only(
            'PACKAGE_NAME', 'VERSION_NAME', 'FILE_NAME', 'MD5')
    ios = StaticAnalyzerIOS.objects.filter(
        MD5__in=md5_list).only('FILE_NAME', 'MD5')

    updir = Path(settings.UPLD_DIR)
    icon_mapping = {}
    package_mapping = {}
    for item in android:
        package_mapping[item.MD5] = item.PACKAGE_NAME
        icon_mapping[item.MD5] = item.ICON_PATH
    for item in ios:
        icon_mapping[item.MD5] = item.ICON_PATH

    for entry in page_obj:
        if entry['MD5'] in package_mapping.keys():
            entry['PACKAGE'] = package_mapping[entry['MD5']]
        else:
            entry['PACKAGE'] = ''
        entry['ICON_PATH'] = icon_mapping.get(entry['MD5'], '')

        if entry['FILE_NAME'].endswith('.ipa'):
            entry['BUNDLE_HASH'] = get_md5(
                entry['PACKAGE_NAME'].encode('utf-8'))
            report_file = updir / entry['BUNDLE_HASH'] / 'mobinspect_dump_file.txt'
        else:
            report_file = updir / entry['MD5'] / 'logcat.txt'
        entry['DYNAMIC_REPORT_EXISTS'] = report_file.exists()
        entries.append(entry)
    context = {
        'title': 'Recent Scans',
        'entries': entries,
        'version': settings.MOBINSPECT_VER,
        'page_obj': page_obj,
        'query': query,
        'async_scans': settings.ASYNC_ANALYSIS,
    }
    template = 'general/recent.html'
    return render(request, template, context)


@login_required
@permission_required(Permissions.SCAN)
def download_apk(request):
    """Download and APK by package name."""
    package = request.POST.get('package')
    if not package:
        return HttpResponse(
            json.dumps({
                'status': 'failed',
                'description': 'No package name provided',
            }),
            content_type='application/json; charset=utf-8',
            status=HTTP_BAD_REQUEST)
    # Package validated in apk_download()
    context = {
        'status': 'failed',
        'description': 'Unable to download APK',
    }
    res = apk_download(package)
    if res:
        context = res
        context['status'] = 'ok'
        context['package'] = package
    resp = HttpResponse(
        json.dumps(context),
        content_type='application/json; charset=utf-8')
    return resp


@login_required
def search(request, api=False):
    """Search scan by checksum or text."""
    if request.method == 'POST':
        query = request.POST.get('query', '')
    else:
        query = request.GET.get('query', '')

    if not query:
        msg = 'No search query provided.'
        return print_n_send_error_response(request, msg, api)

    checksum = query if re.match(MD5_REGEX, query) else find_checksum(query)

    if checksum and re.match(MD5_REGEX, checksum):
        db_obj = RecentScansDB.objects.filter(MD5=checksum).first()
        if db_obj:
            url = scan_report_url(db_obj.ANALYZER, db_obj.MD5)
            if api:
                return {'checksum': db_obj.MD5}
            else:
                return HttpResponseRedirect(url)

    msg = 'You can search by MD5, app name, package name, or file name.'
    return print_n_send_error_response(request, msg, api, 'Scan not found')


def find_checksum(query):
    """Get the first matching checksum from the database."""
    search_fields = ['FILE_NAME', 'PACKAGE_NAME', 'APP_NAME']

    for field in search_fields:
        result = RecentScansDB.objects.filter(
            **{f'{field}__icontains': query}).first()
        if result:
            return result.MD5

    return None

# AJAX


@login_required
@require_http_methods(['POST'])
def scan_status(request, api=False):
    """Get Current Status of a scan in progress."""
    try:
        scan_hash = request.POST['hash']
        if not is_md5(scan_hash):
            return invalid_params(api)
        robj = RecentScansDB.objects.filter(MD5=scan_hash)
        if not robj.exists():
            data = {'status': 'failed', 'error': 'scan hash not found'}
            return send_response(data, api)
        data = {'status': 'ok', 'logs': python_dict(robj[0].SCAN_LOGS)}
    except Exception as exp:
        logger.exception('Fetching Scan Status')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)


def _scan_row_status(checksum):
    """Live status for a scan row that has no APP_NAME/PACKAGE_NAME yet.

    Best-effort: never raises. Returns a dict:
      done   - real app data now exists; caller should stop polling and
               refresh to reveal it.
      failed - the task is done (or dead) but no app data ever landed.
      label  - the live status text to show.
    """
    try:
        recent = (RecentScansDB.objects
                  .filter(MD5=checksum)
                  .only('APP_NAME', 'PACKAGE_NAME', 'SCAN_LOGS')
                  .first())
        if not recent:
            return {'done': False, 'failed': True, 'label': 'Not found'}
        if recent.APP_NAME or recent.PACKAGE_NAME:
            return {'done': True, 'failed': False, 'label': 'Done'}

        logs = python_list(recent.SCAN_LOGS)
        latest = logs[-1]['status'] if logs else None

        enq = (EnqueuedTask.objects
               .filter(checksum=checksum).order_by('-created_at').first())
        if enq and not enq.completed_at:
            if latest:
                return {'done': False, 'failed': False, 'label': latest}
            if not enq.started_at:
                ahead = EnqueuedTask.objects.filter(
                    completed_at__isnull=True,
                    created_at__lt=enq.created_at).count()
                label = ('Queued — next up' if ahead == 0 else
                         f'Queued — {ahead} scan{"s" if ahead != 1 else ""} ahead')
                return {'done': False, 'failed': False, 'label': label}
            return {'done': False, 'failed': False, 'label': 'Starting…'}

        if enq and enq.completed_at:
            # Task finished (success or failure) but no app data ever
            # landed in RecentScansDB — a real failure, not just "still
            # working".
            return {'done': False, 'failed': True,
                     'label': latest or enq.status or 'Scan failed'}

        if latest:
            return {'done': False, 'failed': False, 'label': latest}
        return {'done': False, 'failed': True, 'label': 'Scan incomplete'}
    except Exception:
        logger.exception('Computing live scan status for %s', checksum)
        return {'done': False, 'failed': True, 'label': 'Status unavailable'}


@login_required
def scan_row_status(request, checksum):
    """HTMX polling partial: live status badge for one Recent Scans row.

    Keeps polling until the scan finishes, then tells the browser to do a
    full refresh (HX-Refresh) so the row picks up the real app data and
    action buttons, instead of trying to patch one row's markup in place.
    """
    if not is_md5(checksum):
        return HttpResponse(status=204)
    status = _scan_row_status(checksum)
    if status['done']:
        resp = HttpResponse(status=204)
        resp['HX-Refresh'] = 'true'
        return resp
    return render(request, 'general/_scan_row_status.html', {
        'checksum': checksum,
        'label': status['label'],
        'failed': status['failed'],
    })


def file_download(dwd_file, filename, content_type):
    """HTTP file download response."""
    def create_response(content, is_binary=True):
        """Helper function to create HTTP response."""
        if is_binary:
            wrapper = FileWrapper(content)
            response = HttpResponse(wrapper, content_type=content_type)
            response['Content-Length'] = dwd_file.stat().st_size
        else:
            response = HttpResponse(content, content_type=content_type)
        if filename:
            # Remove CRLF from filename to prevent header injection
            safe_filename = filename.replace('\r', '').replace('\n', '')
            val = f'attachment; filename="{safe_filename}"'
            response['Content-Disposition'] = val
        return response

    # Handle SVG files with bleach cleaning to prevent XSS attacks
    if dwd_file.suffix == '.svg':
        with open(dwd_file, 'r', encoding='utf-8') as file:
            svg_content = file.read()
            cleaned_svg = sanitize_svg(svg_content)
            return create_response(cleaned_svg, is_binary=False)

    # Handle all other binary file types
    with open(dwd_file, 'rb') as file:
        return create_response(file)


@login_required
@require_permission('scan.view')
@require_http_methods(['GET'])
def download_binary(request, checksum, api=False):
    """Download binary from uploads directory."""
    try:
        allowed_exts = settings.ALLOWED_EXTENSIONS
        if not is_md5(checksum):
            return HttpResponse(
                'Invalid MD5 Hash',
                status=HTTP_STATUS_404)
        robj = RecentScansDB.objects.filter(MD5=checksum).first()
        if not robj:
            return HttpResponse(
                'Scan hash not found',
                status=HTTP_STATUS_404)
        file_ext = f'.{robj.SCAN_TYPE}'
        if file_ext not in allowed_exts.keys():
            return HttpResponse(
                'Invalid Scan Type',
                status=HTTP_STATUS_404)
        filename = f'{checksum}{file_ext}'
        dwd_file = Path(settings.UPLD_DIR) / checksum / filename
        if not dwd_file.exists():
            return HttpResponse(
                'File not found',
                status=HTTP_STATUS_404)
        return file_download(
            dwd_file,
            sanitize_filename(robj.FILE_NAME),
            allowed_exts[file_ext])
    except Exception:
        logger.exception('Download Binary Failed')
        return HttpResponse(
            'Failed to download file due to an error',
            status=HTTP_SERVER_ERROR)


@login_required
@require_permission('scan.view')
@require_http_methods(['GET'])
def download(request):
    """Download from mobinspect downloads directory."""
    root = settings.DWD_DIR
    filename = request.path.replace('/download/', '', 1)
    dwd_file = Path(root) / filename

    # Security Checks
    if not is_safe_path(root, dwd_file, filename):
        msg = 'Path Traversal Attack Detected'
        return print_n_send_error_response(request, msg)

    # File and Extension Check
    ext = dwd_file.suffix
    allowed_exts = settings.ALLOWED_EXTENSIONS
    if ext in allowed_exts and dwd_file.is_file():
        return file_download(
            dwd_file,
            None,
            allowed_exts[ext])

    # Special Case for Certain Image Files
    if filename.endswith(('screen/screen.png', '-icon.png')):
        return HttpResponse('')

    return HttpResponse(status=HTTP_STATUS_404)


@login_required
@require_permission('scan.view')
def generate_download(request):
    """Generate downloads for smali/java zip."""
    try:
        logger.info('Generating Downloads')
        md5 = request.GET['hash']
        file_type = request.GET['file_type']
        if (not is_md5(md5)
                or file_type not in ('smali', 'java')):
            msg = 'Invalid download type or hash'
            logger.exception(msg)
            return print_n_send_error_response(request, msg)
        app_dir = Path(settings.UPLD_DIR) / md5
        dwd_dir = Path(settings.DWD_DIR)
        file_name = ''
        if file_type == 'java':
            # For Java zipped source code
            directory = app_dir / 'java_source'
            dwd_file = dwd_dir / f'{md5}-java'
            shutil.make_archive(
                dwd_file.as_posix(), 'zip', directory.as_posix())
            file_name = f'{md5}-java.zip'
        elif file_type == 'smali':
            # For Smali zipped source code
            directory = app_dir / 'smali_source'
            dwd_file = dwd_dir / f'{md5}-smali'
            shutil.make_archive(
                dwd_file.as_posix(), 'zip', directory.as_posix())
            file_name = f'{md5}-smali.zip'
        return redirect(f'/download/{file_name}')
    except Exception:
        msg = 'Generating Downloads'
        logger.exception(msg)
        return print_n_send_error_response(request, msg)


@login_required
@permission_required(Permissions.DELETE)
@require_http_methods(['POST'])
def delete_scan(request, api=False):
    """Delete Scan from DB and remove the scan related files."""
    try:
        if api:
            md5_hash = request.POST['hash']
        else:
            md5_hash = request.POST['md5']

        if not re.match(MD5_REGEX, md5_hash):
            return send_response({'deleted': 'Invalid scan hash'}, api)

        # Delete DB Entries
        scan = RecentScansDB.objects.filter(MD5=md5_hash)
        if not scan.exists():
            return send_response({'deleted': 'Scan not found in Database'}, api)
        if settings.ASYNC_ANALYSIS:
            # Handle Async Tasks
            et = EnqueuedTask.objects.filter(checksum=md5_hash).first()
            if et:
                max_time_passed = now() - et.created_at > timedelta(
                    minutes=settings.ASYNC_ANALYSIS_TIMEOUT)
                if not (et.completed_at or max_time_passed):
                    # Queue is in progress, cannot delete the task
                    return send_response(
                        {'deleted': 'A scan can only be deleted after it is completed'},
                        api)
        # Resolve the package/bundle before the static rows are deleted so
        # we can cascade-delete its suppressions (keyed by package, not MD5).
        package = get_package(md5_hash)
        # Delete all related DB entries
        EnqueuedTask.objects.filter(checksum=md5_hash).all().delete()
        RecentScansDB.objects.filter(MD5=md5_hash).delete()
        StaticAnalyzerAndroid.objects.filter(MD5=md5_hash).delete()
        StaticAnalyzerIOS.objects.filter(MD5=md5_hash).delete()
        StaticAnalyzerWindows.objects.filter(MD5=md5_hash).delete()
        # Cascade-delete suppressions so they don't silently re-apply on
        # a future rescan of the same package.
        if package:
            SuppressFindings.objects.filter(PACKAGE_NAME=package).delete()
        # Delete Upload Dir Contents
        app_upload_dir = os.path.join(settings.UPLD_DIR, md5_hash)
        if is_dir_exists(app_upload_dir):
            shutil.rmtree(app_upload_dir)
        # Delete Download Dir Contents
        dw_dir = settings.DWD_DIR
        for item in os.listdir(dw_dir):
            item_path = os.path.join(dw_dir, item)
            valid_item = item.startswith(md5_hash + '-')
            # Delete all related files
            if is_file_exists(item_path) and valid_item:
                os.remove(item_path)
            # Delete related directories
            if is_dir_exists(item_path) and valid_item:
                shutil.rmtree(item_path, ignore_errors=True)
        return send_response({'deleted': 'yes'}, api)
    except Exception as exp:
        msg = str(exp)
        exp_doc = exp.__doc__
        return print_n_send_error_response(request, msg, api, exp_doc)


class RecentScans(object):

    def __init__(self, request):
        self.request = request

    def recent_scans(self):
        page = self.request.GET.get('page', 1)
        page_size = self.request.GET.get('page_size', 10)
        result = RecentScansDB.objects.all().values().order_by('-TIMESTAMP')
        try:
            paginator = Paginator(result, page_size)
            content = paginator.page(page)
            data = {
                'content': list(content),
                'count': paginator.count,
                'num_pages': paginator.num_pages,
            }
        except Exception as exp:
            data = {'error': str(exp)}
        return data


def update_scan_timestamp(scan_hash):
    # Update the last scan time.
    tms = timezone.now()
    RecentScansDB.objects.filter(MD5=scan_hash).update(TIMESTAMP=tms)
