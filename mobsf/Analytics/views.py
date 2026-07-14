"""
MobInspect — Analytics dashboard.

Fast, single-page overview answering:
  - What's happening now? (KPI strip)
  - How are we trending? (scan-trends chart)
  - How is the fleet distributed? (platform breakdown, top apps)
  - Where's risk concentrated? (severity rollup over recent scans)
  - Are we keeping up? (fleet health)

Throughput metrics are computed from RecentScansDB. The severity rollup is
aggregated on demand from the AppSec scorecard (get_*_dashboard) over a bounded
window of the most recent scans. No materialized rollups (yet — tracked in
docs/06-analytics-spec.md).
"""
import logging
from collections import OrderedDict
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.shortcuts import render
from django.utils import timezone

from mobsf.RBAC.decorators import require_permission
from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
    StaticAnalyzerWindows,
)
from mobsf.StaticAnalyzer.views.common.appsec import (
    SCORE_AVERAGE_EXCLUDED_SCAN_TYPES,
    get_android_dashboard,
    get_ios_dashboard,
)

logger = logging.getLogger(__name__)

# Cap how many recent scans we score for the severity rollup. Each entry is
# deserialized and run through the AppSec scorecard, so this is bounded to keep
# the dashboard responsive regardless of total scan volume.
SEVERITY_ROLLUP_LIMIT = 100


def _severity_rollup():
    """Aggregate severity counts and security scores over recent static scans.

    Sources counts from the AppSec scorecard (the same finding buckets and
    ``security_score`` shown on the per-app scorecard) for the most recently
    scanned Android and iOS apps, bounded by SEVERITY_ROLLUP_LIMIT. A single
    pass over each platform's queryset feeds both the severity rollup and the
    average-security-score metric (no extra queries).

    All five scorecard buckets are aggregated (``high``, ``warning``, ``info``,
    ``secure``, ``hotspot``) so the dashboard totals reconcile exactly with the
    per-app scorecard's "Findings summary". ``hotspot`` collects the same
    investigate-class findings the scorecard surfaces (dangerous permissions,
    hardcoded secrets, OFAC domains, certificate/key files, trackers under
    EFR_01), so dropping it would silently undercount.

    Returns ``(counts, apps_scored, scores)`` where ``counts`` is a dict of
    severity -> finding count, ``apps_scored`` is the number of apps run through
    the scorecard, and ``scores`` is the list of per-app security scores.
    """
    counts = {'high': 0, 'warning': 0, 'info': 0, 'secure': 0, 'hotspot': 0}
    scores = []
    apps_scored = 0

    recent = list(
        RecentScansDB.objects
        .order_by('-TIMESTAMP')
        .values_list('MD5', 'SCAN_TYPE')[:SEVERITY_ROLLUP_LIMIT]
    )
    if not recent:
        return counts, apps_scored, scores
    recent_md5 = [md5 for md5, _ in recent]
    scan_type_by_md5 = dict(recent)

    android = StaticAnalyzerAndroid.objects.filter(MD5__in=recent_md5)
    ios = StaticAnalyzerIOS.objects.filter(MD5__in=recent_md5)

    for entry in android:
        try:
            findings = get_android_dashboard([entry])
        except Exception:
            logger.exception(
                'Severity rollup failed for Android %s', entry.MD5)
            continue
        for sev in counts:
            counts[sev] += len(findings.get(sev) or [])
        score = findings.get('security_score')
        scan_type = scan_type_by_md5.get(entry.MD5)
        if score is not None and scan_type not in SCORE_AVERAGE_EXCLUDED_SCAN_TYPES:
            scores.append(score)
        apps_scored += 1

    for entry in ios:
        try:
            findings = get_ios_dashboard([entry])
        except Exception:
            logger.exception('Severity rollup failed for iOS %s', entry.MD5)
            continue
        for sev in counts:
            counts[sev] += len(findings.get(sev) or [])
        score = findings.get('security_score')
        scan_type = scan_type_by_md5.get(entry.MD5)
        if score is not None and scan_type not in SCORE_AVERAGE_EXCLUDED_SCAN_TYPES:
            scores.append(score)
        apps_scored += 1

    return counts, apps_scored, scores


@login_required
@require_permission('analytics.view')
def dashboard(request):
    """Render the analytics dashboard."""
    now = timezone.now()
    week_start = now - timedelta(days=7)
    prev_week  = now - timedelta(days=14)
    month_start = now - timedelta(days=30)

    total_scans     = RecentScansDB.objects.count()
    scans_this_week = RecentScansDB.objects.filter(
        TIMESTAMP__gte=week_start,
    ).count()
    scans_prev_week = RecentScansDB.objects.filter(
        TIMESTAMP__gte=prev_week, TIMESTAMP__lt=week_start,
    ).count()

    # 30-day daily trend (server-aggregated; suitable up to ~10k scans)
    daily = (
        RecentScansDB.objects
        .filter(TIMESTAMP__gte=month_start)
        .annotate(day=TruncDate('TIMESTAMP'))
        .values('day')
        .annotate(c=Count('MD5'))
        .order_by('day')
    )
    daily_map = OrderedDict()
    for i in range(29, -1, -1):
        d = (now - timedelta(days=i)).date()
        daily_map[d.isoformat()] = 0
    for row in daily:
        if row['day']:
            daily_map[row['day'].isoformat()] = row['c']
    trend_labels = list(daily_map.keys())
    trend_values = list(daily_map.values())
    # Last-14-days window for the dot-matrix widget (components/dot_matrix.html):
    # a real subset of the same daily counts above, zipped into (label, value)
    # pairs so the template can iterate with tuple unpacking (Django template
    # dot-lookup can't index a list by a loop variable), plus the window's
    # own max so each column scales honestly against what actually happened.
    trend_recent_labels = trend_labels[-14:]
    trend_recent_values = trend_values[-14:]
    trend_recent_pairs = list(zip(trend_recent_labels, trend_recent_values))
    trend_recent_max = max(trend_recent_values) if trend_recent_values else 0

    # Platform breakdown (from RecentScansDB SCAN_TYPE)
    platform_rows = (
        RecentScansDB.objects
        .values('SCAN_TYPE')
        .annotate(c=Count('MD5'))
        .order_by('-c')
    )
    platform = {row['SCAN_TYPE'] or 'unknown': row['c'] for row in platform_rows}

    # Top apps by scan count
    top_apps = (
        RecentScansDB.objects
        .exclude(PACKAGE_NAME='')
        .values('PACKAGE_NAME', 'APP_NAME')
        .annotate(c=Count('MD5'))
        .order_by('-c')[:10]
    )

    # Fleet health: distinct packages scanned in last 30d / total
    distinct_recent = (
        RecentScansDB.objects
        .filter(TIMESTAMP__gte=month_start)
        .exclude(PACKAGE_NAME='')
        .values('PACKAGE_NAME')
        .distinct()
        .count()
    )
    distinct_total = (
        RecentScansDB.objects
        .exclude(PACKAGE_NAME='')
        .values('PACKAGE_NAME')
        .distinct()
        .count()
    )
    fleet_pct = (
        round(distinct_recent / distinct_total * 100, 1)
        if distinct_total else 0.0
    )

    # Recent activity — last 12 scans
    recent = (
        RecentScansDB.objects
        .order_by('-TIMESTAMP')[:12]
        .values('MD5', 'APP_NAME', 'PACKAGE_NAME', 'FILE_NAME',
                'TIMESTAMP', 'SCAN_TYPE', 'ANALYZER')
    )

    delta_pct = (
        round((scans_this_week - scans_prev_week) / scans_prev_week * 100, 1)
        if scans_prev_week else None
    )

    # Severity rollup over the most recent static scans (AppSec scorecard).
    # The same pass yields per-app security scores so the average is consistent
    # with the per-app scorecard numbers.
    severity_counts, severity_apps, severity_scores = _severity_rollup()
    severity_total = sum(severity_counts.values())
    avg_security_score = (
        round(sum(severity_scores) / len(severity_scores))
        if severity_scores else None
    )

    context = {
        'title': 'Analytics',
        'kpis': {
            'total_scans':     total_scans,
            'scans_this_week': scans_this_week,
            'scans_prev_week': scans_prev_week,
            'delta_pct':       delta_pct,
            'distinct_apps':   distinct_total,
            'fleet_pct':       fleet_pct,
            'android':         StaticAnalyzerAndroid.objects.count(),
            'ios':             StaticAnalyzerIOS.objects.count(),
            'windows':         StaticAnalyzerWindows.objects.count(),
        },
        'trend_labels':  trend_labels,
        'trend_values':  trend_values,
        'trend_recent_pairs': trend_recent_pairs,
        'trend_recent_max':   trend_recent_max,
        'platform':      platform,
        'severity':      severity_counts,
        'severity_total': severity_total,
        'severity_apps': severity_apps,
        'severity_limit': SEVERITY_ROLLUP_LIMIT,
        'avg_security_score': avg_security_score,
        'top_apps':      list(top_apps),
        'recent':        list(recent),
        'fleet_recent':  distinct_recent,
        'fleet_total':   distinct_total,
    }
    return render(request, 'analytics/dashboard.html', context)
