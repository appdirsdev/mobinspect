# -*- coding: utf_8 -*-
"""Real-execution coverage tests for the `stats` dict built by
mobsf.MobSF.views.home.index().

Scope (deliberately narrow — does not duplicate test_cov_home.py):
  * total / android / ios / windows counts split correctly by the
    RecentScansDB.ANALYZER column (the same key report links use).
  * "week" counts only scans whose TIMESTAMP falls in the trailing 7
    days, real timestamps, no frozen clock / no mocking of `now()`.
  * GET / returns 200 and the `stats` dict lands in the template
    context with the exact expected values.
  * Adversarial ANALYZER values (SQLi-shaped strings, XSS-shaped
    strings, case-variant strings) must not crash the view and must
    not be miscounted into a platform bucket they don't exactly match
    — RecentScansDB is a security-scanner table an attacker-controlled
    upload pipeline could, in principle, poison.

Everything here drives the REAL Django view (`home.index`) against the
real (isolated, per-test) database via the ORM — no mocks. `now()` is
the real `django.utils.timezone.now()`; the DB rows are created with
that same real clock offset by real `timedelta`s, so the boundary
tests are correct without pinning the clock.
"""
from datetime import timedelta

import pytest

from django.contrib.auth import get_user_model
from django.test import Client, RequestFactory
from django.utils.timezone import now

from mobsf.MobSF.views import home
from mobsf.StaticAnalyzer.models import RecentScansDB


ANDROID = 'static_analyzer'
IOS = 'static_analyzer_ios'
WINDOWS = 'static_analyzer_windows'


def _mk(md5, analyzer=ANDROID, ts=None, **kw):
    """Create a real RecentScansDB row with an explicit, tz-aware TIMESTAMP."""
    defaults = dict(
        ANALYZER=analyzer,
        SCAN_TYPE='apk',
        FILE_NAME='sample.apk',
        APP_NAME='Sample',
        PACKAGE_NAME='com.example.sample',
        VERSION_NAME='1.0',
        MD5=md5,
        SCAN_LOGS='[]',
        TIMESTAMP=ts if ts is not None else now(),
    )
    defaults.update(kw)
    return RecentScansDB.objects.create(**defaults)


@pytest.fixture
def su_client(db, django_user_model):
    """A real superuser, logged in through the real Django test Client."""
    user = django_user_model.objects.create_superuser(
        'cov_stats_admin', 'cov_stats_admin@example.com', 'cov_stats_admin')
    client = Client()
    client.force_login(user)
    return client


@pytest.fixture
def authed_request(db):
    """Build a real GET request carrying an authenticated superuser, for
    calling home.index() directly (bypasses URL dispatch / middleware,
    useful when we only care about the returned context)."""
    User = get_user_model()
    user = User.objects.create_superuser(
        'cov_stats_direct', 'cov_stats_direct@example.com', 'cov_stats_direct')
    factory = RequestFactory()

    def _make(path='/'):
        req = factory.get(path)
        req.user = user
        return req
    return _make


# ─────────────────────────────────────────────────────────── empty state
@pytest.mark.django_db
def test_stats_all_zero_when_no_scans(su_client):
    """No RecentScansDB rows at all -> every counter is exactly 0."""
    resp = su_client.get('/')
    assert resp.status_code == 200
    stats = resp.context['stats']
    assert stats == {
        'total': 0,
        'android': 0,
        'ios': 0,
        'windows': 0,
        'week': 0,
        # No prior-week scans to compare against -> None, never a fabricated 0%.
        'week_delta_pct': None,
    }


# ────────────────────────── redesign aggregates (dashboard mirror) ──────────
@pytest.mark.django_db
def test_dashboard_aggregates_empty_db_are_honest_zeros(su_client):
    """The redesigned dashboard's new real-data aggregates must degrade to
    honest empties on a zero-scan DB — never a fabricated value or a
    div-by-zero. Renders 200 (the whole point: no crash on the new code)."""
    resp = su_client.get('/')
    assert resp.status_code == 200
    ctx = resp.context
    assert ctx['issues_total'] == 0
    assert ctx['avg_security_score'] is None      # nothing scored -> None, not 0
    assert ctx['fleet_pct'] == 0                   # div-by-zero guarded
    assert ctx['distinct_total'] == 0
    assert ctx['distinct_recent'] == 0
    # Time series are zero-filled real windows, not empty/None.
    assert ctx['android_daily'] == [0] * 14
    assert ctx['ios_daily'] == [0] * 14
    assert ctx['spark_values'] == [0] * 14
    assert len(ctx['month_labels']) == 9 and ctx['month_values'] == [0] * 9


@pytest.mark.django_db
def test_dashboard_aggregates_reflect_real_rows(su_client):
    """With real RecentScansDB rows, the new aggregates compute from the DB —
    fleet coverage, distinct-app counts, per-platform daily series, and the
    current month's volume all reflect the real rows (no StaticAnalyzer rows
    exist here, so avg_security_score honestly stays None)."""
    # Two distinct Android apps today, one older iOS app (distinct package).
    _mk('a' * 32, analyzer=ANDROID, PACKAGE_NAME='com.a')
    _mk('b' * 32, analyzer=ANDROID, PACKAGE_NAME='com.b')
    _mk('c' * 32, analyzer=IOS, PACKAGE_NAME='com.c', ts=now() - timedelta(days=2))

    resp = su_client.get('/')
    assert resp.status_code == 200
    ctx = resp.context

    assert ctx['distinct_total'] == 3          # com.a / com.b / com.c
    assert ctx['distinct_recent'] == 3         # all within 30 days
    assert ctx['fleet_pct'] == 100             # 3 / 3
    # Per-platform daily windows (14 days) sum to the real per-platform counts.
    assert sum(ctx['android_daily']) == 2
    assert sum(ctx['ios_daily']) == 1
    assert sum(ctx['spark_values']) == 3       # total across both platforms
    # Current month's bucket holds all 3 scans.
    assert ctx['month_values'][-1] == 3
    # No StaticAnalyzer scorecards exist for these MD5s -> honest None, not 0.
    assert ctx['avg_security_score'] is None
    assert ctx['issues_total'] == 0


# ─────────────────────────────────────────────────────── platform split
@pytest.mark.django_db
def test_stats_platform_split_counts_correctly(su_client):
    """Two android, one ios, three windows -> exact bucket counts, and
    total == sum of all rows regardless of platform."""
    _mk('a' * 32, analyzer=ANDROID)
    _mk('b' * 32, analyzer=ANDROID)
    _mk('c' * 32, analyzer=IOS)
    _mk('d' * 32, analyzer=WINDOWS)
    _mk('e' * 32, analyzer=WINDOWS)
    _mk('f' * 32, analyzer=WINDOWS)

    resp = su_client.get('/')
    stats = resp.context['stats']
    assert stats['total'] == 6
    assert stats['android'] == 2
    assert stats['ios'] == 1
    assert stats['windows'] == 3
    # android + ios + windows accounts for every row here (no unknown
    # ANALYZER values in this dataset).
    assert stats['android'] + stats['ios'] + stats['windows'] == stats['total']


@pytest.mark.django_db
def test_stats_unknown_analyzer_counts_in_total_only(su_client):
    """A row whose ANALYZER matches none of the three known platform
    filters must still be counted in 'total', but not attributed to
    any platform bucket — the view must not silently misclassify it."""
    _mk('1' * 32, analyzer=ANDROID)
    _mk('2' * 32, analyzer='some_future_analyzer')
    _mk('3' * 32, analyzer='')

    resp = su_client.get('/')
    stats = resp.context['stats']
    assert stats['total'] == 3
    assert stats['android'] == 1
    assert stats['ios'] == 0
    assert stats['windows'] == 0
    # 2 rows are "orphaned" from the platform split by design.
    assert stats['total'] - (stats['android'] + stats['ios'] + stats['windows']) == 2


@pytest.mark.django_db
def test_stats_analyzer_match_is_case_sensitive(su_client):
    """ANALYZER filter is an exact-match ORM filter, not case-insensitive.
    A case-mismatched value must NOT be attributed to the android bucket
    (guards against a future accidental __iexact regression that could
    misclassify security-scan platform data)."""
    _mk('4' * 32, analyzer='STATIC_ANALYZER')
    _mk('5' * 32, analyzer='Static_Analyzer_IOS')
    _mk('6' * 32, analyzer='STATIC_ANALYZER_WINDOWS')

    resp = su_client.get('/')
    stats = resp.context['stats']
    assert stats['total'] == 3
    assert stats['android'] == 0
    assert stats['ios'] == 0
    assert stats['windows'] == 0


# ────────────────────────────────────────────────────── adversarial input
@pytest.mark.django_db
def test_stats_survives_sqli_shaped_analyzer_value(su_client):
    """A SQL-injection-shaped ANALYZER string must not crash the ORM
    filter (parameterized queries) and must not be misattributed."""
    payload = "static_analyzer'; DROP TABLE recent_scans_db; --"
    _mk('7' * 32, analyzer=payload)
    _mk('8' * 32, analyzer=ANDROID)

    resp = su_client.get('/')
    assert resp.status_code == 200
    stats = resp.context['stats']
    assert stats['total'] == 2
    assert stats['android'] == 1
    # The table must still exist and hold both rows — proves no SQL
    # actually executed out-of-band.
    assert RecentScansDB.objects.count() == 2


@pytest.mark.django_db
def test_stats_survives_xss_shaped_analyzer_value(su_client):
    """An XSS-shaped ANALYZER string is treated as inert data by the
    ORM filter/count path — no template execution happens in stats
    aggregation, so it simply lands in 'total' as an unmatched value."""
    payload = '<script>alert(document.cookie)</script>'
    _mk('9' * 32, analyzer=payload)

    resp = su_client.get('/')
    stats = resp.context['stats']
    assert stats['total'] == 1
    assert stats['android'] == 0
    assert stats['ios'] == 0
    assert stats['windows'] == 0


@pytest.mark.django_db
def test_stats_survives_punctuation_and_unicode_analyzer_values(su_client):
    """Punctuation-laced and non-ASCII ANALYZER values (never something
    a legitimate scan would set, but the field is a plain
    CharField(max_length=50)) must not raise and must still be tallied
    into total. Payloads stay within max_length deliberately — Postgres
    (unlike SQLite) enforces varchar(50) at the DB layer, and a real
    attacker-controlled write path would hit the same constraint, so
    exceeding it would test Postgres, not home.py's stats aggregation."""
    weird_payload = ('$' * 20) + 'DROP;--'  # 27 chars, well within 50
    unicode_payload = 'ANALYZER_名前_😀_' + ('a' * 10)  # multi-byte UTF-8
    _mk('a1' + '0' * 30, analyzer=weird_payload)
    _mk('a2' + '0' * 30, analyzer=unicode_payload)

    resp = su_client.get('/')
    assert resp.status_code == 200
    stats = resp.context['stats']
    assert stats['total'] == 2
    assert stats['android'] == 0


# ─────────────────────────────────────────────────────────────── week window
@pytest.mark.django_db
def test_stats_week_includes_recent_and_excludes_older_than_week(su_client):
    """week = count of scans with TIMESTAMP >= now() - 7 days.
    A scan from 6 days ago must be included; one from 8 days ago must
    not — using generous 1-day margins around the boundary to keep the
    assertion robust against the real wall-clock elapsing between our
    snapshot and the view's own now() call."""
    _mk('b1' + '0' * 30, ts=now() - timedelta(days=6))
    _mk('b2' + '0' * 30, ts=now() - timedelta(hours=1))
    _mk('b3' + '0' * 30, ts=now())
    _mk('b4' + '0' * 30, ts=now() - timedelta(days=8))
    _mk('b5' + '0' * 30, ts=now() - timedelta(days=30))

    resp = su_client.get('/')
    stats = resp.context['stats']
    assert stats['total'] == 5
    assert stats['week'] == 3


@pytest.mark.django_db
def test_stats_week_is_independent_of_platform(su_client):
    """The week counter must count across ALL platforms, not just one —
    mix recent windows/ios rows with an old android row and confirm the
    week bucket isn't accidentally scoped to a single ANALYZER filter."""
    _mk('c1' + '0' * 30, analyzer=WINDOWS, ts=now() - timedelta(days=1))
    _mk('c2' + '0' * 30, analyzer=IOS, ts=now() - timedelta(days=2))
    _mk('c3' + '0' * 30, analyzer=ANDROID, ts=now() - timedelta(days=20))

    resp = su_client.get('/')
    stats = resp.context['stats']
    assert stats['total'] == 3
    assert stats['week'] == 2
    assert stats['windows'] == 1
    assert stats['ios'] == 1
    assert stats['android'] == 1


@pytest.mark.django_db
def test_stats_week_zero_when_all_scans_are_old(su_client):
    """All rows older than 7 days -> week is 0, but total still counts
    them (week is a strict subset filter, never inflates total)."""
    _mk('d1' + '0' * 30, ts=now() - timedelta(days=10))
    _mk('d2' + '0' * 30, ts=now() - timedelta(days=365))

    resp = su_client.get('/')
    stats = resp.context['stats']
    assert stats['total'] == 2
    assert stats['week'] == 0


@pytest.mark.django_db
def test_stats_week_can_equal_total_when_all_scans_recent(su_client):
    """All rows within the trailing 7 days -> week == total."""
    _mk('e1' + '0' * 30, ts=now())
    _mk('e2' + '0' * 30, ts=now() - timedelta(minutes=5))
    _mk('e3' + '0' * 30, ts=now() - timedelta(days=3))

    resp = su_client.get('/')
    stats = resp.context['stats']
    assert stats['total'] == 3
    assert stats['week'] == 3


@pytest.mark.django_db
def test_week_delta_pct_computed_against_real_prior_week(su_client):
    """week_delta_pct compares the trailing week to the 7-day window before
    it: 4 scans this week vs 2 the week before -> +100%, exactly
    round(((4-2)/2)*100). Real week+prev_week rows, not a mocked ratio."""
    for h in (1, 2, 3, 4):
        _mk(f'g{h}' + '0' * 30, ts=now() - timedelta(hours=h))
    for d in (8, 9):
        _mk(f'g{d}' + '0' * 30, ts=now() - timedelta(days=d))

    resp = su_client.get('/')
    stats = resp.context['stats']
    assert stats['week'] == 4
    assert stats['week_delta_pct'] == 100


@pytest.mark.django_db
def test_week_delta_pct_negative_when_activity_drops(su_client):
    """1 scan this week vs 4 the week before -> a real negative delta,
    round(((1-4)/4)*100) = -75, not clamped or fabricated positive."""
    _mk('h9' + '0' * 30, ts=now() - timedelta(hours=1))
    for i, d in enumerate((8, 9, 10, 11)):
        _mk(f'h{i}' + '0' * 30, ts=now() - timedelta(days=d))

    resp = su_client.get('/')
    stats = resp.context['stats']
    assert stats['week'] == 1
    assert stats['week_delta_pct'] == -75


# ───────────────────────────────────────────────────── combined / realistic
@pytest.mark.django_db
def test_stats_combined_realistic_dataset(su_client):
    """A realistic mixed dataset: multiple platforms, some inside and
    some outside the trailing week, verifying every counter at once
    against hand-computed expected values."""
    # Android: 2 within the trailing week (2h, 4d ago), 1 well outside it.
    _mk('f1' + '0' * 30, analyzer=ANDROID, ts=now() - timedelta(hours=2))
    _mk('f2' + '0' * 30, analyzer=ANDROID, ts=now() - timedelta(days=4))
    _mk('f3' + '0' * 30, analyzer=ANDROID, ts=now() - timedelta(days=40))
    # iOS: 1 within the week, 1 well outside it.
    _mk('f4' + '0' * 30, analyzer=IOS, ts=now() - timedelta(days=1))
    _mk('f5' + '0' * 30, analyzer=IOS, ts=now() - timedelta(days=15))
    # Windows: 1 outside the week only.
    _mk('f6' + '0' * 30, analyzer=WINDOWS, ts=now() - timedelta(days=9))
    # Unknown analyzer, recent -> counts in total + week, no platform bucket.
    _mk('f7' + '0' * 30, analyzer='other', ts=now() - timedelta(hours=1))

    resp = su_client.get('/')
    stats = resp.context['stats']
    assert stats['total'] == 7
    assert stats['android'] == 3
    assert stats['ios'] == 2
    assert stats['windows'] == 1
    # In-week rows (TIMESTAMP >= now - 7 days): f1 (2h), f2 (4d), f4 (1d),
    # f7 (1h) = 4. f3 (40d), f5 (15d), f6 (9d) are all outside the window.
    assert stats['week'] == 4


# ─────────────────────────────────────────────────── direct view invocation
@pytest.mark.django_db
def test_index_view_called_directly_renders_stats_into_html(authed_request):
    """Call home.index() directly (bypassing URL dispatch / the test
    Client's template-render signal capture) to confirm the *rendered
    HTML body* actually carries the computed counters — proving the
    stats dict is genuinely threaded through render(), not just built
    and discarded."""
    # 4 scans total; one is older than 7 days so "this week" is a DISTINCT
    # number (3) from the total (4) — makes each counter substring an
    # unambiguous signal that the real computed count reached the template.
    _mk('11' + '0' * 30, analyzer=ANDROID)
    _mk('12' + '0' * 30, analyzer=ANDROID)
    _mk('13' + '0' * 30, analyzer=IOS)
    _mk('14' + '0' * 30, analyzer=WINDOWS, ts=now() - timedelta(days=10))

    req = authed_request('/')
    resp = home.index(req)
    assert resp.status_code == 200
    body = resp.content.decode('utf-8')
    # The redesigned KPI strip renders stats.total and stats.week as literal
    # numbers via Alpine's x-data="counter(N)". Distinct values (total=4,
    # week=3) prove the real computed counts reached the template.
    assert 'x-data="counter(4)"' in body  # stats.total == 4
    assert 'x-data="counter(3)"' in body  # stats.week == 3
    # And the redesigned KPI labels are present (not the old tile set).
    assert 'Total scans' in body
    assert 'Apps tracked' in body


@pytest.mark.django_db
def test_index_get_root_returns_200_via_client(su_client):
    """Baseline: GET / is 200 and stats is present with all five keys,
    regardless of dataset size (covers the truly-empty DB path via the
    real Client + full middleware stack, not a direct call)."""
    resp = su_client.get('/')
    assert resp.status_code == 200
    assert set(resp.context['stats'].keys()) == {
        'total', 'android', 'ios', 'windows', 'week', 'week_delta_pct'}


@pytest.mark.django_db
def test_index_requires_authentication(client):
    """Anonymous GET / must not reach the stats-building code path at
    all — login_required must redirect (302) rather than 200."""
    resp = client.get('/')
    assert resp.status_code == 302
