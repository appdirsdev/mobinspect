"""Coverage close-out for mobinspect/Analytics/views.py's `_severity_rollup`.

Complements the smoke tests in test_dashboard.py, which only ever seed
Android scans. Closes the branches `_severity_rollup` never otherwise
reaches:

  * the empty-RecentScansDB early return (`if not recent: return counts,
    apps_scored, scores`) -- already pinned by test_dashboard.py's
    `test_dashboard_empty_db_renders_200`, mirrored here because that file
    lives outside the test_cov_* coverage glob the campaign run scores.
  * the iOS half of the loop, success path (a real StaticAnalyzerIOS +
    RecentScansDB row that `get_ios_dashboard` can actually score)
  * the iOS `except Exception: ... continue` guard -- reached FOR REAL,
    no mock needed: a StaticAnalyzerIOS row left at its model defaults has
    `BINARY_ANALYSIS` default to `[]` (a list), but appsec.get_ios_dashboard
    always wraps it through `process_suppression()` and then indexes
    `data['binary_analysis']['findings'].items()`, which only works for a
    dict-shaped payload -- a real, organic AttributeError. This is a
    realistic shape too (an in-flight/incomplete scan row), which is
    exactly the kind of per-app failure `_severity_rollup`'s guard exists
    to isolate.
  * the Android `except Exception: ... continue` guard -- Android's
    CERTIFICATE_ANALYSIS default IS a dict (`{}`), so the same organic
    trick doesn't reproduce the failure there; `get_android_dashboard`
    (the exact name imported into mobinspect.Analytics.views) is instead
    narrowly monkeypatched to raise for this one test, standing in for
    "some unexpected internal failure" the guard is written to survive.
"""
import pytest

from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils import timezone

from mobinspect.RBAC.models import Role, RoleAssignment
from mobinspect.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)


def _make_admin(django_user_model, username='analytics_cov_admin'):
    user = django_user_model.objects.create_user(
        username=username, password='not-used')
    role = Role.objects.filter(name='Administrator').first()
    if role is None:
        group, _ = Group.objects.get_or_create(name='Administrator')
        role = Role.objects.create(group=group, name='Administrator')
    RoleAssignment.objects.create(user=user, role=role)
    return user


@pytest.mark.django_db
def test_dashboard_empty_recent_scans_short_circuits_rollup(
        client, django_user_model):
    """Zero RecentScansDB rows -> `_severity_rollup` takes its immediate
    `if not recent: return counts, apps_scored, scores` early return,
    never reaching the per-platform Android/iOS scoring loops below it."""
    admin = _make_admin(django_user_model, username='analytics_cov_empty_admin')
    client.force_login(admin)

    RecentScansDB.objects.all().delete()

    resp = client.get(reverse('analytics:dashboard'))
    assert resp.status_code == 200
    assert resp.context['severity_apps'] == 0


@pytest.mark.django_db
def test_dashboard_ios_success_path_scores_entry(client, django_user_model):
    """BINARY_ANALYSIS='{}' (a dict) avoids the list/dict mismatch
    described in the module docstring, so get_ios_dashboard scores the
    entry successfully -- exercising the real, non-exception iOS loop
    body (counts/severity accumulation, security_score handling)."""
    admin = _make_admin(django_user_model)
    client.force_login(admin)

    RecentScansDB.objects.create(
        MD5='1' * 32, FILE_NAME='real.ipa', SCAN_TYPE='ipa',
        PACKAGE_NAME='com.cov.ios', ANALYZER='static_analyzer_ios',
        TIMESTAMP=timezone.now())
    StaticAnalyzerIOS.objects.create(
        MD5='1' * 32, BUNDLE_ID='com.cov.ios', FILE_NAME='real.ipa',
        APP_NAME='CovIOSApp', APP_VERSION='1.0',
        BINARY_ANALYSIS=str({}))

    resp = client.get(reverse('analytics:dashboard'))
    assert resp.status_code == 200
    assert resp.context['severity_apps'] >= 1


@pytest.mark.django_db
def test_dashboard_ios_incomplete_scan_exception_is_caught_for_real(
        client, django_user_model):
    """A StaticAnalyzerIOS row left at its model defaults (as an
    in-flight/incomplete scan might look) makes the REAL
    get_ios_dashboard call raise -- no mock. The dashboard must still
    render 200 and simply not count this entry."""
    admin = _make_admin(django_user_model)
    client.force_login(admin)

    RecentScansDB.objects.create(
        MD5='3' * 32, FILE_NAME='incomplete.ipa', SCAN_TYPE='ipa',
        PACKAGE_NAME='com.cov.incomplete', ANALYZER='static_analyzer_ios',
        TIMESTAMP=timezone.now())
    StaticAnalyzerIOS.objects.create(
        MD5='3' * 32, BUNDLE_ID='com.cov.incomplete', FILE_NAME='incomplete.ipa',
        APP_NAME='IncompleteIOSApp', APP_VERSION='1.0')
    # BINARY_ANALYSIS deliberately left at its model default ([]).

    resp = client.get(reverse('analytics:dashboard'))
    assert resp.status_code == 200
    assert resp.context['severity_apps'] == 0


@pytest.mark.django_db
def test_dashboard_android_scoring_exception_does_not_sink_page(
        client, django_user_model, monkeypatch):
    admin = _make_admin(django_user_model)
    client.force_login(admin)

    RecentScansDB.objects.create(
        MD5='2' * 32, FILE_NAME='broken.apk', SCAN_TYPE='apk',
        PACKAGE_NAME='com.cov.broken', ANALYZER='static_analyzer',
        TIMESTAMP=timezone.now())
    StaticAnalyzerAndroid.objects.create(
        MD5='2' * 32, PACKAGE_NAME='com.cov.broken', FILE_NAME='broken.apk')

    from mobinspect.Analytics import views as analytics_views

    def _raise(entries):
        raise RuntimeError('simulated appsec scorecard failure')

    monkeypatch.setattr(analytics_views, 'get_android_dashboard', _raise)

    resp = client.get(reverse('analytics:dashboard'))
    assert resp.status_code == 200
    # The failing entry must be skipped (not scored), not crash the page.
    assert resp.context['severity_apps'] == 0
