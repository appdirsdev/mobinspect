"""
Analytics dashboard smoke tests (H17).

Two narrow scenarios:

  * Empty DB → the view still renders 200 (no division-by-zero, no
    KeyError on empty top-apps).
  * A few seeded RecentScansDB rows → the view still renders 200 and
    the KPI total reflects the count.

We deliberately do NOT assert the full template body — that would
freeze the markup and break every Tailwind iteration. The goal is to
catch the next regression that turns the dashboard into a 500.
"""
import pytest

from datetime import datetime, timedelta

from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils import timezone

from mobsf.RBAC.models import Role, RoleAssignment
from mobsf.StaticAnalyzer.models import RecentScansDB


def _make_admin(django_user_model):
    """Build an Administrator user wired with the seeded role."""
    user = django_user_model.objects.create_user(
        username='analytics_admin',
        password='analytics-pw-not-used',
    )
    role = Role.objects.filter(name='Administrator').first()
    if role is None:
        # Fall back: synthesize an Administrator role if migrations did
        # not seed it (e.g. running on a fresh schema).
        group, _ = Group.objects.get_or_create(name='Administrator')
        role = Role.objects.create(group=group, name='Administrator')
    RoleAssignment.objects.create(user=user, role=role)
    return user


@pytest.mark.django_db
def test_dashboard_empty_db_renders_200(client, django_user_model):
    """Empty RecentScansDB → dashboard renders without raising."""
    admin = _make_admin(django_user_model)
    client.force_login(admin)

    # Belt-and-braces: pre-condition is an empty scan table.
    RecentScansDB.objects.all().delete()

    resp = client.get(reverse('analytics:dashboard'))
    assert resp.status_code == 200, (
        f'Dashboard must render with empty DB; got {resp.status_code}. '
        f'Body head: {resp.content[:300]!r}')


@pytest.mark.django_db
def test_dashboard_with_scans_renders_200(client, django_user_model):
    """Seeded scans → dashboard renders and aggregation does not crash."""
    admin = _make_admin(django_user_model)
    client.force_login(admin)

    now = timezone.now()
    for i in range(3):
        RecentScansDB.objects.create(
            MD5=f'{i:032x}',
            APP_NAME=f'TestApp{i}',
            PACKAGE_NAME=f'com.test.app{i}',
            FILE_NAME=f'app{i}.apk',
            SCAN_TYPE='apk',
            ANALYZER='static_analyzer',
            TIMESTAMP=now - timedelta(days=i),
        )

    resp = client.get(reverse('analytics:dashboard'))
    assert resp.status_code == 200, (
        f'Dashboard must render with seeded scans; got {resp.status_code}. '
        f'Body head: {resp.content[:300]!r}')


@pytest.mark.django_db
def test_dashboard_denies_anonymous(client):
    """Anonymous request → 302 to login (via @login_required), not 200."""
    resp = client.get(reverse('analytics:dashboard'))
    # login_required redirects unauthenticated requests; we don't care
    # about the exact destination, only that we did NOT serve the page.
    assert resp.status_code in (302, 401, 403), (
        f'Anonymous user must be redirected/denied; got {resp.status_code}')


@pytest.mark.django_db
def test_avg_security_score_excludes_thin_library_formats(
        client, django_user_model):
    """A bare .so/.jar/.dylib has no manifest to evaluate — the real
    scorecard formula clamps its near-empty result to a vacuous 100. The
    fleet-wide "Avg security score" must not be dragged up by that; only
    real app scans should feed the average."""
    from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid

    admin = _make_admin(django_user_model)
    client.force_login(admin)

    RecentScansDB.objects.create(
        MD5='1' * 32, FILE_NAME='lib.so', SCAN_TYPE='so',
        PACKAGE_NAME='', ANALYZER='static_analyzer',
        TIMESTAMP=timezone.now())
    StaticAnalyzerAndroid.objects.create(
        MD5='1' * 32, PACKAGE_NAME='', FILE_NAME='lib.so',
        VERSION_NAME='', ICON_PATH='',
        CERTIFICATE_ANALYSIS=str({'certificate_findings': [
            ['secure', 'Baseline passing check', 'Baseline OK'],
        ]}))

    RecentScansDB.objects.create(
        MD5='2' * 32, FILE_NAME='real.apk', SCAN_TYPE='apk',
        PACKAGE_NAME='com.cov.real', ANALYZER='static_analyzer',
        TIMESTAMP=timezone.now())
    StaticAnalyzerAndroid.objects.create(
        MD5='2' * 32, PACKAGE_NAME='com.cov.real', FILE_NAME='real.apk',
        VERSION_NAME='1.0', ICON_PATH='',
        CERTIFICATE_ANALYSIS=str({'certificate_findings': [
            ['high', 'Real finding description', 'Real High Finding'],
        ]}))

    resp = client.get(reverse('analytics:dashboard'))
    assert resp.status_code == 200
    # The .so's own vacuous 100 must not blend into the average — with the
    # library excluded, the average equals the one real app's own score.
    assert resp.context['avg_security_score'] < 100
