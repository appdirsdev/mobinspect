"""
Additional coverage tests for mobinspect/RBAC/views.py and mobinspect/RBAC/models.py.

Targets the specific branches left uncovered by test_cov_views.py,
test_cov_integrations.py and the rest of mobinspect/RBAC/tests/:

  views.py:
    * role_assign()            — the "renew/change expiry" branch on a
                                  second assignment of an already-held role
    * _validate_host_port()    — the defensive int(port) conversion guard
                                  (regex only ever yields digits, so the
                                  real regex can't trigger it — mock it)
    * _run_adb()                — no-binary / timeout / generic-exception /
                                  connected-success branches
    * _adb_devices_list()       — no-binary / exception / line-parsing
    * model_integration_add/remove/set_active/test — the legacy by-id AI
      model integration endpoints (separate from the fixed generate/
      classify boxes covered in test_cov_integrations.py)
    * adb_connection_add()      — the host_port-duplicate branch, which is
                                  normally dead code (the single-device
                                  guard above it always fires first once any
                                  row exists) — simulated via a mocked race

  models.py:
    * __str__ on Permission / Role / RoleAssignment / AuditEvent /
      ApiKey / AdbConnection / ModelIntegration
    * RoleAssignment.is_active (no expiry / future expiry / past expiry)
    * ApiKey.is_active (revoked / expired branches)
    * AuditEvent.save() materializing an explicitly-None occurred_at
    * AuditEvent._raw_purge_for_test() sqlite + generic-vendor branches
      (the real test DB is postgresql here, so those branches are dead
      under normal execution — exercised with a mocked cursor/vendor so
      no real SQL is ever sent to the live connection)
    * ModelIntegration.set_active() atomic switch

Every external boundary (subprocess/adb, requests/network, the DB cursor
used only for the vendor-branch simulation) is mocked. No real adb, no
real network call, no real vendor-mismatched SQL. Fixture/auth style
mirrors mobinspect/RBAC/tests/test_cov_integrations.py and
mobinspect/RBAC/test_cov_views.py: a locally-defined superuser force_login'd
via `su_client`, plus a permission-less `plain_user`.
"""
import subprocess
from unittest.mock import MagicMock

import pytest

from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils import timezone

from mobinspect.RBAC import views
from mobinspect.RBAC.models import (
    AdbConnection,
    ApiKey,
    AuditEvent,
    ModelIntegration,
    Permission,
    Role,
    RoleAssignment,
)


# ───────────────────────────────────────────── helpers / fixtures
def _make_role(name, codenames=(), is_system=False):
    group, _ = Group.objects.get_or_create(name=name)
    role, _ = Role.objects.get_or_create(
        group=group, defaults={'name': name, 'is_system': is_system},
    )
    role.name = name
    role.is_system = is_system
    role.save()
    if codenames:
        perms = list(Permission.objects.filter(codename__in=codenames))
        role.permissions.set(perms)
    return role


@pytest.fixture
def superuser(db, django_user_model):
    return django_user_model.objects.create_user(
        username='cov_extra_root', password='pw',
        is_staff=True, is_superuser=True,
    )


@pytest.fixture
def plain_user(db, django_user_model):
    """A logged-in user holding NO RBAC permissions at all."""
    return django_user_model.objects.create_user(
        username='cov_extra_plain', password='pw',
    )


@pytest.fixture
def su_client(client, superuser):
    client.force_login(superuser)
    return client


# A loopback address — resolves locally (no DNS/network) and passes
# `_host_is_enclave`.
LOOPBACK_URL = 'http://127.0.0.1:11434'


class _FakeProc:
    """Minimal stand-in for a subprocess.CompletedProcess."""

    def __init__(self, returncode=0, stdout=b'', stderr=b''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _FakeMatch:
    """Stand-in for an re.Match with a controllable .group()."""

    def __init__(self, port, host=None, ipv6=None):
        self._data = {'port': port, 'host': host, 'ipv6': ipv6}

    def group(self, name):
        return self._data[name]


class _FakeRegex:
    def __init__(self, match_obj):
        self._match_obj = match_obj

    def match(self, value):
        return self._match_obj


# ═══════════════════════════════════════════════════ role_assign renewal
@pytest.mark.django_db
def test_role_assign_renews_changed_expiry(su_client, plain_user):
    """Re-assigning an already-held role with a DIFFERENT expires_at must
    update the existing RoleAssignment in place (not silently keep the old
    window) and record 'role.assign.update' / the 'Updated ...' message."""
    role = _make_role('CovExtraRenewRole')
    first = su_client.post(reverse('rbac:role_assign', args=[role.pk]), {
        'user_id': plain_user.pk,
        'role_id': role.pk,
    })
    assert first.status_code == 302
    ra = RoleAssignment.objects.get(user=plain_user, role=role)
    assert ra.expires_at is None

    second = su_client.post(reverse('rbac:role_assign', args=[role.pk]), {
        'user_id': plain_user.pk,
        'role_id': role.pk,
        'expires_at': '2030-06-01 00:00:00',
    }, follow=True)
    assert second.status_code == 200
    ra.refresh_from_db()
    assert ra.expires_at is not None
    assert RoleAssignment.objects.filter(user=plain_user, role=role).count() == 1
    assert AuditEvent.objects.filter(action='role.assign.update').exists()
    assert b'Updated' in second.content


# ═══════════════════════════════════════════════════ _validate_host_port
def test_validate_host_port_port_int_conversion_error(monkeypatch):
    """SSH_DEVICE_ID_REGEX's port group is \\d{1,5}, so int() can never
    naturally fail — mock the regex to prove the defensive except branch
    behaves correctly if that invariant is ever broken."""
    fake_match = _FakeMatch(port=None, host='example.com', ipv6=None)
    monkeypatch.setattr(
        'mobinspect.MobInspect.utils.SSH_DEVICE_ID_REGEX', _FakeRegex(fake_match))
    assert views._validate_host_port('whatever:1') is None


def test_validate_host_port_port_value_error(monkeypatch):
    fake_match = _FakeMatch(port='not-a-number', host='example.com', ipv6=None)
    monkeypatch.setattr(
        'mobinspect.MobInspect.utils.SSH_DEVICE_ID_REGEX', _FakeRegex(fake_match))
    assert views._validate_host_port('whatever:1') is None


# ═══════════════════════════════════════════════════ _run_adb
def test_run_adb_binary_not_found(monkeypatch):
    monkeypatch.setattr('mobinspect.MobInspect.utils.get_adb', lambda: None)
    status, message = views._run_adb(['connect', '127.0.0.1:5555'])
    assert status == AdbConnection.STATUS_FAILED
    assert message == 'adb binary not found on server.'


def test_run_adb_timeout(monkeypatch):
    monkeypatch.setattr('mobinspect.MobInspect.utils.get_adb', lambda: '/usr/bin/adb')

    def _raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(
            cmd=['adb', 'connect'], timeout=views.ADB_TIMEOUT)

    monkeypatch.setattr(subprocess, 'run', _raise_timeout)
    status, message = views._run_adb(['connect', '127.0.0.1:5555'])
    assert status == AdbConnection.STATUS_TIMEOUT
    assert 'timed out' in message
    assert 'connect' in message


def test_run_adb_generic_exception(monkeypatch):
    monkeypatch.setattr('mobinspect.MobInspect.utils.get_adb', lambda: '/usr/bin/adb')

    def _raise(*a, **kw):
        raise OSError('boom')

    monkeypatch.setattr(subprocess, 'run', _raise)
    status, message = views._run_adb(['connect', '127.0.0.1:5555'])
    assert status == AdbConnection.STATUS_FAILED
    assert message == 'adb invocation failed.'


def test_run_adb_success_connected(monkeypatch):
    monkeypatch.setattr('mobinspect.MobInspect.utils.get_adb', lambda: '/usr/bin/adb')
    monkeypatch.setattr(
        subprocess, 'run',
        lambda *a, **kw: _FakeProc(
            returncode=0, stdout=b'connected to 127.0.0.1:5555\n'))
    status, message = views._run_adb(['connect', '127.0.0.1:5555'])
    assert status == AdbConnection.STATUS_CONNECTED
    assert 'connected to' in message


# ═══════════════════════════════════════════════════ _adb_devices_list
def test_adb_devices_list_no_binary(monkeypatch):
    monkeypatch.setattr('mobinspect.MobInspect.utils.get_adb', lambda: None)
    assert views._adb_devices_list() == []


def test_adb_devices_list_exception(monkeypatch):
    monkeypatch.setattr('mobinspect.MobInspect.utils.get_adb', lambda: '/usr/bin/adb')

    def _raise(*a, **kw):
        raise OSError('boom')

    monkeypatch.setattr(subprocess, 'run', _raise)
    assert views._adb_devices_list() == []


def test_adb_devices_list_parses_serials(monkeypatch):
    monkeypatch.setattr('mobinspect.MobInspect.utils.get_adb', lambda: '/usr/bin/adb')
    stdout = b'List of devices attached\nemulator-5554\tdevice\n\nbadline\n'
    monkeypatch.setattr(
        subprocess, 'run',
        lambda *a, **kw: _FakeProc(returncode=0, stdout=stdout))
    devices = views._adb_devices_list()
    assert devices == [{'serial': 'emulator-5554', 'state': 'device'}]


# ═══════════════════════════════════════════ model_integration_add (by id)
@pytest.mark.django_db
def test_model_integration_add_missing_fields(su_client):
    resp = su_client.post(reverse('rbac:model_integration_add'), {
        'label': '', 'base_url': '', 'model_name': '',
    }, follow=True)
    assert resp.status_code == 200
    assert not ModelIntegration.objects.exists()
    assert b'all required' in resp.content


@pytest.mark.django_db
def test_model_integration_add_invalid_url(su_client):
    resp = su_client.post(reverse('rbac:model_integration_add'), {
        'label': 'Extra', 'base_url': 'not-a-url', 'model_name': 'granite4:3b',
    }, follow=True)
    assert resp.status_code == 200
    assert not ModelIntegration.objects.exists()
    assert b'Invalid endpoint' in resp.content


@pytest.mark.django_db
def test_model_integration_add_rejects_public_host(su_client):
    resp = su_client.post(reverse('rbac:model_integration_add'), {
        'label': 'Extra', 'base_url': 'http://8.8.8.8:11434',
        'model_name': 'granite4:3b',
    }, follow=True)
    assert resp.status_code == 200
    assert not ModelIntegration.objects.exists()
    assert b'no public hosts' in resp.content


@pytest.mark.django_db
def test_model_integration_add_duplicate_base_url(su_client, superuser):
    ModelIntegration.objects.create(
        label='First', base_url=LOOPBACK_URL, model_name='granite4:3b',
        created_by=superuser)
    resp = su_client.post(reverse('rbac:model_integration_add'), {
        'label': 'Second', 'base_url': LOOPBACK_URL, 'model_name': 'granite4:1b',
    }, follow=True)
    assert resp.status_code == 200
    assert ModelIntegration.objects.filter(base_url=LOOPBACK_URL).count() == 1
    assert b'already exists' in resp.content


@pytest.mark.django_db
def test_model_integration_add_happy_path(su_client, monkeypatch):
    monkeypatch.setattr(
        views, '_apply_model_probe',
        MagicMock(return_value=(ModelIntegration.STATUS_CONNECTED, 'ok', [])))
    resp = su_client.post(reverse('rbac:model_integration_add'), {
        'label': 'Extra One', 'base_url': LOOPBACK_URL, 'model_name': 'granite4:3b',
    })
    assert resp.status_code == 302
    integ = ModelIntegration.objects.get(base_url=LOOPBACK_URL)
    assert integ.label == 'Extra One'
    assert integ.model_name == 'granite4:3b'
    assert AuditEvent.objects.filter(action='integration.model.add').exists()


@pytest.mark.django_db
def test_model_integration_add_auto_activates_when_none_active(su_client, monkeypatch):
    """The auto-activate guard only fires when NO integration is currently
    active. ModelIntegration.is_active defaults to True, so the freshly
    created row is already "active" by the time the check runs and this
    branch is unreachable via a plain create-then-probe flow. Simulate the
    intended scenario it protects — the newly probed row starts inactive —
    by having the mocked probe flip it to inactive before returning
    CONNECTED, proving set_active() then correctly promotes it."""
    def fake_probe(integ):
        integ.is_active = False
        integ.last_status = ModelIntegration.STATUS_CONNECTED
        integ.save(update_fields=['is_active', 'last_status'])
        return ModelIntegration.STATUS_CONNECTED, 'ok', ['granite4:3b']

    monkeypatch.setattr(views, '_apply_model_probe', fake_probe)
    resp = su_client.post(reverse('rbac:model_integration_add'), {
        'label': 'Auto Activate', 'base_url': LOOPBACK_URL,
        'model_name': 'granite4:3b',
    })
    assert resp.status_code == 302
    integ = ModelIntegration.objects.get(base_url=LOOPBACK_URL)
    assert integ.is_active is True


@pytest.mark.django_db
def test_model_integration_add_denied_for_plain_user(client, plain_user):
    client.force_login(plain_user)
    resp = client.post(reverse('rbac:model_integration_add'), {
        'label': 'Extra', 'base_url': LOOPBACK_URL, 'model_name': 'granite4:3b',
    })
    assert resp.status_code == 403
    assert not ModelIntegration.objects.exists()


# ═══════════════════════════════════════════ model_integration_remove
@pytest.mark.django_db
def test_model_integration_remove(su_client, superuser):
    integ = ModelIntegration.objects.create(
        label='ToRemove', base_url=LOOPBACK_URL, model_name='granite4:3b',
        created_by=superuser)
    resp = su_client.post(
        reverse('rbac:model_integration_remove', args=[integ.pk]))
    assert resp.status_code == 302
    assert not ModelIntegration.objects.filter(pk=integ.pk).exists()
    ev = AuditEvent.objects.filter(action='integration.model.remove').first()
    assert ev is not None
    assert ev.metadata['label'] == 'ToRemove'


@pytest.mark.django_db
def test_model_integration_remove_404(su_client):
    resp = su_client.post(
        reverse('rbac:model_integration_remove', args=[999999]))
    assert resp.status_code == 404


# ═══════════════════════════════════════ model_integration_set_active
@pytest.mark.django_db
def test_model_integration_set_active(su_client, superuser):
    a = ModelIntegration.objects.create(
        label='A', base_url=LOOPBACK_URL, model_name='m1',
        is_active=True, created_by=superuser)
    b = ModelIntegration.objects.create(
        label='B', base_url='http://127.0.0.1:11435', model_name='m2',
        is_active=False, created_by=superuser)
    resp = su_client.post(
        reverse('rbac:model_integration_set_active', args=[b.pk]))
    assert resp.status_code == 302
    a.refresh_from_db()
    b.refresh_from_db()
    assert b.is_active is True
    assert a.is_active is False
    assert AuditEvent.objects.filter(
        action='integration.model.set_active').exists()


@pytest.mark.django_db
def test_model_integration_set_active_404(su_client):
    resp = su_client.post(
        reverse('rbac:model_integration_set_active', args=[999999]))
    assert resp.status_code == 404


# ═══════════════════════════════════════ model_integration_test
#
# NOTE: `integrations/model/<int:integ_id>/test/` (name='model_integration_test')
# is registered AFTER `integrations/model/<slug:role>/test/` (name='model_test')
# in mobinspect/RBAC/urls.py, and Django's <slug:...> converter matches pure-digit
# segments too. So for any real integer id, URL *resolution* always hits
# `model_test_key` first — `model_integration_test` is unreachable through
# the router (verified with django.urls.resolve()). That is a pre-existing
# routing shadow in urls.py, out of scope to fix here (tests only). We cover
# the view by calling it directly through RequestFactory, which still
# exercises the real @login_required / @require_permission decorators and
# the full view body — only Django's URL dispatch step is bypassed.
@pytest.mark.django_db
def test_model_integration_test_success(superuser, monkeypatch):
    from django.test import RequestFactory

    integ = ModelIntegration.objects.create(
        label='TestMe', base_url=LOOPBACK_URL, model_name='granite4:3b',
        created_by=superuser)
    # Mock the lower-level probe (not _apply_model_probe itself) so the
    # real _apply_model_probe still runs and persists last_status_at, etc.
    monkeypatch.setattr(
        views, '_probe_model_endpoint',
        MagicMock(return_value=(
            ModelIntegration.STATUS_CONNECTED, 'all good', ['granite4:3b'])))
    request = RequestFactory().post(
        f'/rbac/integrations/model/{integ.pk}/test/')
    request.user = superuser
    resp = views.model_integration_test(request, integ.pk)
    assert resp.status_code == 200
    data = resp.json() if hasattr(resp, 'json') else None
    if data is None:
        import json
        data = json.loads(resp.content)
    assert data['success'] is True
    assert data['status'] == ModelIntegration.STATUS_CONNECTED
    assert data['models_list'] == ['granite4:3b']
    ev = AuditEvent.objects.filter(action='integration.model.test').first()
    assert ev is not None
    assert ev.metadata['result'] == 'success'


@pytest.mark.django_db
def test_model_integration_test_failure(superuser, monkeypatch):
    from django.test import RequestFactory

    integ = ModelIntegration.objects.create(
        label='TestFail', base_url=LOOPBACK_URL, model_name='granite4:3b',
        created_by=superuser)
    monkeypatch.setattr(
        views, '_probe_model_endpoint',
        MagicMock(return_value=(ModelIntegration.STATUS_FAILED, 'HTTP 500', [])))
    request = RequestFactory().post(
        f'/rbac/integrations/model/{integ.pk}/test/')
    request.user = superuser
    resp = views.model_integration_test(request, integ.pk)
    import json
    data = json.loads(resp.content)
    assert data['success'] is False
    ev = AuditEvent.objects.filter(action='integration.model.test').first()
    assert ev.metadata['result'] == 'failed'


@pytest.mark.django_db
def test_model_integration_test_404(superuser):
    from django.http import Http404
    from django.test import RequestFactory

    request = RequestFactory().post(
        '/rbac/integrations/model/999999/test/')
    request.user = superuser
    with pytest.raises(Http404):
        views.model_integration_test(request, 999999)


# ═══════════════════════════════════ adb_connection_add duplicate (dead-code guard)
@pytest.mark.django_db
def test_adb_connection_add_duplicate_host_port_race_guard(
        su_client, superuser, monkeypatch):
    """The host_port-duplicate check is a defensive guard against a
    concurrent insert racing the "only one device" check above it — under
    normal operation that first guard always fires once any row exists, so
    this branch never runs through the UI. Simulate the race window it
    protects against: force the single-device guard to see zero rows while
    a row with the target host_port genuinely already exists."""
    AdbConnection.objects.create(
        label='Existing', host_port='127.0.0.1:5960',
        platform=AdbConnection.PLATFORM_ANDROID, created_by=superuser)
    monkeypatch.setattr(AdbConnection.objects, 'exists', lambda: False)
    resp = su_client.post(reverse('rbac:adb_connection_add'), {
        'label': 'Racer', 'host_port': '127.0.0.1:5960',
    }, follow=True)
    assert resp.status_code == 200
    assert b'already exists' in resp.content
    assert AdbConnection.objects.filter(host_port='127.0.0.1:5960').count() == 1


# ═══════════════════════════════════════════════════════════════════════
#                              models.py
# ═══════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────── __str__ methods
@pytest.mark.django_db
def test_permission_str():
    perm = Permission.objects.create(
        codename='cov.extra.test.perm', name='Cov Extra Test',
        category='cov_extra')
    assert str(perm) == 'cov.extra.test.perm'


@pytest.mark.django_db
def test_role_str():
    role = _make_role('CovExtraStrRole')
    assert str(role) == 'CovExtraStrRole'


@pytest.mark.django_db
def test_role_assignment_str(django_user_model):
    user = django_user_model.objects.create_user(username='cov_extra_str_user')
    role = _make_role('CovExtraStrAssignRole')
    ra = RoleAssignment.objects.create(user=user, role=role)
    s = str(ra)
    assert str(user) in s
    assert str(role) in s
    assert '→' in s


@pytest.mark.django_db
def test_audit_event_str_with_actor(django_user_model):
    user = django_user_model.objects.create_user(username='cov_extra_audit_user')
    evt = AuditEvent.objects.create(actor=user, action='cov.extra.action')
    s = str(evt)
    assert 'cov_extra_audit_user' in s
    assert 'cov.extra.action' in s


@pytest.mark.django_db
def test_audit_event_str_without_actor():
    evt = AuditEvent.objects.create(actor=None, action='cov.extra.anon.action')
    s = str(evt)
    assert '<system>' in s
    assert 'cov.extra.anon.action' in s


@pytest.mark.django_db
def test_api_key_str(django_user_model):
    user = django_user_model.objects.create_user(username='cov_extra_apikey_user')
    key, _ = ApiKey.generate(user=user, name='str-test-key')
    assert str(key) == f'{user.username}:{key.name}'


@pytest.mark.django_db
def test_adb_connection_str_active_and_inactive(django_user_model):
    user = django_user_model.objects.create_user(username='cov_extra_adbstr_user')
    active_conn = AdbConnection.objects.create(
        label='StrConn', host_port='127.0.0.1:5997',
        platform=AdbConnection.PLATFORM_ANDROID, is_active=True,
        created_by=user)
    s = str(active_conn)
    assert 'StrConn' in s
    assert '127.0.0.1:5997' in s
    assert '(active)' in s

    inactive_conn = AdbConnection.objects.create(
        label='StrConn2', host_port='127.0.0.1:5996',
        platform=AdbConnection.PLATFORM_IOS, is_active=False,
        created_by=user)
    s2 = str(inactive_conn)
    assert '(active)' not in s2


@pytest.mark.django_db
def test_model_integration_str(django_user_model):
    user = django_user_model.objects.create_user(username='cov_extra_modstr_user')
    integ = ModelIntegration.objects.create(
        label='StrModel', base_url=LOOPBACK_URL, model_name='granite4:3b',
        is_active=True, created_by=user)
    s = str(integ)
    assert 'StrModel' in s
    assert 'granite4:3b' in s
    assert LOOPBACK_URL in s
    assert '(active)' in s


# ─────────────────────────────────────────────────────── RoleAssignment.is_active
@pytest.mark.django_db
def test_role_assignment_is_active_no_expiry(django_user_model):
    user = django_user_model.objects.create_user(username='cov_extra_ra_noexp')
    role = _make_role('CovExtraRoleNoExp')
    ra = RoleAssignment.objects.create(user=user, role=role, expires_at=None)
    assert ra.is_active is True


@pytest.mark.django_db
def test_role_assignment_is_active_future_expiry(django_user_model):
    user = django_user_model.objects.create_user(username='cov_extra_ra_future')
    role = _make_role('CovExtraRoleFuture')
    ra = RoleAssignment.objects.create(
        user=user, role=role,
        expires_at=timezone.now() + timezone.timedelta(days=1))
    assert ra.is_active is True


@pytest.mark.django_db
def test_role_assignment_is_active_past_expiry(django_user_model):
    user = django_user_model.objects.create_user(username='cov_extra_ra_past')
    role = _make_role('CovExtraRolePast')
    ra = RoleAssignment.objects.create(
        user=user, role=role,
        expires_at=timezone.now() - timezone.timedelta(days=1))
    assert ra.is_active is False


# ─────────────────────────────────────────────────────── ApiKey.is_active
@pytest.mark.django_db
def test_api_key_is_active_false_when_revoked(django_user_model):
    user = django_user_model.objects.create_user(username='cov_extra_key_revoked')
    key, _ = ApiKey.generate(user=user, name='revoked-key')
    key.revoked_at = timezone.now()
    key.save(update_fields=['revoked_at'])
    assert key.is_active is False


@pytest.mark.django_db
def test_api_key_is_active_false_when_expired(django_user_model):
    user = django_user_model.objects.create_user(username='cov_extra_key_expired')
    key, _ = ApiKey.generate(
        user=user, name='expired-key',
        expires_at=timezone.now() - timezone.timedelta(days=1))
    assert key.is_active is False


# ─────────────────────────────────────────────────────── AuditEvent.save()
@pytest.mark.django_db
def test_audit_event_save_materializes_none_occurred_at():
    """occurred_at uses default=timezone.now (not auto_now_add), so it is
    already populated by Model.__init__ unless a caller explicitly passes
    None. save() must materialize it before folding it into the hash."""
    evt = AuditEvent(action='cov.extra.materialize.ts', occurred_at=None)
    assert evt.occurred_at is None
    evt.save()
    assert evt.occurred_at is not None
    assert len(evt.current_hash) == AuditEvent.HASH_LEN


# ───────────────────────────────────── AuditEvent._raw_purge_for_test vendor branches
def test_raw_purge_for_test_sqlite_branch(monkeypatch):
    """The live test DB here is postgresql, so the sqlite branch is dead
    under normal execution. Exercise it with a fully mocked cursor/vendor
    so no sqlite-flavored SQL is ever sent to the real (postgres)
    connection."""
    from django.db import connection

    mock_cursor = MagicMock()
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=mock_cursor)
    cm.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr(connection, 'vendor', 'sqlite')
    monkeypatch.setattr(connection, 'cursor', lambda: cm)

    AuditEvent._raw_purge_for_test(where_sql='id = %s', params=(1,))

    assert mock_cursor.execute.call_count == 3
    sqls = [c.args[0] for c in mock_cursor.execute.call_args_list]
    assert 'DROP TRIGGER' in sqls[0]
    assert 'DELETE FROM' in sqls[1]
    assert 'WHERE id = %s' in sqls[1]
    assert 'CREATE TRIGGER' in sqls[2]


def test_raw_purge_for_test_other_vendor_branch(monkeypatch):
    """Any vendor other than sqlite/postgresql falls through to a bare
    DELETE — exercised with a mocked cursor to avoid depending on a third
    real database engine being available."""
    from django.db import connection

    mock_cursor = MagicMock()
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=mock_cursor)
    cm.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr(connection, 'vendor', 'mysql')
    monkeypatch.setattr(connection, 'cursor', lambda: cm)

    AuditEvent._raw_purge_for_test()

    mock_cursor.execute.assert_called_once()
    sql = mock_cursor.execute.call_args.args[0]
    assert 'DELETE FROM' in sql


# ─────────────────────────────────────────────────────── ModelIntegration.set_active
@pytest.mark.django_db
def test_model_integration_set_active_atomic_switch(django_user_model):
    user = django_user_model.objects.create_user(username='cov_extra_setactive')
    a = ModelIntegration.objects.create(
        label='SA-A', base_url=LOOPBACK_URL, model_name='m1',
        is_active=True, created_by=user)
    b = ModelIntegration.objects.create(
        label='SA-B', base_url='http://127.0.0.1:11436', model_name='m2',
        is_active=False, created_by=user)
    b.set_active()
    a.refresh_from_db()
    b.refresh_from_db()
    assert b.is_active is True
    assert a.is_active is False
