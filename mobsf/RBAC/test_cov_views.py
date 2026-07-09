"""
REAL-EXECUTION coverage tests for mobsf/RBAC/views.py.

STRICT: no mocks, no monkeypatch of internal logic. Everything is driven
through the real Django test Client (full middleware stack), a really
created superuser via force_login, real ORM rows, and real (seeded)
Permission catalog from the migrations. The ADB helpers invoke a real
subprocess (or take the real "adb binary not found" branch when adb is
absent) — never faked.
"""
import pytest

from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils import timezone

from mobsf.RBAC import views
from mobsf.RBAC.models import (
    AdbConnection,
    ApiKey,
    AuditEvent,
    Permission,
    Role,
    RoleAssignment,
)


# ───────────────────────────────────────────── helpers / fixtures
def _make_role(name, codenames=(), is_system=False):
    group, _ = Group.objects.get_or_create(name=name)
    role, _ = Role.objects.get_or_create(
        group=group,
        defaults={'name': name, 'is_system': is_system},
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
        username='cov_root', password='pw', is_staff=True, is_superuser=True,
    )


@pytest.fixture
def plain_user(db, django_user_model):
    """A logged-in user holding NO RBAC permissions at all."""
    return django_user_model.objects.create_user(
        username='cov_plain', password='pw',
    )


@pytest.fixture
def manage_user(db, django_user_model):
    """User who can manage roles but does NOT hold every permission."""
    user = django_user_model.objects.create_user(
        username='cov_manager', password='pw',
    )
    role = _make_role('CovManager', ['rbac.role.view', 'rbac.role.manage'])
    RoleAssignment.objects.create(user=user, role=role)
    return user


@pytest.fixture
def su_client(client, superuser):
    client.force_login(superuser)
    return client


# ───────────────────────────────────────────── roles list / catalog
@pytest.mark.django_db
def test_roles_list_ok(su_client):
    _make_role('CovAlpha', ['scan.view'])
    resp = su_client.get(reverse('rbac:roles_list'))
    assert resp.status_code == 200
    assert b'CovAlpha' in resp.content


@pytest.mark.django_db
def test_permissions_browse_ok(su_client):
    resp = su_client.get(reverse('rbac:permissions'))
    assert resp.status_code == 200


# ───────────────────────────────────────────── role create
@pytest.mark.django_db
def test_role_create_get(su_client):
    resp = su_client.get(reverse('rbac:role_create'))
    assert resp.status_code == 200


@pytest.mark.django_db
def test_role_create_post_valid(su_client):
    resp = su_client.post(reverse('rbac:role_create'), {
        'name': 'CovBravo',
        'description': 'made in test',
        'color': '#2563EB',
        'icon': 'shield',
        'permission_codenames': 'scan.view,audit.view',
    })
    assert resp.status_code == 302
    role = Role.objects.get(name='CovBravo')
    assert set(role.codenames()) == {'scan.view', 'audit.view'}
    assert AuditEvent.objects.filter(
        action='role.create', target_id=str(role.pk)).exists()


@pytest.mark.django_db
def test_role_create_post_invalid(su_client):
    # Bad hex color -> form invalid -> re-render 200, no redirect, no row.
    resp = su_client.post(reverse('rbac:role_create'), {
        'name': 'CovBadColor',
        'color': 'notacolor',
        'icon': 'shield',
        'permission_codenames': '',
    })
    assert resp.status_code == 200
    assert not Role.objects.filter(name='CovBadColor').exists()


# ───────────────────────────────────────────── role edit
@pytest.mark.django_db
def test_role_edit_get(su_client):
    role = _make_role('CovEditGet', ['scan.view'])
    resp = su_client.get(reverse('rbac:role_edit', args=[role.pk]))
    assert resp.status_code == 200


@pytest.mark.django_db
def test_role_edit_post_valid_records_diff(su_client):
    role = _make_role('CovEditPost', ['scan.view'])
    resp = su_client.post(reverse('rbac:role_edit', args=[role.pk]), {
        'name': 'CovEditPost',
        'description': '',
        'color': '#123456',
        'icon': 'key',
        'permission_codenames': 'audit.view',  # drop scan.view, add audit.view
    })
    assert resp.status_code == 302
    role.refresh_from_db()
    assert set(role.codenames()) == {'audit.view'}
    ev = AuditEvent.objects.filter(
        action='role.update', target_id=str(role.pk)).first()
    assert ev is not None
    assert 'audit.view' in ev.metadata['added']
    assert 'scan.view' in ev.metadata['removed']


@pytest.mark.django_db
def test_role_edit_404(su_client):
    resp = su_client.get(reverse('rbac:role_edit', args=[999999]))
    assert resp.status_code == 404


# ───────────────────────────────────────────── role delete
@pytest.mark.django_db
def test_role_delete_normal(su_client):
    role = _make_role('CovDeleteMe', ['scan.view'])
    resp = su_client.post(reverse('rbac:role_delete', args=[role.pk]))
    assert resp.status_code == 302
    assert not Role.objects.filter(pk=role.pk).exists()
    assert AuditEvent.objects.filter(action='role.delete').exists()


@pytest.mark.django_db
def test_role_delete_system_blocked(su_client):
    role = _make_role('CovSystemRole', ['scan.view'], is_system=True)
    resp = su_client.post(reverse('rbac:role_delete', args=[role.pk]))
    assert resp.status_code == 302
    # System role survives.
    assert Role.objects.filter(pk=role.pk).exists()


@pytest.mark.django_db
def test_role_delete_get_not_allowed(su_client):
    role = _make_role('CovGetDelete', ['scan.view'])
    resp = su_client.get(reverse('rbac:role_delete', args=[role.pk]))
    assert resp.status_code == 405


# ───────────────────────────────────────────── role assign / unassign
@pytest.mark.django_db
def test_role_assign_valid(su_client, plain_user):
    role = _make_role('CovAssignRole', ['scan.view'])
    resp = su_client.post(reverse('rbac:role_assign', args=[role.pk]), {
        'user_id': plain_user.pk,
        'role_id': role.pk,
    })
    assert resp.status_code == 302
    assert RoleAssignment.objects.filter(
        user=plain_user, role=role).exists()
    assert AuditEvent.objects.filter(action='role.assign').exists()


@pytest.mark.django_db
def test_role_assign_noop_when_already_assigned(su_client, plain_user):
    role = _make_role('CovAssignNoop', ['scan.view'])
    RoleAssignment.objects.create(user=plain_user, role=role)
    resp = su_client.post(reverse('rbac:role_assign', args=[role.pk]), {
        'user_id': plain_user.pk,
        'role_id': role.pk,
    })
    assert resp.status_code == 302
    assert AuditEvent.objects.filter(action='role.assign.noop').exists()


@pytest.mark.django_db
def test_role_assign_invalid_form_400(su_client):
    role = _make_role('CovAssignBad', ['scan.view'])
    resp = su_client.post(reverse('rbac:role_assign', args=[role.pk]), {})
    assert resp.status_code == 400


@pytest.mark.django_db
def test_role_assign_escalation_blocked_for_non_superuser(client, manage_user,
                                                          plain_user):
    """Non-superuser cannot grant a role carrying permissions they lack."""
    client.force_login(manage_user)
    # Target role carries a dangerous perm the manager does not hold.
    target = _make_role('CovElevated', ['admin.user.delete'])
    resp = client.post(reverse('rbac:role_assign', args=[target.pk]), {
        'user_id': plain_user.pk,
        'role_id': target.pk,
    })
    assert resp.status_code == 302
    # Assignment must NOT have been created.
    assert not RoleAssignment.objects.filter(
        user=plain_user, role=target).exists()


@pytest.mark.django_db
def test_role_unassign_normal(su_client, plain_user):
    role = _make_role('CovUnassign', ['scan.view'])
    RoleAssignment.objects.create(user=plain_user, role=role)
    resp = su_client.post(
        reverse('rbac:role_unassign', args=[role.pk, plain_user.pk]))
    assert resp.status_code == 302
    assert not RoleAssignment.objects.filter(
        user=plain_user, role=role).exists()
    assert AuditEvent.objects.filter(action='role.unassign').exists()


@pytest.mark.django_db
def test_role_unassign_last_admin_blocked(su_client, plain_user):
    role = _make_role('Administrator', ['scan.view'])
    RoleAssignment.objects.create(user=plain_user, role=role)
    resp = su_client.post(
        reverse('rbac:role_unassign', args=[role.pk, plain_user.pk]))
    assert resp.status_code == 302
    # The last Administrator assignment must be preserved.
    assert RoleAssignment.objects.filter(
        user=plain_user, role=role).exists()


@pytest.mark.django_db
def test_role_unassign_admin_with_remaining_ok(su_client, plain_user,
                                               django_user_model):
    role = _make_role('Administrator', ['scan.view'])
    other = django_user_model.objects.create_user(username='cov_other2')
    RoleAssignment.objects.create(user=plain_user, role=role)
    RoleAssignment.objects.create(user=other, role=role)
    resp = su_client.post(
        reverse('rbac:role_unassign', args=[role.pk, plain_user.pk]))
    assert resp.status_code == 302
    assert not RoleAssignment.objects.filter(
        user=plain_user, role=role).exists()
    assert RoleAssignment.objects.filter(user=other, role=role).exists()


# ───────────────────────────────────────────── api keys
@pytest.mark.django_db
def test_api_keys_get(su_client):
    resp = su_client.get(reverse('rbac:api_keys'))
    assert resp.status_code == 200


@pytest.mark.django_db
def test_api_keys_create_shows_plaintext_once(su_client, superuser):
    resp = su_client.post(reverse('rbac:api_keys'), {
        'name': 'cov-ci-key',
        'expires_in_days': '30',
    })
    assert resp.status_code == 200
    key = ApiKey.objects.get(user=superuser, name='cov-ci-key')
    assert key.expires_at is not None
    # Plaintext is surfaced exactly once in the response body.
    assert b'mi_' in resp.content
    assert AuditEvent.objects.filter(
        action='api_key.create', target_id=str(key.pk)).exists()


@pytest.mark.django_db
def test_api_keys_create_invalid(su_client, superuser):
    # name is required; empty name -> form invalid -> no key created.
    resp = su_client.post(reverse('rbac:api_keys'), {'name': ''})
    assert resp.status_code == 200
    assert not ApiKey.objects.filter(user=superuser).exists()


@pytest.mark.django_db
def test_api_key_revoke(su_client, superuser):
    key, _ = ApiKey.generate(user=superuser, name='cov-revoke-me')
    assert key.revoked_at is None
    resp = su_client.post(reverse('rbac:api_key_revoke', args=[key.pk]))
    assert resp.status_code == 302
    key.refresh_from_db()
    assert key.revoked_at is not None
    assert AuditEvent.objects.filter(action='api_key.revoke').exists()


@pytest.mark.django_db
def test_api_key_revoke_other_user_404(su_client, plain_user):
    """Revoking another user's key is a 404 (scoped to request.user)."""
    key, _ = ApiKey.generate(user=plain_user, name='not-mine')
    resp = su_client.post(reverse('rbac:api_key_revoke', args=[key.pk]))
    assert resp.status_code == 404
    key.refresh_from_db()
    assert key.revoked_at is None


# ───────────────────────────────────────────── audit log
@pytest.mark.django_db
def test_audit_log_with_filters(su_client, superuser):
    AuditEvent.objects.create(actor=superuser, action='role.create')
    AuditEvent.objects.create(actor=superuser, action='api_key.create')
    resp = su_client.get(reverse('rbac:audit_log'), {
        'action': 'role',
        'actor': 'cov_root',
        'page': '1',
    })
    assert resp.status_code == 200
    assert resp.context['action_filter'] == 'role'
    assert resp.context['actor_filter'] == 'cov_root'


@pytest.mark.django_db
def test_audit_log_no_filters(su_client):
    resp = su_client.get(reverse('rbac:audit_log'))
    assert resp.status_code == 200


# ───────────────────────────────────────────── permission-denied paths
@pytest.mark.django_db
def test_roles_list_denied_for_plain_user(client, plain_user):
    client.force_login(plain_user)
    resp = client.get(reverse('rbac:roles_list'))
    assert resp.status_code == 403


@pytest.mark.django_db
def test_role_create_denied_for_plain_user(client, plain_user):
    client.force_login(plain_user)
    resp = client.get(reverse('rbac:role_create'))
    assert resp.status_code == 403


@pytest.mark.django_db
def test_api_keys_denied_for_plain_user(client, plain_user):
    client.force_login(plain_user)
    resp = client.get(reverse('rbac:api_keys'))
    assert resp.status_code == 403


@pytest.mark.django_db
def test_adb_list_denied_for_plain_user(client, plain_user):
    client.force_login(plain_user)
    resp = client.get(reverse('rbac:adb_connections'))
    assert resp.status_code == 403


# ───────────────────────────────────────────── _validate_host_port (pure)
def test_validate_host_port_valid_ipv4():
    assert views._validate_host_port('192.168.1.100:5555') == '192.168.1.100:5555'


def test_validate_host_port_strips_whitespace():
    assert views._validate_host_port('  10.0.0.1:5037  ') == '10.0.0.1:5037'


def test_validate_host_port_empty():
    assert views._validate_host_port('') is None
    assert views._validate_host_port(None) is None


def test_validate_host_port_too_long():
    assert views._validate_host_port('a' * 300 + ':5555') is None


def test_validate_host_port_no_match():
    assert views._validate_host_port('not-a-host-port') is None


def test_validate_host_port_bad_port_range():
    assert views._validate_host_port('192.168.1.1:70000') is None
    assert views._validate_host_port('192.168.1.1:0') is None


def test_validate_host_port_ipv6():
    val = views._validate_host_port('[::1]:5555')
    assert val == '[::1]:5555'


def test_validate_host_port_host_bad_charset():
    # Matches the device regex host group ([^:\[\]]+) but carries a shell
    # meta char rejected by the defense-in-depth host charset.
    assert views._validate_host_port('host$(x):5555') is None


def test_validate_host_port_ipv6_bad_charset():
    # Matches the [ipv6] shape but the inner chars are not valid hex/':'.
    assert views._validate_host_port('[gg!!]:5555') is None


# ───────────────────────────────────────────── _run_adb / _adb_devices (real)
def test_run_adb_returns_status_and_message():
    # Real subprocess (or the real "binary not found" branch). Never mocked.
    # Use a fast-failing loopback target so the connect attempt returns
    # quickly whether or not adb is installed.
    status, message = views._run_adb(['connect', '127.0.0.1:5999'])
    assert status in {
        AdbConnection.STATUS_CONNECTED,
        AdbConnection.STATUS_FAILED,
        AdbConnection.STATUS_TIMEOUT,
    }
    assert isinstance(message, str) and message


def test_adb_devices_list_returns_list():
    devices = views._adb_devices_list()
    assert isinstance(devices, list)


# ───────────────────────────────────────────── adb connection views
@pytest.mark.django_db
def test_adb_connections_list_ok(su_client):
    AdbConnection.objects.create(
        label='Cov Emu', host_port='127.0.0.1:5555',
        platform=AdbConnection.PLATFORM_ANDROID)
    resp = su_client.get(reverse('rbac:adb_connections'))
    assert resp.status_code == 200
    # The Integrations page is now four fixed cards (no listing table); the
    # configured Android device prefills its host:port into the Android card.
    assert b'Android device' in resp.content
    assert b'127.0.0.1:5555' in resp.content


@pytest.mark.django_db
def test_adb_connection_add_valid(su_client, superuser):
    resp = su_client.post(reverse('rbac:adb_connection_add'), {
        'label': 'Cov Added',
        'host_port': '127.0.0.1:5901',
        'platform': 'android',
    })
    assert resp.status_code == 302
    conn = AdbConnection.objects.get(host_port='127.0.0.1:5901')
    assert conn.label == 'Cov Added'
    assert conn.last_status_at is not None
    assert AuditEvent.objects.filter(action='integration.adb.add').exists()


@pytest.mark.django_db
def test_adb_connection_add_missing_label(su_client):
    resp = su_client.post(reverse('rbac:adb_connection_add'), {
        'label': '',
        'host_port': '127.0.0.1:5902',
    })
    assert resp.status_code == 302
    assert not AdbConnection.objects.filter(host_port='127.0.0.1:5902').exists()


@pytest.mark.django_db
def test_adb_connection_add_invalid_host_port(su_client):
    resp = su_client.post(reverse('rbac:adb_connection_add'), {
        'label': 'Cov Bad Addr',
        'host_port': 'garbage$(x)',
    })
    assert resp.status_code == 302
    assert not AdbConnection.objects.filter(label='Cov Bad Addr').exists()


@pytest.mark.django_db
def test_adb_connection_add_duplicate(su_client, superuser):
    AdbConnection.objects.create(
        label='Existing', host_port='127.0.0.1:5903',
        platform=AdbConnection.PLATFORM_ANDROID, created_by=superuser)
    resp = su_client.post(reverse('rbac:adb_connection_add'), {
        'label': 'Dup',
        'host_port': '127.0.0.1:5903',
    })
    assert resp.status_code == 302
    # No second row for the same host_port.
    assert AdbConnection.objects.filter(host_port='127.0.0.1:5903').count() == 1


@pytest.mark.django_db
def test_adb_connection_add_unknown_platform_defaults_android(su_client):
    resp = su_client.post(reverse('rbac:adb_connection_add'), {
        'label': 'Cov Plat',
        'host_port': '127.0.0.1:5904',
        'platform': 'windows-phone',
    })
    assert resp.status_code == 302
    conn = AdbConnection.objects.get(host_port='127.0.0.1:5904')
    assert conn.platform == AdbConnection.PLATFORM_ANDROID


@pytest.mark.django_db
def test_adb_connection_remove(su_client, superuser):
    conn = AdbConnection.objects.create(
        label='Cov Rm', host_port='127.0.0.1:5905',
        platform=AdbConnection.PLATFORM_ANDROID, created_by=superuser)
    resp = su_client.post(
        reverse('rbac:adb_connection_remove', args=[conn.pk]))
    assert resp.status_code == 302
    assert not AdbConnection.objects.filter(pk=conn.pk).exists()
    assert AuditEvent.objects.filter(action='integration.adb.remove').exists()


@pytest.mark.django_db
def test_adb_connection_set_active(su_client, superuser):
    a = AdbConnection.objects.create(
        label='Cov A', host_port='127.0.0.1:5906',
        platform=AdbConnection.PLATFORM_ANDROID, is_active=True,
        created_by=superuser)
    b = AdbConnection.objects.create(
        label='Cov B', host_port='127.0.0.1:5907',
        platform=AdbConnection.PLATFORM_ANDROID, is_active=False,
        created_by=superuser)
    resp = su_client.post(
        reverse('rbac:adb_connection_set_active', args=[b.pk]))
    assert resp.status_code == 302
    a.refresh_from_db()
    b.refresh_from_db()
    assert b.is_active is True
    assert a.is_active is False
    assert AuditEvent.objects.filter(
        action='integration.adb.set_active').exists()


@pytest.mark.django_db
def test_adb_connection_test_returns_json(su_client, superuser):
    conn = AdbConnection.objects.create(
        label='Cov Test', host_port='127.0.0.1:5908',
        platform=AdbConnection.PLATFORM_ANDROID, created_by=superuser)
    resp = su_client.post(
        reverse('rbac:adb_connection_test', args=[conn.pk]))
    assert resp.status_code == 200
    data = resp.json()
    assert set(['success', 'status', 'message',
                'last_status_at', 'devices_list']).issubset(data.keys())
    assert isinstance(data['devices_list'], list)
    conn.refresh_from_db()
    assert conn.last_status_at is not None
    assert AuditEvent.objects.filter(action='integration.adb.test').exists()
