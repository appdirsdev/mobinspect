"""Real-execution coverage tests for the seed_rbac management command
(mobinspect/RBAC/management/commands/seed_rbac.py).

STRICT: no mocks. Drives the real management command via
django.core.management.call_command against the real Postgres test DB,
the real permission-catalog / default-roles migration seed() functions
(imported live via importlib, exactly as the command does), and the real
ORM. Nothing about `_AppsShim` or the migration seed functions is faked --
the shim really resolves the CURRENT (not historical) model classes via
django.apps.apps.get_model, and the seed() functions really run.
"""
import io
from importlib import import_module

import pytest

from django.contrib.auth.models import Group
from django.core.management import call_command

from mobinspect.RBAC.management.commands.seed_rbac import _AppsShim
from mobinspect.RBAC.models import Permission, Role, RoleAssignment

# Module name has a leading digit -> not importable via dotted syntax,
# same reason the seed_rbac command itself uses importlib.
PERMISSIONS = import_module(
    'mobinspect.RBAC.migrations.0002_seed_permissions').PERMISSIONS


pytestmark = pytest.mark.django_db


def _call(**opts):
    out, err = io.StringIO(), io.StringIO()
    call_command('seed_rbac', stdout=out, stderr=err, **opts)
    return out.getvalue(), err.getvalue()


# ─────────────────────────────────────────────────────── _AppsShim
def test_apps_shim_resolves_real_current_model():
    # Real django.apps lookup, not a migration historical model -- proves
    # the shim's .get_model() interface actually works end to end.
    model = _AppsShim.get_model('rbac', 'Role')
    assert model is Role
    model2 = _AppsShim.get_model('rbac', 'Permission')
    assert model2 is Permission


# ─────────────────────────────────────────────────────── basic seed
def test_seed_rbac_basic_populates_catalog_and_roles():
    out, err = _call()
    assert 'Seeded permission catalog.' in out
    assert 'Seeded default system roles.' in out
    assert err == ''

    codenames = set(Permission.objects.values_list('codename', flat=True))
    expected = {p[0] for p in PERMISSIONS}
    assert expected.issubset(codenames)

    admin = Role.objects.get(name='Administrator')
    assert admin.is_system is True
    # Administrator holds the FULL catalog ('*' marker in the migration).
    assert admin.permissions.count() == Permission.objects.count()

    viewer = Role.objects.get(name='Viewer')
    assert 'scan.view' in viewer.codenames()
    assert 'admin.user.delete' not in viewer.codenames()


def test_seed_rbac_idempotent_rerun():
    _call()
    perm_count_1 = Permission.objects.count()
    role_count_1 = Role.objects.filter(is_system=True).count()

    # Re-running must not create duplicates (update_or_create keyed on
    # codename / group respectively).
    out, _err = _call()
    assert 'Seeded permission catalog.' in out
    perm_count_2 = Permission.objects.count()
    role_count_2 = Role.objects.filter(is_system=True).count()

    assert perm_count_2 == perm_count_1
    assert role_count_2 == role_count_1
    assert role_count_2 == 4  # Administrator, Security Analyst, Viewer, API User


def test_seed_rbac_reset_deletes_and_reseeds_system_roles():
    _call()
    assert Role.objects.filter(name='Administrator', is_system=True).exists()

    out, _err = _call(reset=True)
    assert 'Deleted existing system roles.' in out
    assert 'Seeded default system roles.' in out
    # Recreated after the reset (fresh row, same wrapped Group).
    admin = Role.objects.get(name='Administrator')
    assert admin.is_system is True
    assert admin.permissions.count() == Permission.objects.count()


def test_seed_rbac_reset_preserves_user_accounts():
    """--reset only removes system Role rows -- User accounts are never
    touched (docstring: 'preserves users')."""
    from django.contrib.auth import get_user_model
    User = get_user_model()
    user = User.objects.create_user(username='cov_seed_user', password='pw')

    _call()
    admin_role = Role.objects.get(name='Administrator')
    RoleAssignment.objects.create(user=user, role=admin_role)

    _call(reset=True)

    # The User row itself survives the reset untouched.
    assert User.objects.filter(pk=user.pk).exists()


def test_seed_rbac_reset_without_prior_seed_is_a_noop_delete():
    """--reset on a table with no system roles yet still logs the
    'Deleted' message (filter().delete() on an empty queryset is a
    harmless no-op) and seeding still proceeds normally."""
    Role.objects.filter(is_system=True).delete()
    out, _err = _call(reset=True)
    assert 'Deleted existing system roles.' in out
    assert Role.objects.filter(name='Administrator', is_system=True).exists()


def test_seed_rbac_reuses_existing_group_across_reset():
    """The wrapped auth.Group survives a --reset (only the Role row is
    deleted), so re-seeding must reuse the SAME Group rather than create
    a sibling."""
    _call()
    group_pk_before = Group.objects.get(name='Administrator').pk

    _call(reset=True)

    group_pk_after = Group.objects.get(name='Administrator').pk
    assert group_pk_before == group_pk_after
    assert Group.objects.filter(name='Administrator').count() == 1
