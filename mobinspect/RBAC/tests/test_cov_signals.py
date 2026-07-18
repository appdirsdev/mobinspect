"""Additional real-execution coverage test for mobinspect/RBAC/signals.py.

STRICT: no mocks. Closes branches the sibling `test_signals.py` /
`test_audit_signals.py` already pin but which live outside the
`test_cov_*.py` coverage glob used by the campaign run:

  * `sync_group_name_on_role_save`'s rename branch -- renaming a Role
    propagates the new name onto its wrapped Group (test_signals.py's
    `test_role_name_change_propagates_to_group`, mirrored here).
  * `sync_legacy_group_permissions`'s early-return when the m2m_changed
    signal fires with `reverse=True` (i.e. the change was made through
    the REVERSE accessor, `permission.roles.add(role)`, rather than
    `role.permissions.add(...)`).
"""
import pytest

from mobinspect.RBAC.models import Permission, Role


@pytest.mark.django_db
def test_role_rename_propagates_to_wrapped_group():
    """post_save on Role keeps Group.name in lockstep with Role.name --
    the "name changed" branch of sync_group_name_on_role_save. Creating
    the Role already fires post_save once with grp.name == instance.name
    (a no-op save), so the rename on the SECOND save is what actually
    exercises the branch."""
    from django.contrib.auth.models import Group

    group, _ = Group.objects.get_or_create(name='CovSignalsRenameRole')
    role = Role.objects.create(group=group, name='CovSignalsRenameRole')

    role.name = 'CovSignalsRenameRoleRenamed'
    role.save()

    group.refresh_from_db()
    assert group.name == 'CovSignalsRenameRoleRenamed'


@pytest.mark.django_db
def test_reverse_m2m_change_is_a_noop(django_user_model):
    """Adding a Role via the reverse `Permission.roles` accessor must not
    crash and must return early without attempting the legacy-permission
    mirror (which assumes the forward direction)."""
    from django.contrib.auth.models import Group

    group, _ = Group.objects.get_or_create(name='CovReverseM2MRole')
    role = Role.objects.create(group=group, name='CovReverseM2MRole')
    perm = Permission.objects.create(
        codename='cov.reverse.m2m.perm', name='Cov Reverse M2M',
        category='cov_reverse')

    # Reverse accessor -> m2m_changed fires with reverse=True.
    perm.roles.add(role)

    assert role in perm.roles.all()
    assert perm in role.permissions.all()
