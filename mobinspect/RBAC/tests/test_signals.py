"""
RBAC signal-mirror tests (H17).

Pins the contract between `RoleAssignment` and `User.groups`:

  * Creating a RoleAssignment adds the user to the wrapped Django Group
    (this is what keeps legacy `permission_required('app.codename')`
    decorators working for users granted access through the new UI).
  * Deleting a RoleAssignment removes the user from the wrapped Group.

Why this matters: without the mirror, a user granted "Security Analyst"
via the RBAC UI would not be a member of the underlying Django Group
and would 403 on every legacy scan/finding endpoint — defeating the
purpose of the new role system. Conversely, leaving a stale Group
membership behind after revocation would silently retain access.
"""
import pytest

from django.contrib.auth.models import Group

from mobinspect.RBAC.models import Role, RoleAssignment


@pytest.mark.django_db
def test_assignment_adds_user_to_wrapped_group(django_user_model):
    """post_save on RoleAssignment → user is in role.group."""
    user = django_user_model.objects.create_user(
        username='sig_alice', password='x',
    )
    role = Role.objects.filter(name='Viewer').first()
    assert role is not None, 'Viewer role should be seeded by migration 0003'

    # Pre-condition: not in the group yet.
    assert not user.groups.filter(pk=role.group.pk).exists()

    RoleAssignment.objects.create(user=user, role=role)

    # Post-condition: signal fired, user added to the wrapped Group.
    assert user.groups.filter(pk=role.group.pk).exists()


@pytest.mark.django_db
def test_assignment_is_idempotent(django_user_model):
    """Re-running the add path twice does not duplicate Group membership."""
    user = django_user_model.objects.create_user(
        username='sig_bob', password='x',
    )
    role = Role.objects.filter(name='Viewer').first()
    assert role is not None

    RoleAssignment.objects.create(user=user, role=role)
    # Force the signal to re-fire by triggering a save (post_save runs
    # on update too).
    ra = RoleAssignment.objects.get(user=user, role=role)
    ra.save()

    matches = user.groups.filter(pk=role.group.pk).count()
    assert matches == 1, 'Group membership must not duplicate on re-save'


@pytest.mark.django_db
def test_unassignment_removes_user_from_group(django_user_model):
    """post_delete on RoleAssignment → user is no longer in role.group."""
    user = django_user_model.objects.create_user(
        username='sig_carol', password='x',
    )
    role = Role.objects.filter(name='Viewer').first()
    assert role is not None

    ra = RoleAssignment.objects.create(user=user, role=role)
    assert user.groups.filter(pk=role.group.pk).exists()

    ra.delete()
    assert not user.groups.filter(pk=role.group.pk).exists()


@pytest.mark.django_db
def test_role_name_change_propagates_to_group(django_user_model):
    """post_save on Role keeps Group.name in lockstep with Role.name."""
    # Create a fresh non-system Role we can rename safely.
    group, _ = Group.objects.get_or_create(name='SignalTestRole')
    role = Role.objects.create(
        group=group, name='SignalTestRole', is_system=False,
    )
    role.name = 'SignalTestRoleRenamed'
    role.save()

    group.refresh_from_db()
    assert group.name == 'SignalTestRoleRenamed'
