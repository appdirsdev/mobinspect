"""
Privilege-escalation guard tests (H17).

Pins the most-important authorization invariant in the RBAC views:
a user editing roles cannot grant a permission they do not themselves
hold. Without this guard, the lowest-privilege user with
`rbac.role.manage` could mint themselves an admin role and call any
privileged endpoint.

The actual enforcement is split across two layers:

  1. `RoleForm.clean_permission_codenames` validates the form post.
  2. `role_assign` view checks the actor's permission set against the
     role's codename set before creating the assignment.

We test the form path here because it's the entry point for both
role-create and role-edit and runs deterministically without a full
HTTP round-trip. The view-level guard is exercised by integration
tests in test_api_auth.py.
"""
import pytest

from mobinspect.RBAC.forms import RoleForm


@pytest.mark.django_db
def test_low_priv_user_cannot_grant_admin_delete(viewer_user):
    """A user holding only 'scan.view' cannot create a role with
    'admin.user.delete'.

    The form is the privilege-escalation chokepoint — bypassing this
    would allow any holder of `rbac.role.manage` to escalate to full
    admin in one POST.
    """
    form = RoleForm(
        data={
            'name': 'EscalatedRole',
            'description': '',
            'color': '#2563EB',
            'icon': 'shield',
            'permission_codenames': 'admin.user.delete',
        },
        actor=viewer_user,
    )
    assert not form.is_valid(), (
        'Form must reject permissions the actor does not hold. '
        f'Errors: {form.errors!r}')
    # The exact error message belongs to the codenames field.
    errors = form.errors.get('permission_codenames', [])
    assert any('admin.user.delete' in e for e in errors), (
        f'Expected admin.user.delete in error messages, got {errors!r}')


@pytest.mark.django_db
def test_user_can_grant_permissions_they_hold(viewer_user):
    """Sanity check: the guard does not over-block.

    A Viewer can create a role granting `scan.view` (a permission they
    themselves hold). If this fails, the form is rejecting too much
    and the escalation guard would be unusable in practice.
    """
    form = RoleForm(
        data={
            'name': 'ViewerLite',
            'description': '',
            'color': '#2563EB',
            'icon': 'shield',
            'permission_codenames': 'scan.view',
        },
        actor=viewer_user,
    )
    assert form.is_valid(), (
        f'Form must accept permissions the actor holds. '
        f'Errors: {form.errors!r}')


@pytest.mark.django_db
def test_superuser_can_grant_anything(superuser):
    """Superusers escape the escalation guard — they hold every permission."""
    form = RoleForm(
        data={
            'name': 'RootRole',
            'description': '',
            'color': '#DC2626',
            'icon': 'shield-alert',
            'permission_codenames': 'admin.user.delete',
        },
        actor=superuser,
    )
    assert form.is_valid(), (
        f'Superuser must be able to grant any permission. '
        f'Errors: {form.errors!r}')


@pytest.mark.django_db
def test_unknown_codename_rejected(viewer_user):
    """A codename not in the Permission catalog is rejected by the form."""
    form = RoleForm(
        data={
            'name': 'FakeRole',
            'description': '',
            'color': '#2563EB',
            'icon': 'shield',
            'permission_codenames': 'nonexistent.perm.codename',
        },
        actor=viewer_user,
    )
    assert not form.is_valid()
    errors = form.errors.get('permission_codenames', [])
    assert any('Unknown' in e or 'nonexistent' in e for e in errors), (
        f'Expected unknown-codename error, got {errors!r}')
