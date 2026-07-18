"""Additional real-execution coverage tests for mobinspect/RBAC/permissions.py.

STRICT: no mocks. Complements the sibling `test_permissions.py`, closing
the branches it does not reach: `effective_user(None)`, the "no user"
short-circuits in `get_user_permissions` / `get_user_roles` /
`has_permission`, the `is_auth_disabled()` bypass inside `has_permission`
for a real (non-superuser) authenticated user, and `has_any_permission`
(never exercised elsewhere in the suite -- `require_permission(any_=True)`
is not used by any current view).
"""
import pytest

from django.test import override_settings

from mobinspect.RBAC.permissions import (
    effective_user,
    get_user_permissions,
    get_user_roles,
    has_any_permission,
    has_permission,
)


# ─────────────────────────────────────────────────────── effective_user
def test_effective_user_none_input_returns_none():
    assert effective_user(None) is None


# ─────────────────────────────────────────────────────── get_user_permissions
def test_get_user_permissions_none_target_returns_empty_frozenset():
    assert get_user_permissions(None) == frozenset()


# ─────────────────────────────────────────────────────── get_user_roles
def test_get_user_roles_none_target_returns_empty_list():
    assert get_user_roles(None) == []


# ─────────────────────────────────────────────────────── has_permission
def test_has_permission_none_target_returns_false():
    assert has_permission(None, 'scan.view') is False


@pytest.mark.django_db
@override_settings(DISABLE_AUTHENTICATION='1')
def test_has_permission_dev_bypass_grants_unheld_permission(viewer_user):
    """Even a permission the user demonstrably does NOT hold is granted
    while the dev kill-switch is on."""
    assert 'admin.user.delete' not in get_user_permissions(viewer_user)
    assert has_permission(viewer_user, 'admin.user.delete') is True


@pytest.mark.django_db
def test_has_permission_superuser_bypass(superuser):
    assert has_permission(superuser, 'anything.at.all') is True


@pytest.mark.django_db
def test_has_permission_real_check_for_ordinary_user(viewer_user):
    assert has_permission(viewer_user, 'scan.view') is True
    assert has_permission(viewer_user, 'admin.user.delete') is False


# ─────────────────────────────────────────────────────── has_any_permission
def test_has_any_permission_empty_codenames_short_circuits_true():
    assert has_any_permission(None, []) is True


@pytest.mark.django_db
def test_has_any_permission_true_when_one_matches(viewer_user):
    assert has_any_permission(
        viewer_user, ['admin.user.delete', 'scan.view']) is True


@pytest.mark.django_db
def test_has_any_permission_false_when_none_match(viewer_user):
    assert has_any_permission(
        viewer_user, ['admin.user.delete', 'admin.user.create']) is False
