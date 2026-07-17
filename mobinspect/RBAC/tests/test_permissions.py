"""
Permission-resolution tests (H17).

Pins three behaviors of mobinspect.RBAC.permissions:

  * `effective_user` honors `request.api_user` over `request.user` when
    both are present (so an API-key auth doesn't fall through to the
    session user's role set).
  * `get_user_permissions` short-circuits to the full catalog for a
    superuser — the fast path matters both for performance and to keep
    `is_superuser` behaving like a kill-switch for emergency access.
  * An expired `RoleAssignment` (expires_at in the past) is excluded
    from the effective permission set. Without this, revocation by
    expiry would silently fail open.
"""
from datetime import timedelta

import pytest

from django.utils import timezone

from mobinspect.RBAC.models import Permission, Role, RoleAssignment
from mobinspect.RBAC.permissions import (
    effective_user,
    get_user_permissions,
    has_permission,
)


class _FakeRequest:
    """Minimal duck-typed request — only the attrs the resolver reads."""

    def __init__(self, user=None, api_user=None):
        self.user = user
        if api_user is not None:
            self.api_user = api_user


# ─────────────────────────────────────────────────────── effective_user
@pytest.mark.django_db
def test_effective_user_prefers_api_user_when_set(viewer_user, analyst_user):
    """API-key user wins over session user (key auth must not fall through)."""
    req = _FakeRequest(user=viewer_user, api_user=analyst_user)
    assert effective_user(req) == analyst_user


@pytest.mark.django_db
def test_effective_user_falls_back_to_request_user(viewer_user):
    """No api_user → use the session user."""
    req = _FakeRequest(user=viewer_user)
    assert effective_user(req) == viewer_user


@pytest.mark.django_db
def test_effective_user_returns_none_for_anonymous(django_user_model):
    """An unauthenticated session resolves to None, not AnonymousUser."""
    from django.contrib.auth.models import AnonymousUser
    req = _FakeRequest(user=AnonymousUser())
    assert effective_user(req) is None


@pytest.mark.django_db
def test_effective_user_accepts_bare_user(viewer_user):
    """Callers may pass a User directly (e.g. management commands)."""
    assert effective_user(viewer_user) == viewer_user


# ─────────────────────────────────────────────────────── superuser fast-path
@pytest.mark.django_db
def test_superuser_gets_full_catalog(superuser):
    """is_superuser=True → frozenset == every codename in Permission."""
    perms = get_user_permissions(superuser)
    expected = frozenset(Permission.objects.values_list('codename', flat=True))
    assert perms == expected
    # And the catalog is non-empty — guards against the migration being
    # rolled back to an empty Permission table.
    assert len(expected) > 0


@pytest.mark.django_db
def test_superuser_has_arbitrary_permission(superuser):
    """has_permission returns True for any codename, even unknown ones."""
    # Even a permission that doesn't exist in the catalog short-circuits
    # to True for a superuser — by design, superuser is an escape hatch.
    assert has_permission(superuser, 'nonexistent.permission')
    assert has_permission(superuser, 'scan.delete')


# ─────────────────────────────────────────────────────── expired assignments
@pytest.mark.django_db
def test_expired_assignment_is_excluded(django_user_model):
    """A RoleAssignment with expires_at in the past must not grant perms."""
    user = django_user_model.objects.create_user(
        username='rbac_expired', password='x',
    )
    role = Role.objects.filter(name='Viewer').first()
    assert role is not None, 'Viewer role should be seeded by migration 0003'

    ra = RoleAssignment.objects.create(user=user, role=role)
    # Sanity: live assignment grants Viewer's perms.
    live = get_user_permissions(user)
    assert 'scan.view' in live

    # Now expire it.
    ra.expires_at = timezone.now() - timedelta(hours=1)
    ra.save(update_fields=['expires_at'])

    expired = get_user_permissions(user)
    assert 'scan.view' not in expired
    # And the queryset really did return an empty result, not the
    # catalog by accident.
    assert expired == frozenset()


@pytest.mark.django_db
def test_future_expiry_is_still_active(django_user_model):
    """expires_at in the future is treated as live."""
    user = django_user_model.objects.create_user(
        username='rbac_future', password='x',
    )
    role = Role.objects.filter(name='Viewer').first()
    assert role is not None

    RoleAssignment.objects.create(
        user=user, role=role,
        expires_at=timezone.now() + timedelta(days=7),
    )
    perms = get_user_permissions(user)
    assert 'scan.view' in perms
