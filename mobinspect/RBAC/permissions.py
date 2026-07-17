"""
MobInspect — permission resolution.

Centralizes the "what can this user do?" question. Used by:
  - decorators.require_permission
  - middleware (populates request.mi_permissions)
  - context processor (template {% can %} tag)
  - API auth (api_middleware)

A user's effective permission set is the union of permissions across
all active (non-expired) role assignments.

Cached for the duration of a request via the middleware to avoid
repeated DB hits per template render.
"""
from django.conf import settings
from django.db.models import Q
from django.utils import timezone


def is_auth_disabled():
    """Single source of truth for the dev auth bypass."""
    return getattr(settings, 'DISABLE_AUTHENTICATION', '0') == '1'


def effective_user(request_or_user):
    """Return the user whose permissions should be evaluated.

    Accepts either a request object (preferred — honors request.api_user)
    or a User instance directly.
    """
    if request_or_user is None:
        return None
    # Duck-typing: a request has .user and possibly .api_user.
    if hasattr(request_or_user, 'user'):
        api_user = getattr(request_or_user, 'api_user', None)
        if api_user is not None and api_user.is_authenticated:
            return api_user
        u = request_or_user.user
        return u if u is not None and u.is_authenticated else None
    # Else assume it's a User-like.
    return request_or_user if getattr(
        request_or_user, 'is_authenticated', False) else None


def get_user_permissions(target):
    """Return a frozenset of permission codenames.

    `target` is a request or a User. Anonymous users return an empty set.
    Superusers receive the full catalog. Otherwise we union permissions
    across all active (non-expired) role assignments.
    """
    user = effective_user(target)
    if user is None:
        return frozenset()

    if user.is_superuser:
        from mobinspect.RBAC.models import Permission as MIPerm
        return frozenset(MIPerm.objects.values_list('codename', flat=True))

    from mobinspect.RBAC.models import RoleAssignment
    now = timezone.now()
    qs = (
        RoleAssignment.objects
        .filter(user=user)
        .filter(_q_active(now))
        .values_list('role__permissions__codename', flat=True)
        .distinct()
    )
    return frozenset(c for c in qs if c)


def get_user_roles(target):
    """Return a sorted list of distinct Role names the user holds."""
    user = effective_user(target)
    if user is None:
        return []
    from mobinspect.RBAC.models import RoleAssignment
    now = timezone.now()
    qs = (
        RoleAssignment.objects
        .filter(user=user)
        .filter(_q_active(now))
        .values_list('role__name', flat=True)
        .distinct()
    )
    return sorted(qs)


def has_permission(target, codename):
    """Quick check; for many checks per request use the cached set."""
    user = effective_user(target)
    if user is None:
        return False
    if user.is_superuser:
        return True
    if is_auth_disabled():
        return True
    return codename in get_user_permissions(user)


def has_any_permission(target, codenames):
    if not codenames:
        return True
    perms = get_user_permissions(target)
    return any(c in perms for c in codenames)


def has_all_permissions(target, codenames):
    perms = get_user_permissions(target)
    return all(c in perms for c in codenames)


def _q_active(now):
    """Q object: assignment is non-expired."""
    return Q(expires_at__isnull=True) | Q(expires_at__gt=now)
