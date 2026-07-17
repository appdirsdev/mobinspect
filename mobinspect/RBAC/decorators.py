"""
MobInspect — view decorators.

Usage:
    from mobinspect.RBAC.decorators import require_permission

    @require_permission('scan.create')
    def upload(request):
        ...

For multiple permissions:
    @require_permission('scan.view', 'scan.export.pdf', any_=False)  # all required
    @require_permission('scan.view', 'scan.view_own', any_=True)     # any one suffices
"""
from functools import wraps

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import redirect
from django.template.response import TemplateResponse
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme

from mobinspect.RBAC import audit
from mobinspect.RBAC.permissions import (
    effective_user,
    has_all_permissions,
    has_any_permission,
    is_auth_disabled,
)


def _is_api(request):
    """Authoritative check: was this request authenticated via api_middleware?

    `request.is_api` is set ONLY by RestApiAuthMiddleware on a successful
    API-key auth. We do not infer api-ness from URL paths or kwargs; that
    avoids spoofing via URL captures named 'api'.
    """
    return bool(getattr(request, 'is_api', False))


def _deny(request, codenames, is_api):
    """Return a 403 response, recording the denial in the audit log."""
    audit.record(
        request, 'denied',
        target_type='permission',
        target_id=','.join(codenames)[:80],
        metadata={
            'path': getattr(request, 'path', ''),
            'required': list(codenames),
        },
    )
    if is_api:
        return JsonResponse(
            {
                'error': 'forbidden',
                'detail': 'Insufficient permissions.',
            },
            status=403,
        )
    return TemplateResponse(request, '403.html', status=403)


def require_permission(*codenames, any_=False):
    """Require all (default) or any of the given permission codenames."""
    if not codenames:
        raise ValueError('require_permission needs ≥1 codename')

    check = has_any_permission if any_ else has_all_permissions

    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            # Dev bypass — single source of truth in permissions.is_auth_disabled.
            if is_auth_disabled():
                return view(request, *args, **kwargs)

            api = _is_api(request)
            user = effective_user(request)

            if user is None:
                if api:
                    return JsonResponse(
                        {'error': 'unauthenticated'}, status=401,
                    )
                login_url = reverse(getattr(settings, 'LOGIN_URL', 'login'))
                nxt = request.get_full_path()
                if not url_has_allowed_host_and_scheme(
                    nxt, allowed_hosts={request.get_host()},
                ):
                    nxt = '/'
                return redirect(f'{login_url}?next={nxt}')

            if check(user, codenames):
                return view(request, *args, **kwargs)
            return _deny(request, codenames, api)

        return wrapper
    return decorator


def require_role(*role_names):
    """Require the user to hold at least one of the named roles."""
    if not role_names:
        raise ValueError('require_role needs ≥1 role name')

    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            from mobinspect.RBAC.permissions import get_user_roles

            if is_auth_disabled():
                return view(request, *args, **kwargs)

            api = _is_api(request)
            user = effective_user(request)
            if user is None:
                if api:
                    return JsonResponse(
                        {'error': 'unauthenticated'}, status=401,
                    )
                return redirect(reverse(
                    getattr(settings, 'LOGIN_URL', 'login'),
                ))

            user_roles = set(get_user_roles(user))
            if user.is_superuser or user_roles & set(role_names):
                return view(request, *args, **kwargs)
            return _deny(
                request,
                tuple(f'role:{r}' for r in role_names),
                api,
            )
        return wrapper
    return decorator
