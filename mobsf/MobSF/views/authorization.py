"""User management and authorization."""
from itertools import chain
from inspect import signature
from functools import wraps
from enum import Enum
import logging

from django.contrib.auth.models import (
    Group,
    Permission,
    User,
)
from django.http import JsonResponse
from django.shortcuts import (
    redirect,
    render,
)
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import (
    login_required,
    permission_required as pr,
)
from mobsf.RBAC.decorators import require_permission
from django.views.decorators.http import require_http_methods
from django.template.defaulttags import register
from django.conf import settings

from mobsf.MobSF.forms import RegisterForm
from mobsf.MobSF.utils import (
    USERNAME_REGEX,
    get_md5,
)
from mobsf.DynamicAnalyzer.views.common.shared import (
    send_response,
)
from mobsf.RBAC import audit

logger = logging.getLogger(__name__)
register.filter('md5', get_md5)


PERM_CAN_SCAN = 'can_scan'
PERM_CAN_SUPPRESS = 'can_suppress'
PERM_CAN_DELETE = 'can_delete'


class Permissions(Enum):
    SCAN = f'StaticAnalyzer.{PERM_CAN_SCAN}'
    SUPPRESS = f'StaticAnalyzer.{PERM_CAN_SUPPRESS}'
    DELETE = f'StaticAnalyzer.{PERM_CAN_DELETE}'


MAINTAINER_GROUP = settings.IDP_MAINTAINER_GROUP
VIEWER_GROUP = settings.IDP_VIEWER_GROUP


def permission_required(perm):
    """Enforce a MobInspect permission on a view.

    The wrapped view's `api` kwarg only switches the *shape* of the 403
    response (JSON for API callers, HTML for browser users); it does NOT
    bypass authorization. Historically this decorator short-circuited the
    permission check whenever `api=True`, which let any holder of a valid
    API key (including Viewer-role users) invoke privileged endpoints
    like `delete_scan`. See AUDIT.md / C1.

    Resolution order for the authenticated principal:
      * API request authenticated via per-user MobInspect ApiKey →
        `request.api_user` carries the real user, so we check perms on it.
      * Session-authenticated browser user → `request.user`.
      * Legacy global API key → `request.api_user` is unset; the global
        key is treated as having NO MobInspect role, so any non-trivial
        permission is denied (operators should migrate to per-user keys).
    """
    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            sig = signature(view)
            arguments = sig.bind(request, *args, **kwargs)
            api = bool(arguments.arguments.get('api'))
            if settings.DISABLE_AUTHENTICATION == '1':
                # Auth fully disabled (single-user / dev mode).
                return view(request, *args, **kwargs)

            principal = getattr(request, 'api_user', None) or request.user
            allowed = False
            try:
                # Only superusers get a blanket bypass — aligns with the
                # RBAC path (get_user_permissions), which grants all perms to
                # is_superuser only. is_staff is NOT a bypass: a staff user
                # with no role/permission must be denied, same as RBAC.
                if getattr(principal, 'is_superuser', False):
                    allowed = True
                elif getattr(principal, 'is_authenticated', False):
                    allowed = principal.has_perm(perm.value)
            except Exception:  # noqa: BLE001
                logger.exception('[ERROR] Permission check failed')
                allowed = False

            if allowed:
                return view(request, *args, **kwargs)

            # Denied. Shape the 403 to match the caller (API vs browser).
            if api:
                return JsonResponse(
                    {
                        'status': 'denied',
                        'message': (
                            f'Permission denied: {perm.value} required.'
                        ),
                    },
                    status=403,
                )
            # Browser path: reuse Django's HTML 403 by re-raising via the
            # stock decorator (it returns/raises PermissionDenied which the
            # framework renders as 403.html).
            return pr(
                perm.value,
                raise_exception=True)(view)(request, *args, **kwargs)
        return wrapper
    return decorator


def has_permission(request, permission, api):
    """Check whether the request principal holds a MobInspect permission.

    The `api` flag only tells the CALLER how to shape its denial response
    (JSON vs HTML); it MUST NOT grant access. The historical
    `... or api: return True` short-circuit meant any valid API key —
    including a Viewer-role per-user key — could drive privileged scan
    endpoints. See AUDIT.md / C1; this mirrors the `permission_required`
    fix.

    Principal resolution mirrors `permission_required`:
      * API request authenticated via per-user MobInspect ApiKey →
        `request.api_user` carries the real user (the middleware does NOT
        replace `request.user`), so we check perms on it.
      * Session-authenticated browser user → `request.user`.
      * Legacy global API key → `request.api_user` is unset; it carries no
        MobInspect role, so non-trivial permissions are denied (operators
        should migrate to per-user keys).
    """
    try:
        if settings.DISABLE_AUTHENTICATION == '1':
            return True
        principal = getattr(request, 'api_user', None) or request.user
        # Superuser-only bypass (see permission_required): is_staff is not a
        # blanket grant — it must resolve an actual permission like RBAC does.
        if getattr(principal, 'is_superuser', False):
            return True
        if getattr(principal, 'is_authenticated', False) and \
                principal.has_perm(permission.value):
            return True
    except Exception:
        logger.exception('[ERROR] Failed to check permissions')
    return False


def create_authorization_roles():
    """Create Authorization Roles."""
    try:
        maintainer, _created = Group.objects.get_or_create(
            name=MAINTAINER_GROUP)
        Group.objects.get_or_create(name=VIEWER_GROUP)

        scan_permissions = Permission.objects.filter(
            codename=PERM_CAN_SCAN)
        suppress_permissions = Permission.objects.filter(
            codename=PERM_CAN_SUPPRESS)
        delete_permissions = Permission.objects.filter(
            codename=PERM_CAN_DELETE)
        all_perms = list(chain(
            scan_permissions, suppress_permissions, delete_permissions))
        maintainer.permissions.set(all_perms)
        _mirror_rbac_role_groups()
    except Exception:
        logger.exception('[ERROR] Failed to create roles and permissions')


def _mirror_rbac_role_groups():
    """Mirror each RBAC Role's mapped codenames into its wrapped Django
    Group's auth.Permission set.

    The RBAC seed migration (0003) sets ``role.permissions`` via historical
    models, so the runtime ``sync_legacy_group_permissions`` m2m signal never
    fires for the seeded roles — leaving every role group with EMPTY Django
    permissions. As a result any non-superuser assigned an RBAC role is
    denied by the legacy ``@permission_required(Permissions.SCAN/DELETE/
    SUPPRESS)`` guards (upload, delete_scan, suppress, dynamic analysis).

    This runs at startup via the ``create_roles`` command — AFTER migrate,
    so the ``can_scan``/``can_delete``/``can_suppress`` auth.Permission rows
    exist. Uses ``filter()`` because each legacy codename spans several
    StaticAnalyzer content types. Idempotent.
    """
    try:
        from mobsf.RBAC.models import Role
        from mobsf.RBAC.signals import LEGACY_PERMISSION_MAP
    except Exception:
        logger.exception('[ERROR] RBAC role-group mirror unavailable')
        return
    for role in Role.objects.all():
        legacy = []
        for code in role.codenames():
            mapping = LEGACY_PERMISSION_MAP.get(code)
            if mapping:
                legacy.extend(Permission.objects.filter(
                    content_type__app_label=mapping[0],
                    codename=mapping[1],
                ))
        role.group.permissions.set(legacy)


@require_permission('admin.user.view')
def users(request):
    """Show all users with their MobInspect role assignments."""
    if settings.DISABLE_AUTHENTICATION == '1':
        return redirect('/')

    # Pull roles + assignments for the new RBAC UI; tolerate the case
    # where the RBAC app isn't migrated yet (fresh setups) by falling
    # back to empty defaults.
    try:
        from mobsf.RBAC.models import Role
        all_roles = list(Role.objects.all())
    except Exception:  # noqa: BLE001
        all_roles = []

    users_qs = (
        get_user_model().objects.all()
        .prefetch_related('role_assignments__role')
    )
    # Decorate each user with a `role_ids` set for the template.
    for u in users_qs:
        try:
            u.role_ids = {ra.role_id for ra in u.role_assignments.all()}
        except Exception:  # noqa: BLE001
            u.role_ids = set()

    context = {
        'title': 'All Users',
        'users': users_qs,
        'all_roles': all_roles,
        'version': settings.MOBSF_VER,
    }
    return render(request, 'auth/users.html', context)


@require_permission('admin.user.create')
def create_user(request):
    if settings.DISABLE_AUTHENTICATION == '1':
        return redirect('/')
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            role_pk = form.cleaned_data.get('role')
            username = request.POST.get('username')
            if not username:
                messages.error(request, 'No Username Provided')
                return redirect('create_user')
            if not USERNAME_REGEX.match(username):
                messages.error(request, 'Invalid Username')
                return redirect('create_user')
            user = form.save()
            user.is_staff = False
            user.save(update_fields=['is_staff'])
            # Assign the selected RBAC role.
            rbac_role = None
            try:
                from mobsf.RBAC.models import Role, RoleAssignment
                rbac_role = Role.objects.get(pk=role_pk)
                RoleAssignment.objects.get_or_create(
                    user=user,
                    role=rbac_role,
                    defaults={'granted_by': request.user},
                )
                # Mirror into the role's backing Django Group for legacy
                # permission checks (e.g. @permission_required(Permissions.SCAN)).
                user.groups.add(rbac_role.group)
            except Exception:
                logger.exception('[WARN] Could not assign RBAC role for new user %s', user.username)
            audit.record(
                request,
                'admin.user.create',
                target_type='user',
                target_id=user.id,
                metadata={
                    'username': user.username,
                    'role': rbac_role.name if rbac_role else str(role_pk),
                },
            )
            messages.success(
                request,
                'User created successfully!')
            return redirect('create_user')
        else:
            messages.error(
                request,
                'Please correct the error below.')
    else:
        form = RegisterForm()
    context = {
        'title': 'Create User',
        'version': settings.VERSION,
        'form': form,
    }
    return render(request, 'auth/register.html', context)


@require_permission('admin.user.delete')
@require_http_methods(['POST'])
def delete_user(request):
    data = {'deleted': 'Failed to delete user'}
    try:
        if settings.DISABLE_AUTHENTICATION == '1':
            return redirect('/')
        username = request.POST.get('username')
        if not username:
            data = {'deleted': 'No Username Provided'}
            return send_response(data)
        if not USERNAME_REGEX.match(username):
            data = {'deleted': 'Invalid Username'}
            return send_response(data)
        u = User.objects.get(username=username)
        if u.is_staff:
            data = {'deleted': 'Cannot delete staff users'}
            return send_response(data)
        # Capture identity BEFORE delete — once the row is gone the
        # id/username attributes still exist on the in-memory instance
        # but the audit record is more useful when emitted with the
        # values we captured here.
        deleted_id = u.id
        deleted_username = u.username

        # A user referenced by the audit log CANNOT be hard-deleted: the
        # actor FK is on_delete=SET_NULL, which issues an UPDATE against the
        # append-only audit_event table and is blocked by its immutability
        # trigger. Deactivate such users instead — this revokes all access
        # (login + permissions) while preserving the audit trail intact.
        from mobsf.RBAC.models import AuditEvent, RoleAssignment
        u.groups.clear()
        RoleAssignment.objects.filter(user=u).delete()
        if AuditEvent.objects.filter(actor=u).exists():
            u.is_active = False
            u.save(update_fields=['is_active'])
            action = 'admin.user.deactivate'
        else:
            u.delete()
            action = 'admin.user.delete'
        audit.record(
            request,
            action,
            target_type='user',
            target_id=deleted_id,
            metadata={'username': deleted_username},
        )
        data = {'deleted': 'yes'}
    except User.DoesNotExist:
        data = {'deleted': 'User does not exist'}
    except Exception as e:
        logger.exception('[ERROR] Failed to delete user')
        data = {'deleted': f'Failed to delete user: {e}'}
    return send_response(data)
