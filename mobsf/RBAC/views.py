"""
MobInspect — RBAC admin views.

URLs (registered under /rbac/ in mobsf.RBAC.urls):
  /rbac/roles/                       list
  /rbac/roles/new/                   create
  /rbac/roles/<id>/                  edit
  /rbac/roles/<id>/delete/           confirm + delete
  /rbac/roles/<id>/assign/           assign to user
  /rbac/roles/<id>/unassign/<uid>/   revoke
  /rbac/permissions/                 catalog
  /rbac/api-keys/                    list (own only)
  /rbac/api-keys/new/                create (returns plaintext ONCE)
  /rbac/api-keys/<id>/revoke/        revoke
  /rbac/audit/                       audit log
  /rbac/integrations/adb/                     list ADB connections
  /rbac/integrations/adb/add/                 create
  /rbac/integrations/adb/<id>/remove/         delete
  /rbac/integrations/adb/<id>/set-active/     mark active
  /rbac/integrations/adb/<id>/test/           adb connect + adb devices (JSON)
"""
import logging
import re
import subprocess

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from mobsf.RBAC import audit
from mobsf.RBAC.decorators import require_permission
from mobsf.RBAC.forms import (
    ApiKeyForm,
    RoleAssignmentForm,
    RoleForm,
    all_permissions_grouped,
)
from mobsf.RBAC.models import (
    AdbConnection,
    ApiKey,
    AuditEvent,
    Role,
    RoleAssignment,
)


logger = logging.getLogger('mobsf.MobSF')

User = get_user_model()

# Wall-clock cap for any single adb subprocess invocation (seconds).
# adb connect to an unreachable host can hang on TCP connect; this keeps
# the request thread from blocking indefinitely.
ADB_TIMEOUT = 15


# Curated subset of Lucide icons offered for role customization.
# Must be a subset of mi_icons.ICON_PATHS to render correctly.
ICON_OPTIONS = [
    'shield', 'shield-check', 'shield-alert',
    'key', 'lock', 'eye',
    'users', 'user',
    'zap', 'activity', 'bell',
    'settings', 'sliders',
    'package', 'database',
]


# Maximum filter input length on audit log endpoint (DOS prevention).
MAX_FILTER_LEN = 80


# ─────────────────────────────────────────────────────── roles
@login_required
@require_permission('rbac.role.view')
def roles_list(request):
    roles = (
        Role.objects.all()
        .prefetch_related('permissions', 'assignments')
    )
    return render(request, 'rbac/roles_list.html', {
        'title': 'Roles',
        'version': settings.MOBSF_VER,
        'roles': roles,
    })


@login_required
@require_permission('rbac.role.manage')
@require_http_methods(['GET', 'POST'])
def role_create(request):
    grouped_perms = all_permissions_grouped()
    if request.method == 'POST':
        form = RoleForm(request.POST, actor=request.user)
        if form.is_valid():
            role = form.save()
            audit.record(
                request, 'role.create',
                target_type='role', target_id=role.pk,
                metadata={'name': role.name},
            )
            messages.success(request, f'Role "{role.name}" created.')
            return redirect('rbac:roles_list')
    else:
        form = RoleForm(actor=request.user)
    return render(request, 'rbac/role_form.html', {
        'title': 'New role',
        'version': settings.MOBSF_VER,
        'form': form,
        'grouped_perms': grouped_perms,
        'selected_codes': [],
        'icon_options': ICON_OPTIONS,
        'is_create': True,
    })


@login_required
@require_permission('rbac.role.manage')
@require_http_methods(['GET', 'POST'])
def role_edit(request, role_id):
    role = get_object_or_404(Role, pk=role_id)
    grouped_perms = all_permissions_grouped()
    if request.method == 'POST':
        form = RoleForm(request.POST, instance=role, actor=request.user)
        if form.is_valid():
            before = set(role.codenames())
            role = form.save()
            after = set(role.codenames())
            added = after - before
            removed = before - after
            audit.record(
                request, 'role.update',
                target_type='role', target_id=role.pk,
                metadata={
                    'name': role.name,
                    'added': sorted(added),
                    'removed': sorted(removed),
                },
            )
            messages.success(request, f'Role "{role.name}" updated.')
            return redirect('rbac:roles_list')
    else:
        form = RoleForm(instance=role, actor=request.user)
    return render(request, 'rbac/role_form.html', {
        'title': f'Edit · {role.name}',
        'version': settings.MOBSF_VER,
        'form': form,
        'role': role,
        'grouped_perms': grouped_perms,
        'selected_codes': sorted(role.codenames()),
        'icon_options': ICON_OPTIONS,
        'is_create': False,
    })


@login_required
@require_permission('rbac.role.manage')
@require_http_methods(['POST'])
def role_delete(request, role_id):
    role = get_object_or_404(Role, pk=role_id)
    if role.is_system:
        messages.error(request, f'System role "{role.name}" cannot be deleted.')
        return redirect('rbac:roles_list')
    name = role.name
    audit.record(
        request, 'role.delete',
        target_type='role', target_id=role.pk,
        metadata={'name': name},
    )
    role.delete()  # cascades to RoleAssignments; Group remains
    messages.success(request, f'Role "{name}" deleted.')
    return redirect('rbac:roles_list')


@login_required
@require_permission('rbac.role.manage')
@require_http_methods(['POST'])
def role_assign(request, role_id):
    role = get_object_or_404(Role, pk=role_id)
    form = RoleAssignmentForm(request.POST)
    if not form.is_valid():
        return HttpResponseBadRequest('invalid form')
    user = get_object_or_404(User, pk=form.cleaned_data['user_id'])

    # Prevent privilege escalation: actor must already hold every permission
    # the granted role confers. Superusers escape this guard.
    if not request.user.is_superuser:
        from mobsf.RBAC.permissions import get_user_permissions
        actor_perms = get_user_permissions(request.user)
        role_perms  = role.codenames()
        elevated    = role_perms - actor_perms
        if elevated:
            messages.error(
                request,
                f'Cannot grant role "{role.name}": it includes permissions '
                f'you do not hold ({", ".join(sorted(elevated))[:200]}).',
            )
            return redirect('users')

    ra, created = RoleAssignment.objects.get_or_create(
        user=user, role=role,
        defaults={
            'granted_by': request.user,
            'expires_at': form.cleaned_data.get('expires_at'),
        },
    )
    audit.record(
        request, 'role.assign' if created else 'role.assign.noop',
        target_type='user', target_id=user.pk,
        metadata={'role': role.name, 'created': created},
    )
    if created:
        messages.success(request, f'Granted "{role.name}" to {user.username}.')
    else:
        messages.info(request, f'{user.username} already has "{role.name}".')
    return redirect('users')


@login_required
@require_permission('rbac.role.manage')
@require_http_methods(['POST'])
def role_unassign(request, role_id, user_id):
    role = get_object_or_404(Role, pk=role_id)
    user = get_object_or_404(User, pk=user_id)

    # Prevent locking everyone out of the Administrator role.
    if role.name == 'Administrator':
        remaining = (
            RoleAssignment.objects
            .filter(role=role)
            .exclude(user=user)
            .exists()
        )
        if not remaining:
            messages.error(
                request,
                'Cannot revoke the last Administrator. '
                'Grant Administrator to another user first.',
            )
            return redirect('users')

    deleted, _ = RoleAssignment.objects.filter(
        user=user, role=role,
    ).delete()
    audit.record(
        request, 'role.unassign',
        target_type='user', target_id=user.pk,
        metadata={'role': role.name, 'deleted': deleted},
    )
    messages.success(request, f'Revoked "{role.name}" from {user.username}.')
    return redirect('users')


# ─────────────────────────────────────────────────────── permissions catalog
@login_required
@require_permission('rbac.role.view')
def permissions_browse(request):
    return render(request, 'rbac/permissions.html', {
        'title': 'Permissions catalog',
        'version': settings.MOBSF_VER,
        'grouped_perms': all_permissions_grouped(),
    })


# ─────────────────────────────────────────────────────── api keys
@login_required
@require_permission('api.key.create')
@require_http_methods(['GET', 'POST'])
def api_keys(request):
    just_created = None
    plaintext = None

    if request.method == 'POST':
        form = ApiKeyForm(request.POST)
        if form.is_valid():
            just_created, plaintext = ApiKey.generate(
                user=request.user,
                name=form.cleaned_data['name'],
                expires_at=form.expires_at(),
            )
            audit.record(
                request, 'api_key.create',
                target_type='api_key', target_id=just_created.pk,
                metadata={'name': just_created.name},
            )
    else:
        form = ApiKeyForm()

    keys = ApiKey.objects.filter(user=request.user).order_by(
        '-created_at',
    )
    return render(request, 'rbac/api_keys.html', {
        'title': 'API keys',
        'version': settings.MOBSF_VER,
        'form': form,
        'keys': keys,
        'just_created': just_created,
        'plaintext': plaintext,
    })


@login_required
@require_http_methods(['POST'])
def api_key_revoke(request, key_id):
    key = get_object_or_404(ApiKey, pk=key_id, user=request.user)
    if key.revoked_at is None:
        key.revoked_at = timezone.now()
        key.save(update_fields=['revoked_at'])
        audit.record(
            request, 'api_key.revoke',
            target_type='api_key', target_id=key.pk,
            metadata={'name': key.name},
        )
        messages.success(request, f'Key "{key.name}" revoked.')
    return redirect('rbac:api_keys')


# ─────────────────────────────────────────────────────── audit log
@login_required
@require_permission('audit.view')
def audit_log(request):
    qs = AuditEvent.objects.select_related('actor').all()
    action = (request.GET.get('action', '') or '').strip()[:MAX_FILTER_LEN]
    actor  = (request.GET.get('actor', '')  or '').strip()[:MAX_FILTER_LEN]

    if action:
        qs = qs.filter(action__icontains=action)
    if actor:
        # __istartswith is anchored — far cheaper than __icontains for actor names.
        qs = qs.filter(actor__username__istartswith=actor)

    paginator = Paginator(qs, 50)
    page = paginator.get_page(request.GET.get('page', 1))
    return render(request, 'rbac/audit_log.html', {
        'title': 'Audit log',
        'version': settings.MOBSF_VER,
        'page': page,
        'action_filter': action,
        'actor_filter': actor,
    })


# ──────────────────────────────────────────── integrations · adb
#
# Lets an admin wire a network-adb device (remote emulator / physical
# device) through the dashboard instead of the MOBSF_ANALYZER_IDENTIFIER
# env var. ``host_port`` is a command-execution surface: it is ALWAYS
# validated against SSH_DEVICE_ID_REGEX before being stored or handed to a
# subprocess, every adb call passes argv as a list (never a shell string),
# and raw adb output is truncated before it is persisted or returned.

# Cap on captured adb output we keep/return — keeps the audit metadata and
# JSON payloads bounded and avoids surfacing a wall of daemon noise.
ADB_OUTPUT_MAX = 500

# Defense-in-depth host charset. SSH_DEVICE_ID_REGEX's host group is
# permissive ([^:\[\]]+), which would admit shell-meta like "$(...)". adb
# is always invoked with argv lists (shell=False) so these are never
# evaluated, but a hostname/IPv4 has no legitimate use for anything beyond
# letters, digits, dot and hyphen — so we reject the rest outright.
_HOST_CHARSET_RE = re.compile(r'^[A-Za-z0-9.\-]+$')
# IPv6 inside [] may legitimately contain hex, ':' and '.' (mapped v4).
_IPV6_CHARSET_RE = re.compile(r'^[0-9A-Fa-f:.]+$')


def _validate_host_port(raw):
    """Validate user-supplied host:port against the strict device regex.

    Returns the canonical (stripped) value on success, or None if it does
    not match ``host:port`` / ``[ipv6]:port``. Also rejects ports outside
    1-65535 and any host containing characters with no place in a
    hostname / IP. The returned value is safe to hand to ``adb connect``
    as a single argv element.
    """
    from mobsf.MobSF.utils import SSH_DEVICE_ID_REGEX
    value = (raw or '').strip()
    if not value or len(value) > 255:
        return None
    match = SSH_DEVICE_ID_REGEX.match(value)
    if not match:
        return None
    try:
        port = int(match.group('port'))
    except (TypeError, ValueError):
        return None
    if not (1 <= port <= 65535):
        return None
    host = match.group('host')
    ipv6 = match.group('ipv6')
    if host is not None and not _HOST_CHARSET_RE.match(host):
        return None
    if ipv6 is not None and not _IPV6_CHARSET_RE.match(ipv6):
        return None
    return value


def _run_adb(args):
    """Run an adb command as a list (shell=False) with a hard timeout.

    Returns a tuple ``(status, message)`` where status is one of the
    AdbConnection.STATUS_* values and message is a truncated, safe-to-store
    string. Never raises.
    """
    from mobsf.MobSF.utils import get_adb
    adb = get_adb()
    if not adb:
        return AdbConnection.STATUS_FAILED, 'adb binary not found on server.'
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, shell=False
            [adb, *args],
            capture_output=True,
            timeout=ADB_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return (
            AdbConnection.STATUS_TIMEOUT,
            f'adb {args[0]} timed out after {ADB_TIMEOUT}s.',
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning('adb %s failed: %s', args, exc)
        return AdbConnection.STATUS_FAILED, 'adb invocation failed.'

    out = (proc.stdout or b'').decode('utf-8', 'replace')
    err = (proc.stderr or b'').decode('utf-8', 'replace')
    combined = (out + ('\n' + err if err.strip() else '')).strip()
    combined = combined[:ADB_OUTPUT_MAX]
    # adb connect prints "connected to" / "already connected" on success;
    # it exits 0 even for "unable to connect", so inspect the text too.
    lowered = combined.lower()
    if proc.returncode == 0 and (
        'unable to connect' not in lowered
        and 'failed to connect' not in lowered
        and 'cannot connect' not in lowered
    ):
        status = AdbConnection.STATUS_CONNECTED
    else:
        status = AdbConnection.STATUS_FAILED
    return status, combined or 'no output'


def _adb_devices_list():
    """Return the parsed device serials from ``adb devices``.

    Best-effort: returns a list of {'serial', 'state'} dicts, or [] on any
    failure. Never raises.
    """
    from mobsf.MobSF.utils import get_adb
    adb = get_adb()
    if not adb:
        return []
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, shell=False
            [adb, 'devices'],
            capture_output=True,
            timeout=ADB_TIMEOUT,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning('adb devices failed: %s', exc)
        return []
    devices = []
    out = (proc.stdout or b'').decode('utf-8', 'replace')
    for line in out.splitlines()[1:]:  # skip "List of devices attached"
        line = line.strip()
        if not line or '\t' not in line:
            continue
        serial, _, state = line.partition('\t')
        devices.append({'serial': serial.strip(), 'state': state.strip()})
    return devices


@login_required
@require_permission('settings.view')
def adb_connections_list(request):
    """List configured ADB connections, active one highlighted per platform."""
    connections = (
        AdbConnection.objects.select_related('created_by').all()
    )
    return render(request, 'rbac/adb_connections.html', {
        'title': 'Integrations · ADB Connections',
        'version': settings.MOBSF_VER,
        'connections': connections,
    })


@login_required
@require_permission('settings.manage')
@require_http_methods(['POST'])
def adb_connection_add(request):
    """Create a new ADB connection from POSTed label + host_port."""
    label = (request.POST.get('label', '') or '').strip()[:80]
    raw_host_port = request.POST.get('host_port', '')
    platform = (request.POST.get('platform', '') or '').strip().lower()
    if platform not in dict(AdbConnection.PLATFORM_CHOICES):
        platform = AdbConnection.PLATFORM_ANDROID

    host_port = _validate_host_port(raw_host_port)
    if not label:
        messages.error(request, 'A label is required.')
        return redirect('rbac:adb_connections')
    if not host_port:
        messages.error(
            request,
            'Invalid device address. Use host:port or [ipv6]:port '
            '(e.g. 192.168.1.100:5555).',
        )
        return redirect('rbac:adb_connections')
    if AdbConnection.objects.filter(host_port=host_port).exists():
        messages.error(
            request, f'A connection for "{host_port}" already exists.',
        )
        return redirect('rbac:adb_connections')

    conn = AdbConnection.objects.create(
        label=label,
        host_port=host_port,
        platform=platform,
        created_by=request.user,
    )
    # Best-effort initial connect so the row shows a real status immediately.
    status, message = _run_adb(['connect', conn.host_port])
    conn.last_status = status
    conn.last_status_message = message
    conn.last_status_at = timezone.now()
    conn.save(update_fields=[
        'last_status', 'last_status_message', 'last_status_at', 'updated_at',
    ])

    audit.record(
        request, 'integration.adb.add',
        target_type='adb_connection', target_id=conn.pk,
        metadata={
            'label': conn.label,
            'host_port': conn.host_port,
            'platform': conn.platform,
        },
    )
    messages.success(request, f'Connection "{conn.label}" added.')
    return redirect('rbac:adb_connections')


@login_required
@require_permission('settings.manage')
@require_http_methods(['POST'])
def adb_connection_remove(request, conn_id):
    """Disconnect and delete an ADB connection."""
    conn = get_object_or_404(AdbConnection, pk=conn_id)
    label = conn.label
    host_port = conn.host_port
    # Best-effort disconnect; ignore the result, we are tearing it down.
    _run_adb(['disconnect', host_port])
    conn.delete()
    audit.record(
        request, 'integration.adb.remove',
        target_type='adb_connection', target_id=conn_id,
        metadata={'label': label, 'host_port': host_port},
    )
    messages.success(request, f'Connection "{label}" removed.')
    return redirect('rbac:adb_connections')


@login_required
@require_permission('settings.manage')
@require_http_methods(['POST'])
def adb_connection_set_active(request, conn_id):
    """Make a connection the sole active one for its platform."""
    conn = get_object_or_404(AdbConnection, pk=conn_id)
    # set_active() atomically clears siblings of the same platform and sets
    # this row (select_for_update inside a transaction).
    conn.set_active()
    audit.record(
        request, 'integration.adb.set_active',
        target_type='adb_connection', target_id=conn.pk,
        metadata={
            'label': conn.label,
            'host_port': conn.host_port,
            'platform': conn.platform,
        },
    )
    messages.success(
        request, f'"{conn.label}" is now the active {conn.platform} device.',
    )
    return redirect('rbac:adb_connections')


@login_required
@require_permission('settings.manage')
@require_http_methods(['POST'])
def adb_connection_test(request, conn_id):
    """Run ``adb connect`` then ``adb devices`` and report status as JSON."""
    conn = get_object_or_404(AdbConnection, pk=conn_id)
    status, message = _run_adb(['connect', conn.host_port])
    conn.last_status = status
    conn.last_status_message = message
    conn.last_status_at = timezone.now()
    conn.save(update_fields=[
        'last_status', 'last_status_message', 'last_status_at', 'updated_at',
    ])

    devices = _adb_devices_list()
    audit.record(
        request, 'integration.adb.test',
        target_type='adb_connection', target_id=conn.pk,
        metadata={
            'host_port': conn.host_port,
            'result': (
                'success'
                if status == AdbConnection.STATUS_CONNECTED
                else 'failed'
            ),
            'message': message,
        },
    )
    return JsonResponse({
        'success': status == AdbConnection.STATUS_CONNECTED,
        'status': status,
        'message': message,
        'last_status_at': conn.last_status_at.isoformat(),
        'devices_list': devices,
    })
