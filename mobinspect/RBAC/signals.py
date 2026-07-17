"""
MobInspect — RBAC signal receivers.

Two responsibilities:

1. Keep the wrapped Django Group's display name in lockstep with the
   Role's name (so the legacy SAML group → Group machinery and any
   admin who looks at auth_group sees the same label).

2. **Mirror RoleAssignment → User.groups membership.** This is what
   makes the legacy `@permission_required('StaticAnalyzer.can_scan')`
   decorator continue to work for users granted access through the
   new RBAC UI. Without this signal, a user holding the "Security
   Analyst" role via mobinspect.RBAC.RoleAssignment would NOT have the
   underlying Django Group membership and would 403 on every legacy
   scan/finding endpoint.

   The mapping is intentionally one-way (RoleAssignment → groups).
   We do not reflect raw user.groups changes back into RoleAssignment
   to avoid loops and to keep MobInspect as the source of truth.
"""
from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out,
    user_login_failed,
)
from django.db.models.signals import (
    m2m_changed,
    post_delete,
    post_save,
)
from django.dispatch import receiver

from mobinspect.RBAC import audit
from mobinspect.RBAC.models import Role, RoleAssignment


# ─────────────────────────────────────────────── Role display name
@receiver(post_save, sender=Role)
def sync_group_name_on_role_save(sender, instance, created, **kwargs):
    """Keep the wrapped Group's name in lockstep with the Role's name."""
    grp = instance.group
    if grp.name != instance.name:
        grp.name = instance.name
        grp.save(update_fields=['name'])


# ─────────────────────────────────────── RoleAssignment → groups
@receiver(post_save, sender=RoleAssignment)
def add_user_to_group_on_assignment(sender, instance, created, **kwargs):
    """Add the user to the wrapped Group when a role is granted.

    Idempotent — Django's M2M `add()` is a no-op if already a member.
    """
    instance.user.groups.add(instance.role.group)


@receiver(post_delete, sender=RoleAssignment)
def remove_user_from_group_on_unassign(sender, instance, **kwargs):
    """Remove the user from the wrapped Group when a role is revoked.

    Only removes if the user has no OTHER active RoleAssignments that
    reference the same group (rare — would mean two roles wrapping the
    same Group, which the unique_together constraint already forbids).
    """
    user = instance.user
    role = instance.role
    still_assigned = RoleAssignment.objects.filter(
        user=user, role=role,
    ).exists()
    if not still_assigned:
        user.groups.remove(role.group)


# ─────────────────────────────────────── Role.permissions → Group.permissions
# Best-effort translation: when a MobInspect Role's permission set changes,
# add the matching auth.Permission rows to the wrapped Group so that
# `user.has_perm('StaticAnalyzer.can_scan')` continues to work for users
# assigned via the new UI.
#
# The codename mapping is conservative — only a curated set of MobInspect
# codenames have direct Django auth.Permission equivalents:
LEGACY_PERMISSION_MAP = {
    # MobInspect catalog → ('app_label', 'codename')
    'scan.create':         ('StaticAnalyzer', 'can_scan'),
    'finding.suppress':    ('StaticAnalyzer', 'can_suppress'),
    'finding.unsuppress':  ('StaticAnalyzer', 'can_suppress'),
    'scan.delete':         ('StaticAnalyzer', 'can_delete'),
}


@receiver(m2m_changed, sender=Role.permissions.through)
def sync_legacy_group_permissions(
    sender, instance, action, reverse, pk_set, **kwargs,
):
    """Mirror MobInspect codenames → legacy auth.Permission on the Group.

    Runs after add/remove/clear. Reads the Role's full codename set and
    sets the Group's auth.Permission membership to the matching legacy
    permissions. This keeps `permission_required('StaticAnalyzer.can_scan')`
    decorators working for users assigned to roles holding 'scan.create'.
    """
    if reverse:
        return
    if action not in {'post_add', 'post_remove', 'post_clear'}:
        return

    from django.contrib.auth.models import Permission as AuthPermission
    codenames = set(instance.codenames())
    legacy = []
    for code in codenames:
        mapping = LEGACY_PERMISSION_MAP.get(code)
        if mapping:
            # filter() (not get()): can_scan/can_delete are declared in
            # Meta.permissions of several StaticAnalyzer models, so each
            # codename resolves to multiple auth.Permission rows (one per
            # content type). get() would raise MultipleObjectsReturned and
            # 500 the role create/edit view. Holding any one row satisfies
            # user.has_perm('StaticAnalyzer.can_scan').
            legacy.extend(AuthPermission.objects.filter(
                content_type__app_label=mapping[0],
                codename=mapping[1],
            ))
    instance.group.permissions.set(legacy)


# ─────────────────────────────────────────────── auth events (audit)
# Hook Django's built-in auth signals into the MobInspect audit log so
# every successful login, logout, and failed login attempt is recorded
# with the same shape as RBAC and admin actions. Anonymous events
# (failed logins — no actor) go through audit.record_anon so the actor
# column is intentionally NULL and the presented username is captured
# in metadata for correlation.
@receiver(user_logged_in)
def audit_user_logged_in(sender, request, user, **kwargs):
    """Record a successful authentication."""
    audit.record(
        request,
        'auth.login.ok',
        target_type='user',
        target_id=getattr(user, 'id', '') or '',
        metadata={'username': getattr(user, 'username', '')},
        actor=user,
    )


@receiver(user_logged_out)
def audit_user_logged_out(sender, request, user, **kwargs):
    """Record a logout. user may be None if the session was already gone."""
    audit.record(
        request,
        'auth.logout',
        target_type='user' if user is not None else '',
        target_id=getattr(user, 'id', '') or '',
        metadata={'username': getattr(user, 'username', '') if user else ''},
        actor=user,
    )


@receiver(user_login_failed)
def audit_user_login_failed(sender, credentials, request=None, **kwargs):
    """Record a failed login attempt.

    No actor is attached — we cannot trust the presented username to
    correspond to a real user. The username (if any) is stored in
    metadata for correlation. Passwords are NEVER stored.
    """
    username = ''
    if credentials:
        username = credentials.get('username') or ''
    audit.record_anon(
        request,
        'auth.login.fail',
        metadata={'username': username},
    )
