"""Backfill existing users to the new role system.

Mapping rules:
  - is_staff=True OR is_superuser=True  →  Administrator
  - existing 'Maintainer' Django Group  →  Security Analyst (preserve membership)
  - existing 'Viewer'     Django Group  →  Viewer
  - everyone else                       →  Viewer (safe default — read-only)

Idempotent: re-running the migration produces no duplicate assignments.
"""
from django.db import migrations


# (legacy_group_name, target_role_name)
GROUP_REMAP = [
    ('Maintainer', 'Security Analyst'),
    ('Viewer', 'Viewer'),
]


def backfill(apps, schema_editor):
    User = apps.get_model('auth', 'User')
    Role = apps.get_model('rbac', 'Role')
    RoleAssignment = apps.get_model('rbac', 'RoleAssignment')

    # Cache role lookups
    try:
        admin_role   = Role.objects.get(name='Administrator')
        analyst_role = Role.objects.get(name='Security Analyst')
        viewer_role  = Role.objects.get(name='Viewer')
    except Role.DoesNotExist:
        # Default roles weren't seeded yet — nothing to backfill against.
        return

    role_by_name = {
        'Administrator':    admin_role,
        'Security Analyst': analyst_role,
        'Viewer':           viewer_role,
    }

    for user in User.objects.all():
        roles_to_assign = set()

        # 1. Staff / superuser → Administrator
        if user.is_staff or user.is_superuser:
            roles_to_assign.add(admin_role)

        # 2. Legacy group remap
        legacy_groups = set(user.groups.values_list('name', flat=True))
        for legacy, target in GROUP_REMAP:
            if legacy in legacy_groups:
                target_role = role_by_name.get(target)
                if target_role is not None:
                    roles_to_assign.add(target_role)

        # 3. Default fallback — read-only Viewer
        if not roles_to_assign:
            roles_to_assign.add(viewer_role)

        for role in roles_to_assign:
            RoleAssignment.objects.get_or_create(
                user=user, role=role,
            )


def reverse(apps, schema_editor):
    # Non-destructive — leave any assignments in place.
    pass


class Migration(migrations.Migration):
    dependencies = [('rbac', '0003_seed_default_roles')]
    operations = [migrations.RunPython(backfill, reverse)]
