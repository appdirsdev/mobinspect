"""Add the `dynamic.adb.shell` permission for deployed databases.

The seed file (`0002_seed_permissions.py`) already lists this permission so
fresh installs receive it automatically. This migration is a no-op there and
an idempotent backfill for already-migrated production DBs. It also grants
the permission to the existing Security Analyst and Administrator system
roles so the audit-log of role memberships matches the seed catalog.
"""
from django.db import migrations


PERMISSION = (
    'dynamic.adb.shell',
    'ADB/SSH shell pass-through',
    'dynamic',
    'Run ADB or iOS SSH commands from the allowlist',
    True,
)

ROLES_TO_GRANT = ('Administrator', 'Security Analyst')


def add_permission(apps, schema_editor):
    Permission = apps.get_model('rbac', 'Permission')
    Role = apps.get_model('rbac', 'Role')

    codename, name, category, description, dangerous = PERMISSION
    perm, _ = Permission.objects.update_or_create(
        codename=codename,
        defaults={
            'name': name,
            'category': category,
            'description': description,
            'is_dangerous': dangerous,
            'scope': 'action',
        },
    )

    for role_name in ROLES_TO_GRANT:
        try:
            role = Role.objects.get(name=role_name)
        except Role.DoesNotExist:
            continue
        role.permissions.add(perm)


def remove_permission(apps, schema_editor):
    Permission = apps.get_model('rbac', 'Permission')
    Permission.objects.filter(codename=PERMISSION[0]).delete()


class Migration(migrations.Migration):
    dependencies = [('rbac', '0004_migrate_existing_users')]
    operations = [migrations.RunPython(add_permission, remove_permission)]
