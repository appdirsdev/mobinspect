"""Add the `admin.ai.view` permission for deployed databases.

The seed file (`0002_seed_permissions.py`) already lists this permission so
fresh installs receive it automatically. This migration is an idempotent
backfill for already-migrated databases. The AI Security Analysis section is
admin-only, so the permission is granted to the Administrator role only.
"""
from django.db import migrations


PERMISSION = (
    'admin.ai.view',
    'View AI analysis',
    'admin',
    'View the AI Security Analysis section',
    False,
)

ROLES_TO_GRANT = ('Administrator',)


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
    dependencies = [('rbac', '0009_adbconnection')]
    operations = [migrations.RunPython(add_permission, remove_permission)]
