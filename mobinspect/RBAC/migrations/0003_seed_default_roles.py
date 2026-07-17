"""Seed the four default system roles.

System roles cannot be deleted or renamed via the UI. Their permission
sets remain editable so admins can tighten or loosen them over time.
"""
from django.db import migrations


# (name, color, icon, description, [permission codenames])
DEFAULT_ROLES = [
    (
        'Administrator', '#8D5CFC', 'shield-alert',
        'Full access to all features, including user and role management.',
        '*',  # special marker — all permissions
    ),
    (
        'Security Analyst', '#2563EB', 'shield-check',
        'Run scans, triage findings, suppress, view analytics, use API.',
        [
            'scan.create', 'scan.view', 'scan.delete', 'scan.rescan',
            'scan.export.pdf', 'scan.export.json',
            'finding.suppress', 'finding.unsuppress', 'finding.comment',
            'dynamic.android.run', 'dynamic.ios.run', 'dynamic.frida.script',
            'dynamic.adb.shell',
            'integration.virustotal.use', 'integration.malware.lookup',
            'analytics.view', 'analytics.export',
            'api.use', 'api.key.create',
        ],
    ),
    (
        'Viewer', '#64748B', 'eye',
        'Read-only access to scans, reports, and analytics.',
        [
            'scan.view', 'scan.export.pdf', 'scan.export.json',
            'analytics.view',
        ],
    ),
    (
        'API User', '#FE4A23', 'key',
        'Programmatic-only role for CI/CD pipelines.',
        [
            'api.use', 'scan.create', 'scan.view',
            'scan.export.json', 'finding.suppress',
        ],
    ),
]


def seed(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Role = apps.get_model('rbac', 'Role')
    Permission = apps.get_model('rbac', 'Permission')

    all_perms = list(Permission.objects.all())

    for name, color, icon, description, perm_list in DEFAULT_ROLES:
        group, _ = Group.objects.get_or_create(name=name)
        role, _ = Role.objects.update_or_create(
            group=group,
            defaults={
                'name': name,
                'description': description,
                'color': color,
                'icon': icon,
                'is_system': True,
            },
        )
        if perm_list == '*':
            role.permissions.set(all_perms)
        else:
            role.permissions.set(
                Permission.objects.filter(codename__in=perm_list),
            )


def unseed(apps, schema_editor):
    Role = apps.get_model('rbac', 'Role')
    Role.objects.filter(
        name__in=[r[0] for r in DEFAULT_ROLES],
    ).delete()


class Migration(migrations.Migration):
    dependencies = [('rbac', '0002_seed_permissions')]
    operations = [migrations.RunPython(seed, unseed)]
