"""Seed the MobInspect permission catalog.

The catalog is the authoritative list of permissions checkable in the
product. Adding a new permission means: add a row here, then reference
it in a `@require_permission` decorator on the new view.

Removing one means: data migration that detaches it from any roles, then
removes the row.
"""
from django.db import migrations


# (codename, name, category, description, dangerous)
PERMISSIONS = [
    # ── scan
    ('scan.create',        'Create scans',         'scan', 'Upload binaries and start static/dynamic scans', False),
    ('scan.view',          'View any scan',        'scan', 'View any scan and its report',                   False),
    ('scan.view_own',      'View own scans only',  'scan', 'View only scans I uploaded',                     False),
    ('scan.delete',        'Delete scans',         'scan', 'Delete scans',                                   True),
    ('scan.rescan',        'Re-scan',              'scan', 'Re-run analysis on an existing scan',            False),
    ('scan.export.pdf',    'Export PDF',           'scan', 'Download PDF reports',                           False),
    ('scan.export.json',   'Export JSON',          'scan', 'Download JSON reports',                          False),

    # ── finding
    ('finding.suppress',   'Suppress findings',    'finding', 'Mark findings as suppressed',          False),
    ('finding.unsuppress', 'Reverse suppression',  'finding', 'Reverse a finding suppression',        False),
    ('finding.comment',    'Comment on findings',  'finding', 'Add comments to findings',             False),

    # ── dynamic
    ('dynamic.android.run',  'Android dynamic',    'dynamic', 'Run Android dynamic analysis',        False),
    ('dynamic.ios.run',      'iOS dynamic',        'dynamic', 'Run iOS dynamic analysis',            False),
    ('dynamic.frida.script', 'Custom Frida scripts','dynamic', 'Upload custom Frida scripts',         True),
    ('dynamic.adb.shell',    'ADB/SSH shell pass-through','dynamic','Run ADB or iOS SSH commands from the allowlist',True),

    # ── integration
    ('integration.virustotal.use',    'Use VirusTotal',    'integration', 'Submit hashes to VirusTotal',         False),
    ('integration.virustotal.upload', 'Upload to VirusTotal','integration','Upload binaries to VirusTotal',       True),
    ('integration.malware.lookup',    'Malware DB lookup', 'integration', 'Use external malware DBs',           False),

    # ── api
    ('api.use',                  'Use REST API',           'api', 'Use REST API at all',                          False),
    ('api.key.create',           'Create own API key',     'api', 'Create new API keys for self',                 False),
    ('api.key.create_for_others','Create others\' API keys','api', 'Create keys on behalf of other users',         True),

    # ── analytics
    ('analytics.view',   'View analytics',  'analytics', 'See the analytics dashboard',                False),
    ('analytics.export', 'Export analytics','analytics', 'Export analytics data',                      False),

    # ── admin / users
    ('admin.user.view',           'View users',         'admin', 'List users',                          False),
    ('admin.user.create',         'Create users',       'admin', 'Create new users',                    True),
    ('admin.user.delete',         'Delete users',       'admin', 'Delete users',                        True),
    ('admin.user.reset_password', 'Reset passwords',    'admin', 'Reset another user\'s password',      True),

    # ── rbac
    ('rbac.role.view',   'View roles',   'rbac', 'List roles and their permissions',          False),
    ('rbac.role.manage', 'Manage roles', 'rbac', 'Create, edit, delete roles & assignments',  True),

    # ── settings
    ('settings.view',    'View settings',   'settings', 'View global settings',     False),
    ('settings.manage',  'Manage settings', 'settings', 'Modify global settings',   True),

    # ── audit
    ('audit.view',       'View audit log', 'audit', 'View the audit log',           False),
]


def seed(apps, schema_editor):
    Permission = apps.get_model('rbac', 'Permission')
    for codename, name, category, description, dangerous in PERMISSIONS:
        Permission.objects.update_or_create(
            codename=codename,
            defaults={
                'name': name,
                'category': category,
                'description': description,
                'is_dangerous': dangerous,
                'scope': 'action',
            },
        )


def unseed(apps, schema_editor):
    Permission = apps.get_model('rbac', 'Permission')
    Permission.objects.filter(
        codename__in=[p[0] for p in PERMISSIONS],
    ).delete()


class Migration(migrations.Migration):
    dependencies = [('rbac', '0001_initial')]
    operations = [migrations.RunPython(seed, unseed)]
