"""
Idempotent re-seed of the RBAC catalog and default roles.

Useful when adding a new permission to the catalog without writing a
data migration (development), or to recover from a corrupted seed.
"""
from importlib import import_module

from django.apps import apps as django_apps
from django.core.management.base import BaseCommand
from django.db import transaction


class _AppsShim:
    """Provides the .get_model() interface that migration helpers expect."""
    @staticmethod
    def get_model(app_label, model_name):
        return django_apps.get_model(app_label, model_name)


class Command(BaseCommand):
    help = 'Re-seed RBAC permissions and default roles (idempotent).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Drop and re-create the four system roles (preserves users).',
        )

    @transaction.atomic
    def handle(self, *args, **opts):
        # Module names with leading digits can't be imported via dotted syntax,
        # so use importlib for both to keep the call sites uniform.
        seed_perms = import_module(
            'mobsf.RBAC.migrations.0002_seed_permissions',
        )
        seed_roles = import_module(
            'mobsf.RBAC.migrations.0003_seed_default_roles',
        )

        if opts['reset']:
            from mobsf.RBAC.models import Role
            Role.objects.filter(is_system=True).delete()
            self.stdout.write(self.style.WARNING(
                'Deleted existing system roles.',
            ))

        seed_perms.seed(_AppsShim, None)
        self.stdout.write(self.style.SUCCESS('Seeded permission catalog.'))

        seed_roles.seed(_AppsShim, None)
        self.stdout.write(self.style.SUCCESS('Seeded default system roles.'))
