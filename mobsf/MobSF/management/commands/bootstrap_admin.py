"""Idempotent first-boot admin bootstrap.

Wraps ``mobsf.MobSF.init.bootstrap_admin`` so deploy scripts (entrypoint,
setup.sh, systemd ExecStartPre, …) can call it without ever falling back
to the legacy ``createsuperuser --noinput`` flow that seeded the
``mobsf/mobsf`` superuser.

The command is *safe to re-run*: if any superuser already exists it exits
0 silently. Otherwise it reads ``MOBINSPECT_ADMIN_USERNAME`` /
``MOBINSPECT_ADMIN_PASSWORD`` from the environment, prompts interactively
on a TTY, or generates a 24-char ``secrets.token_urlsafe`` and writes it
to ``<MOBSF_HOME>/initial-admin-password.txt`` (mode 0600).
"""
from django.core.management.base import BaseCommand

from mobsf.MobSF.init import bootstrap_admin


class Command(BaseCommand):
    help = (  # noqa: A003
        'Create the initial MobInspect superuser if none exists. '
        'Idempotent: exits 0 silently when a superuser already exists.')

    def handle(self, *args, **options):
        created = bootstrap_admin()
        if created:
            self.stdout.write(self.style.SUCCESS(
                'Initial admin user created.'))
        # When a superuser already exists bootstrap_admin returns False and
        # logs at INFO; we stay silent on stdout so the command is quiet
        # on the steady-state boot path.
