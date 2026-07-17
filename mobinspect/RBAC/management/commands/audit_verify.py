"""Verify the AuditEvent hash chain (H9).

Walks ``rbac_auditevent`` in insertion order and recomputes each row's
``current_hash``. Any mismatch — wrong ``prev_hash``, recomputed hash that
disagrees with the stored value, or a missing predecessor — is reported
to stdout and yields a non-zero exit code so the command is usable from
cron / systemd timer health checks.

Examples:

    poetry run python manage.py audit_verify
    poetry run python manage.py audit_verify --limit 1000 --quiet

Exit codes:
    0  chain intact (and at least one row checked, or --allow-empty)
    1  one or more mismatches detected
    2  chain is empty AND --allow-empty was not passed
"""
import sys

from django.core.management.base import BaseCommand

from mobinspect.RBAC.models import AuditEvent


class Command(BaseCommand):
    help = 'Verify the integrity of the AuditEvent hash chain.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--limit',
            type=int,
            default=0,
            help=(
                'Only verify the N most-recent rows (still walks them in '
                'chronological order). 0 = walk the whole chain.'
            ),
        )
        parser.add_argument(
            '--quiet',
            action='store_true',
            help='Suppress the per-row progress line; print only summary.',
        )
        parser.add_argument(
            '--allow-empty',
            action='store_true',
            help=(
                'Treat an empty AuditEvent table as success (exit 0). '
                'Without this flag an empty chain returns exit 2 so a '
                'misconfigured cron job is noisy rather than silent.'
            ),
        )

    def handle(self, *args, **opts):
        limit = opts['limit']
        quiet = opts['quiet']
        allow_empty = opts['allow_empty']

        qs = AuditEvent.objects.order_by('id').only(
            'id', 'actor_id', 'action', 'target_type', 'target_id',
            'metadata', 'occurred_at', 'prev_hash', 'current_hash',
        )
        if limit > 0:
            # Anchor on the last N rows but still process them in order.
            # We need the row immediately BEFORE the window to seed the
            # expected prev_hash.
            total = qs.count()
            offset = max(total - limit, 0)
            window = list(qs[offset:offset + limit])
            if offset > 0:
                seed = qs[offset - 1: offset].first()
                seed_hash = seed.current_hash if seed else ''
            else:
                seed_hash = ''
            iterator = iter(window)
            walked_total = len(window)
        else:
            iterator = qs.iterator()
            seed_hash = ''
            walked_total = qs.count()

        if walked_total == 0:
            msg = 'AuditEvent table is empty.'
            if allow_empty:
                self.stdout.write(self.style.SUCCESS(msg + ' (allowed)'))
                return
            self.stderr.write(self.style.WARNING(msg))
            sys.exit(2)

        prev_hash = seed_hash
        mismatches = []
        checked = 0

        for evt in iterator:
            checked += 1
            issues = []
            if evt.prev_hash != prev_hash:
                issues.append(
                    f'prev_hash mismatch: stored={evt.prev_hash!r} '
                    f'expected={prev_hash!r}',
                )
            recomputed = AuditEvent._compute_hash(
                prev_hash,
                evt.actor_id,
                evt.action,
                evt.target_type,
                evt.target_id,
                evt.metadata,
                evt.occurred_at,
            )
            if recomputed != evt.current_hash:
                issues.append(
                    f'current_hash mismatch: stored={evt.current_hash!r} '
                    f'recomputed={recomputed!r}',
                )
            if issues:
                mismatches.append((evt.id, issues))
                if not quiet:
                    self.stdout.write(self.style.ERROR(
                        f'  [#{evt.id}] {evt.action} — '
                        + '; '.join(issues),
                    ))
            # Always advance the chain off the row's STORED current_hash
            # so a single bad row does not cascade and flag every
            # subsequent row as broken.
            prev_hash = evt.current_hash

        if mismatches:
            self.stderr.write(self.style.ERROR(
                f'audit_verify: {len(mismatches)} of {checked} rows '
                'failed integrity check.',
            ))
            sys.exit(1)

        self.stdout.write(self.style.SUCCESS(
            f'audit_verify: {checked} rows OK.',
        ))
