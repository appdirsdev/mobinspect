"""Real-execution coverage tests for the audit_verify management command
(mobinspect/RBAC/management/commands/audit_verify.py).

STRICT: no mocks. Drives the real management command via
django.core.management.call_command against real AuditEvent rows in the
Postgres test DB.

"Tamper" scenarios insert rows with deliberately wrong stored hash-chain
columns by calling the base ``django.db.models.Model.save()`` directly on
an AuditEvent instance — this bypasses only AuditEvent.save()'s own hash
computation (a Python method override), while still performing a genuine
ORM INSERT against the real database. INSERT is used (never UPDATE/DELETE)
because the append-only trigger installed by migration 0007 blocks
mutation of an already-committed row on Postgres; it does not block a
fresh INSERT, so this is the real, DB-level way to seed a "corrupted"
chain for audit_verify to detect (exactly the scenario the command exists
to catch: a chain member whose stored hash disagrees with what recomputing
it would produce).
"""
import io

import pytest

from django.core.management import call_command
from django.db import models as django_models
from django.utils import timezone

from mobinspect.RBAC.models import AuditEvent


pytestmark = pytest.mark.django_db


def _create(action, actor=None, target_type='', target_id='', metadata=None):
    """A normal, real, hash-chained AuditEvent via the model's own save()."""
    return AuditEvent.objects.create(
        actor=actor, action=action, target_type=target_type,
        target_id=target_id, metadata=metadata or {},
    )


def _insert_raw(prev_hash, current_hash, action='cov.tamper', occurred_at=None):
    """Insert an AuditEvent with EXACT, caller-chosen prev/current hash
    values, bypassing AuditEvent.save()'s hash computation (only that
    Python override is skipped -- this is still a genuine ORM INSERT
    against the real Postgres test DB).
    """
    evt = AuditEvent(
        actor=None, action=action, target_type='', target_id='',
        metadata={}, occurred_at=occurred_at or timezone.now(),
    )
    evt.prev_hash = prev_hash
    evt.current_hash = current_hash
    django_models.Model.save(evt, force_insert=True)
    return evt


def _call(**opts):
    out, err = io.StringIO(), io.StringIO()
    call_command('audit_verify', stdout=out, stderr=err, **opts)
    return out.getvalue(), err.getvalue()


# ─────────────────────────────────────────────────────── empty chain
def test_empty_without_allow_empty_exits_2():
    with pytest.raises(SystemExit) as exc:
        call_command('audit_verify', stdout=io.StringIO(), stderr=io.StringIO())
    assert exc.value.code == 2


def test_empty_with_allow_empty_succeeds():
    out, _err = _call(allow_empty=True)
    assert 'allowed' in out


def test_empty_with_limit_and_allow_empty():
    # Exercises the limit>0 offset/window computation with zero rows in
    # the table (offset = max(0-limit, 0) == 0 -> window is empty).
    out, _err = _call(allow_empty=True, limit=10)
    assert 'allowed' in out


def test_empty_with_limit_without_allow_empty_still_exits_2():
    with pytest.raises(SystemExit) as exc:
        call_command(
            'audit_verify', limit=5,
            stdout=io.StringIO(), stderr=io.StringIO())
    assert exc.value.code == 2


# ─────────────────────────────────────────────────────── verify-ok
def test_full_chain_verifies_ok():
    for i in range(5):
        _create(f'cov.ok.{i}')
    out, err = _call()
    assert 'audit_verify: 5 rows OK.' in out
    assert err == ''


def test_full_chain_quiet_still_reports_summary():
    for i in range(3):
        _create(f'cov.ok.quiet.{i}')
    out, _err = _call(quiet=True)
    assert 'audit_verify: 3 rows OK.' in out


def test_limit_zero_walks_whole_chain():
    for i in range(4):
        _create(f'cov.limitzero.{i}')
    out, _err = _call(limit=0)
    assert 'audit_verify: 4 rows OK.' in out


def test_limit_greater_equal_total_offset_zero_branch():
    # limit >= total row count -> offset collapses to 0, seed_hash='' path.
    for i in range(3):
        _create(f'cov.limitbig.{i}')
    out, _err = _call(limit=10)
    assert 'audit_verify: 3 rows OK.' in out


def test_limit_smaller_than_total_offset_branch():
    # limit < total -> offset>0, seeds expected prev_hash from the row
    # immediately BEFORE the window.
    for i in range(6):
        _create(f'cov.limitwindow.{i}')
    out, _err = _call(limit=2)
    assert 'audit_verify: 2 rows OK.' in out


# ─────────────────────────────────────────────────────── tamper detection
def test_tamper_current_hash_mismatch_only():
    _create('cov.tamperc.a')
    prior = AuditEvent.objects.order_by('-id').first()
    real_prev = prior.current_hash
    # prev_hash correct (matches the real chain); current_hash is garbage.
    _insert_raw(prev_hash=real_prev, current_hash='0' * 64,
                action='cov.tamperc.bad')
    _create('cov.tamperc.after')  # chain continues off the bad STORED hash
    out, err = io.StringIO(), io.StringIO()
    with pytest.raises(SystemExit) as exc:
        call_command('audit_verify', stdout=out, stderr=err)
    assert exc.value.code == 1
    assert 'current_hash mismatch' in out.getvalue()
    assert 'prev_hash mismatch' not in out.getvalue()
    assert 'audit_verify: 1 of 3 rows failed integrity check.' in err.getvalue()


def test_tamper_prev_hash_mismatch_only():
    _create('cov.tamperp.a')
    prior = AuditEvent.objects.order_by('-id').first()
    bad_prev = 'f' * 64  # does NOT match the real chain's expected prev_hash
    occurred_at = timezone.now()
    # current_hash IS internally consistent with (the wrong) bad_prev, so
    # recompute-from-the-REAL-expected-prev is what disagrees -> isolates
    # a prev_hash-only mismatch (current_hash still "matches" its own
    # payload once the real accumulator is substituted in -- no, the
    # recompute always uses the walking accumulator, so this deliberately
    # produces ONLY the prev_hash issue by keeping current_hash equal to
    # compute_hash(real_expected_prev, ...) instead).
    real_prev = prior.current_hash
    consistent_current = AuditEvent._compute_hash(
        real_prev, None, 'cov.tamperp.bad', '', '', {}, occurred_at)
    _insert_raw(prev_hash=bad_prev, current_hash=consistent_current,
                action='cov.tamperp.bad', occurred_at=occurred_at)
    out, err = io.StringIO(), io.StringIO()
    with pytest.raises(SystemExit) as exc:
        call_command('audit_verify', stdout=out, stderr=err)
    assert exc.value.code == 1
    assert 'prev_hash mismatch' in out.getvalue()
    assert 'current_hash mismatch' not in out.getvalue()


def test_tamper_both_prev_and_current_mismatch():
    _create('cov.tamperb.a')
    # Both prev_hash and current_hash are pure garbage -> both issues fire
    # for the same row, joined with '; ' in the per-row message.
    _insert_raw(prev_hash='a' * 64, current_hash='b' * 64,
                action='cov.tamperb.bad')
    out, err = io.StringIO(), io.StringIO()
    with pytest.raises(SystemExit) as exc:
        call_command('audit_verify', stdout=out, stderr=err)
    assert exc.value.code == 1
    line = next(l for l in out.getvalue().splitlines() if 'cov.tamperb.bad' in l)
    assert 'prev_hash mismatch' in line
    assert 'current_hash mismatch' in line
    assert '; ' in line


def test_tamper_quiet_suppresses_per_row_print():
    _create('cov.tamperq.a')
    prior = AuditEvent.objects.order_by('-id').first()
    _insert_raw(prev_hash=prior.current_hash, current_hash='1' * 64,
                action='cov.tamperq.bad')
    out, err = io.StringIO(), io.StringIO()
    with pytest.raises(SystemExit) as exc:
        call_command('audit_verify', quiet=True, stdout=out, stderr=err)
    assert exc.value.code == 1
    assert out.getvalue() == ''  # per-row line suppressed by --quiet
    assert 'audit_verify: 1 of 2 rows failed integrity check.' in err.getvalue()


def test_self_healing_after_corrupt_row_does_not_cascade():
    """A single corrupted row must not flag every subsequent row: the
    walk always advances prev_hash off the STORED current_hash, so rows
    created after the bad one (which correctly chain off its stored,
    if-wrong, hash) still verify clean."""
    _create('cov.heal.a')
    prior = AuditEvent.objects.order_by('-id').first()
    _insert_raw(prev_hash=prior.current_hash, current_hash='2' * 64,
                action='cov.heal.bad')
    _create('cov.heal.after1')
    _create('cov.heal.after2')
    out, err = io.StringIO(), io.StringIO()
    with pytest.raises(SystemExit) as exc:
        call_command('audit_verify', stdout=out, stderr=err)
    assert exc.value.code == 1
    assert 'audit_verify: 1 of 4 rows failed integrity check.' in err.getvalue()


def test_tamper_row_outside_limit_window_not_flagged():
    """A corrupted row that falls OUTSIDE the requested --limit window is
    not walked at all, so a scoped run reports clean even though the full
    chain is not."""
    _create('cov.limittamper.a')
    prior = AuditEvent.objects.order_by('-id').first()
    _insert_raw(prev_hash=prior.current_hash, current_hash='3' * 64,
                action='cov.limittamper.bad')
    _create('cov.limittamper.after1')
    _create('cov.limittamper.after2')
    # Only the last 2 rows (both real, chained off the bad row's stored
    # hash) are in-window -> clean.
    out, _err = _call(limit=2)
    assert 'audit_verify: 2 rows OK.' in out
    # But the unscoped, whole-chain run still finds the corruption.
    out2, err2 = io.StringIO(), io.StringIO()
    with pytest.raises(SystemExit) as exc:
        call_command('audit_verify', stdout=out2, stderr=err2)
    assert exc.value.code == 1


# ─────────────────────────────────────────────────────── argument handling
def test_invalid_limit_type_raises():
    """--limit is declared type=int; a non-numeric value fails argument
    parsing rather than silently falling through to handle()."""
    with pytest.raises(Exception):
        call_command(
            'audit_verify', '--limit=not-a-number',
            stdout=io.StringIO(), stderr=io.StringIO())
