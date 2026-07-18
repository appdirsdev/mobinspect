"""
MobInspect — audit log helpers.

Use record() at the call sites of consequential actions (role grants,
role edits, permission denials, key creation, etc.).
"""
import logging

from django.db import transaction

from mobinspect.RBAC.models import AuditEvent

logger = logging.getLogger('mobinspect.MobInspect')


def record(
    request, action,
    target_type='', target_id='', metadata=None, actor=None,
):
    """Record an audit event. Best-effort — never raises.

    The create() runs inside its own ``transaction.atomic()`` savepoint.
    Without it, a real DB error raised by create() while THIS call is
    nested inside a caller's already-open ``atomic()`` block would still
    be swallowed by the except below, but would leave the connection's
    ``needs_rollback`` flag set — poisoning the caller's outer
    transaction so its very next query raises
    ``TransactionManagementError``, even though no Python exception ever
    escaped this function. The nested atomic() gives Django a savepoint
    boundary to roll back to on exit, clearing the flag and containing
    the damage to this call alone.
    """
    try:
        with transaction.atomic():
            AuditEvent.objects.create(
                actor=actor or _request_user(request),
                action=action,
                target_type=target_type or '',
                target_id=str(target_id or '')[:80],
                metadata=metadata or {},
                ip_address=_client_ip(request),
                user_agent=(_header(request, 'User-Agent') or '')[:400],
            )
    except Exception as e:  # noqa: BLE001
        # Never let audit failure break the request.
        logger.warning('audit event %r failed: %s', action, e)


def record_anon(
    request, action,
    target_type='', target_id='', metadata=None,
):
    """Record an audit event for an UNAUTHENTICATED actor.

    Use this for events where there is no authenticated user attached to
    the request (failed logins, failed API key auth attempts). The actor
    column is intentionally left NULL — the metadata payload carries the
    presented identifier (username prefix, key prefix, etc.) so operators
    can correlate without false-attributing the event to whoever happens
    to hold the session.

    Best-effort — never raises. See record()'s docstring for why the
    create() is wrapped in its own transaction.atomic() savepoint.
    """
    try:
        with transaction.atomic():
            AuditEvent.objects.create(
                actor=None,
                action=action,
                target_type=target_type or '',
                target_id=str(target_id or '')[:80],
                metadata=metadata or {},
                ip_address=_client_ip(request),
                user_agent=(_header(request, 'User-Agent') or '')[:400],
            )
    except Exception as e:  # noqa: BLE001
        # Never let audit failure break the request.
        logger.warning('anon audit event %r failed: %s', action, e)


def _request_user(request):
    if request is None:
        return None
    # Prefer the API-key owner (api_user) over the session user so that
    # actions performed via an API key are attributed to the key's owner,
    # not to whoever happens to hold an open browser session.
    api_user = getattr(request, 'api_user', None)
    if api_user is not None and getattr(api_user, 'is_authenticated', False):
        return api_user
    user = getattr(request, 'user', None)
    if user is not None and getattr(user, 'is_authenticated', False):
        return user
    return None


def _client_ip(request):
    if request is None:
        return None
    fwd = _header(request, 'X-Forwarded-For')
    if fwd:
        # First entry is the client; the rest are upstream proxies.
        return fwd.split(',')[0].strip()
    return getattr(request, 'META', {}).get('REMOTE_ADDR')


def _header(request, name):
    if request is None:
        return ''
    meta = getattr(request, 'META', {}) or {}
    key = 'HTTP_' + name.upper().replace('-', '_')
    return meta.get(key, '') or meta.get(name, '')
