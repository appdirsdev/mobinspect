"""
MobInspect — audit log helpers.

Use record() at the call sites of consequential actions (role grants,
role edits, permission denials, key creation, etc.).
"""
import logging

from mobsf.RBAC.models import AuditEvent

logger = logging.getLogger('mobsf.MobSF')


def record(
    request, action,
    target_type='', target_id='', metadata=None, actor=None,
):
    """Record an audit event. Best-effort — never raises."""
    try:
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

    Best-effort — never raises.
    """
    try:
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
    user = getattr(request, 'user', None)
    if user is not None and user.is_authenticated:
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
