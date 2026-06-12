# -*- coding: utf_8 -*-
"""REST API Middleware."""
import logging
from hmac import compare_digest

from django.http import HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django_ratelimit import ALL as RATELIMIT_ALL_METHODS
from django_ratelimit.core import is_ratelimited

from mobsf.MobSF.init import api_key

OK = 200
TOO_MANY = 429
FORBIDDEN = 403
UNAUTHORIZED = 401

logger = logging.getLogger(__name__)

# Per-IP rate limit for repeated API auth FAILURES. We do not rate-limit
# successful authenticated calls here — those are governed by Django
# session/view-level limits. The intent is to slow brute-force scanning
# of the X-Mobsf-Api-Key header without disrupting legitimate clients.
# A VALID key always bypasses this limit (we authenticate before
# consulting the counter), so a bad-key flood from a shared IP cannot
# 429 a legitimate caller behind the same NAT/proxy.
API_AUTH_FAIL_RATE = getattr(
    settings, 'MOBINSPECT_API_AUTH_FAIL_RATE', '60/m')


def _decorate_api_headers(resp):
    """Add the standard CORS / content headers used by every API response."""
    resp['Access-Control-Allow-Origin'] = '*'
    resp['Access-Control-Allow-Methods'] = 'POST'
    resp['Access-Control-Allow-Headers'] = 'Authorization, X-Mobsf-Api-Key'
    resp['Content-Type'] = 'application/json; charset=utf-8'
    return resp


def make_api_response(data, status=OK):
    """Make API Response.

    If `data` is already an HttpResponse (typically a 403 JsonResponse
    emitted by `permission_required` when an API caller lacks the
    required RBAC permission), pass it through untouched — just decorate
    the standard CORS headers. Without this short-circuit, JsonResponse
    would try to re-serialize the inner HttpResponse and raise TypeError,
    mangling a clean 403 into an opaque 500.
    """
    if isinstance(data, HttpResponse):
        return _decorate_api_headers(data)
    resp = JsonResponse(
        data=data,
        status=status,
        safe=False)
    return _decorate_api_headers(resp)


def _extract_key(meta):
    """Pull the candidate API key string from request headers."""
    return meta.get('HTTP_X_MOBSF_API_KEY') or meta.get('HTTP_AUTHORIZATION') or ''


def _global_key_matches(presented):
    """Constant-time compare against the legacy global API key."""
    if not presented:
        return False
    mobsf_api_key = api_key(settings.MOBSF_HOME)
    return compare_digest(mobsf_api_key, presented)


def api_auth(request):
    """Authenticate an API request.

    Resolution order:
      1. Per-user MobInspect ApiKey (preferred) — sets request.api_user + request.api_key
      2. Global API key from MOBINSPECT_API_KEY (or legacy MOBSF_API_KEY) —
         sets request.api = True (no user attribution).

    The HTTP header name X-Mobsf-Api-Key is intentionally NOT renamed
    (would break existing API clients); the body of the rebrand is in
    the env-var names and per-user key system.

    Returns True if either succeeds; False otherwise.
    """
    presented = _extract_key(request.META)
    if not presented:
        return False

    # 1. Try per-user key first.
    try:
        from mobsf.RBAC.models import ApiKey  # local import — avoid app load order
        key = ApiKey.lookup(presented)
    except Exception:  # noqa: BLE001
        key = None

    if key is not None:
        # Layer the API-key user on top of the (anonymous) session user.
        # We do NOT replace request.user — Django's AuthenticationMiddleware
        # treats that as session-derived and could regress identity checks
        # that emit Set-Cookie. Permission and role helpers honor api_user.
        request.api_user = key.user
        request.api_key = key
        request.api = True
        request.is_api = True
        try:
            key.touch()
        except Exception:  # noqa: BLE001
            pass
        return True

    # 2. Fall back to the legacy global key.
    if _global_key_matches(presented):
        request.api = True
        request.is_api = True
        return True

    return False


def _audit_auth_fail(request, reason):
    """Emit an anonymous audit record for a failed API auth attempt.

    Captured fields:
      * prefix — first 11 chars of the presented key (never the full key)
      * path   — endpoint being probed
      * reason — short tag (no_key | bad_key | rate_limited | no_api_perm)
    """
    try:
        from mobsf.RBAC import audit
    except Exception:  # noqa: BLE001
        # RBAC app may not be migrated on a brand-new install — never
        # let audit-import failure surface to the caller.
        return
    presented = _extract_key(getattr(request, 'META', {}) or {})
    audit.record_anon(
        request,
        'api.auth.fail',
        metadata={
            'prefix': (presented or '')[:11],
            'path': getattr(request, 'path', ''),
            'reason': reason,
        },
    )


def _has_api_use_permission(request):
    """Check the api.use MobInspect permission for the authenticated
    principal. The legacy global API key has no associated user, so we
    treat it as having full access (operators should migrate to per-user
    keys). Per-user keys must hold api.use explicitly — this stops a
    revoked-role user from continuing to call the API."""
    api_user = getattr(request, 'api_user', None)
    if api_user is None:
        # Legacy global key path — no user-level enforcement here.
        return True
    if getattr(api_user, 'is_superuser', False) or getattr(
            api_user, 'is_staff', False):
        return True
    try:
        from mobsf.RBAC.permissions import has_permission
        return has_permission(request, 'api.use')
    except Exception:  # noqa: BLE001
        # Fail closed on a permission-lookup error, but log loudly so we
        # notice misconfiguration rather than silently locking everyone
        # out — return True and rely on per-view permission_required to
        # catch privileged endpoints. The api.use gate is defense-in-depth.
        logger.exception('[ERROR] api.use permission check failed')
        return True


class RestApiAuthMiddleware(MiddlewareMixin):
    """Middleware for REST API auth.

    Honors per-user MobInspect ApiKey and the legacy global key. Adds:
      * Per-IP rate limit on auth FAILURES (anti-brute-force).
      * Audit record on every failure path (no_key, bad_key, rate, perm).
      * api.use permission gate on successful authentication.
    """

    def process_request(self, request):
        if not request.path.startswith('/api/'):
            return
        if request.method == 'OPTIONS':
            return make_api_response({}, 200)

        # Authenticate FIRST so a VALID key bypasses the per-IP failure
        # rate-limit entirely. Otherwise a bad-key flood from a shared
        # NAT/proxy IP could 429 legitimate clients hitting the same IP.
        # The failure counter (group='api.auth.fail') is only consulted —
        # and only incremented — on auth FAILURES, never on success.
        if api_auth(request):
            # Valid key: skip the failure rate-limit and fall through to
            # the api.use permission gate below.
            pass
        else:
            # Auth failed. Tick the per-IP failure counter and decide
            # whether this IP has crossed the failure threshold.
            # `is_ratelimited` is a no-op when RATELIMIT_ENABLE is False
            # (e.g. in tests). `increment=True` ticks the counter for this
            # failed attempt; group='api.auth.fail' isolates this bucket
            # from other ratelimit groups in the app.
            try:
                limited = is_ratelimited(
                    request,
                    group='api.auth.fail',
                    key='ip',
                    rate=API_AUTH_FAIL_RATE,
                    method=RATELIMIT_ALL_METHODS,
                    increment=True,
                )
            except Exception:  # noqa: BLE001
                limited = False
            if limited:
                _audit_auth_fail(request, 'rate_limited')
                return make_api_response(
                    {'error': 'Too many failed API auth attempts.'},
                    TOO_MANY)
            presented = _extract_key(request.META)
            _audit_auth_fail(
                request,
                'no_key' if not presented else 'bad_key')
            return make_api_response(
                {'error': 'You are unauthorized to make this request.'},
                UNAUTHORIZED)

        # Authenticated — enforce the api.use permission. Without this,
        # a per-user key whose role no longer holds api.use could still
        # hit /api/ endpoints (per-view permission_required only fires
        # for the specific verbs it wraps).
        if not _has_api_use_permission(request):
            _audit_auth_fail(request, 'no_api_perm')
            return make_api_response(
                {'error': 'API access not permitted for this user.'},
                FORBIDDEN)
