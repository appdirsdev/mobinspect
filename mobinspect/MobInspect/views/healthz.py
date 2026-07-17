"""
MobInspect — liveness/readiness endpoints for monitors.

Two routes:
  - /healthz : probes DB, queue table, and adb. Returns JSON with per-component
               status. Used by external monitors (Prometheus blackbox, k8s
               readiness probes, uptime checks) — intentionally unauthenticated.
  - /readyz  : no probing, just a 200. Use for liveness checks where you only
               want to know the process is up and serving.

Status semantics:
  - status='ok'       all probes succeeded
  - status='degraded' queue or adb probe failed (service can still scan,
                      but background work / dynamic analysis may be impaired)
  - status='failed'   DB probe failed — service is effectively down
"""
import datetime
import logging
import subprocess

from django.conf import settings
from django.db import connection
from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET

from mobinspect.MobInspect.utils import get_adb


logger = logging.getLogger(__name__)


def _check_db():
    """Probe the primary DB by issuing a trivial query."""
    try:
        connection.cursor().execute('SELECT 1')
        return True
    except Exception:
        logger.exception('healthz: DB probe failed')
        return False


def _check_queue():
    """Probe django-q by touching the Schedule table.

    Only the table being reachable matters; an empty result is fine.
    """
    try:
        from django_q.models import Schedule
        Schedule.objects.exists()
        return True
    except Exception:
        logger.exception('healthz: queue probe failed')
        return False


def _check_adb():
    """Probe adb by running `adb devices` with a short timeout.

    Returns True only when at least one attached target reports the
    'device' state. `adb devices` exits 0 even with zero devices (or with
    targets stuck offline/unauthorized), so we parse the table rather than
    trusting the exit code.

    adb is optional in many deployments (static-only installs), so a
    failure here only degrades — never fails — the overall health.
    """
    try:
        adb = get_adb()
        if not adb:
            return False
        out = subprocess.check_output(
            [adb, 'devices'],
            timeout=2,
            stderr=subprocess.STDOUT,
        )
        # Skip the 'List of devices attached' header; each remaining line
        # is '<serial>\t<state>'. We require at least one 'device' state.
        lines = out.decode('utf-8', 'ignore').splitlines()
        for line in lines[1:]:
            parts = line.split('\t')
            if len(parts) == 2 and parts[1].strip() == 'device':
                return True
        return False
    except Exception:
        logger.exception('healthz: adb probe failed')
        return False


@csrf_exempt
@never_cache
@require_GET
def healthz(request):
    """Readiness probe with component-level detail."""
    db_ok = _check_db()
    queue_ok = _check_queue()
    adb_ok = _check_adb()

    if not db_ok:
        status = 'failed'
    elif not (queue_ok and adb_ok):
        status = 'degraded'
    else:
        status = 'ok'

    payload = {
        'status': status,
        'db': db_ok,
        'queue': queue_ok,
        'adb': adb_ok,
        'version': getattr(settings, 'MOBINSPECT_VER', ''),
        'now': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    # 200 for ok/degraded so monitors can distinguish via JSON body;
    # 503 only when the service truly cannot serve requests (DB down).
    http_status = 503 if status == 'failed' else 200
    return JsonResponse(payload, status=http_status)


@csrf_exempt
@never_cache
@require_GET
def readyz(request):
    """Liveness probe — returns 200 if the process is serving."""
    return JsonResponse({'status': 'ok'})
