# -*- coding: utf_8 -*-
"""AI Security Analysis — a SEPARATE, admin-only page (and its htmx partial).

Fully decoupled from the scan report/dashboard: the scan dashboard never
references AI, so any AI problem cannot affect it. `ai_dashboard` renders the
standalone page; `ai_report` is the htmx endpoint the page uses to lazily load
and poll the enrichment. Both are admin-only and read-only.
"""
import logging

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render

from mobsf.MobSF.utils import is_md5, python_list
from mobsf.MobSF.views.authentication import login_required
from mobsf.RBAC.decorators import require_permission
from mobsf.RBAC.permissions import (
    effective_user,
    has_any_permission,
    is_auth_disabled,
)
from mobsf.StaticAnalyzer.models import AIEnrichment

logger = logging.getLogger(__name__)

_PARTIAL = 'static_analysis/_ai_analysis.html'
_PAGE = 'static_analysis/ai_dashboard.html'
# The AI Security Analysis is ADMIN-ONLY.
_ADMIN_AI_PERM = 'admin.ai.view'


def _is_ai_admin(request):
    if is_auth_disabled():
        return True
    return has_any_permission(effective_user(request), [_ADMIN_AI_PERM])


def _enrichment_ctx(checksum):
    """Return (status, context) for a scan's enrichment.

    status: disabled | invalid | none | pending | running | failed | done.
    """
    if not getattr(settings, 'MOBINSPECT_AI_ENABLED', False):
        return 'disabled', {'checksum': checksum}
    if not is_md5(checksum):
        return 'invalid', {'checksum': checksum}
    row = AIEnrichment.objects.filter(MD5=checksum).first()
    if not row:
        return 'none', {'checksum': checksum}
    if row.STATUS in ('pending', 'running'):
        return row.STATUS, {'checksum': checksum, 'ai_status': row.STATUS}
    if row.STATUS == 'failed':
        return 'failed', {'checksum': checksum, 'ai_status': 'failed'}
    return 'done', {
        'checksum': checksum,
        'ai_status': 'done',
        'ai_summary': row.EXEC_SUMMARY,
        'ai_findings': python_list(row.FINDING_EXPLANATIONS),
        'ai_secrets': row.SECRETS_TRIAGE,
        'ai_model': row.MODEL_USED,
    }


@login_required
@require_permission(_ADMIN_AI_PERM)
def ai_dashboard(request, checksum):
    """Standalone admin-only AI Security Analysis page."""
    try:
        status, ctx = _enrichment_ctx(checksum)
        ctx['ai_page_status'] = status
        return render(request, _PAGE, ctx)
    except Exception:
        logger.exception('Failed to render AI dashboard for %s', checksum)
        return render(request, _PAGE, {
            'checksum': checksum, 'ai_page_status': 'failed'})


@login_required
def ai_report(request, checksum):
    """htmx partial used by the AI page to lazily load / poll enrichment.

    Admin-only: non-admins get 204 so nothing is shown (never a 403 fragment).
    """
    try:
        if not _is_ai_admin(request):
            return HttpResponse(status=204)
        status, ctx = _enrichment_ctx(checksum)
        if status in ('disabled', 'invalid'):
            return HttpResponse(status=204)
        if status == 'none':
            # Enabled + valid, but the background row hasn't appeared yet:
            # render a pending state that keeps polling until it does (avoids
            # the "hidden until reload" race).
            return render(request, _PARTIAL, {
                'checksum': checksum, 'ai_status': 'pending'})
        return render(request, _PARTIAL, ctx)
    except Exception:
        logger.exception('Failed to render AI report for %s', checksum)
        return HttpResponse(status=204)
