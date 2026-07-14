# -*- coding: utf_8 -*-
"""AI Security Analysis — a SEPARATE, admin-only page (and its htmx partial).

Fully decoupled from the scan report/dashboard: the scan dashboard never
references AI, so any AI problem cannot affect it. `ai_dashboard` renders the
standalone page; `ai_report` is the htmx endpoint the page uses to lazily load
and poll the enrichment. Both are admin-only and read-only.
"""
import logging

from django.conf import settings
from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme

from mobsf.MobSF.utils import is_md5, python_list
from mobsf.MobSF.views.authentication import login_required
from mobsf.RBAC import audit
from mobsf.RBAC.decorators import require_permission
from mobsf.RBAC.permissions import (
    effective_user,
    has_any_permission,
    is_auth_disabled,
)
from mobsf.StaticAnalyzer.models import (
    AIEnrichment,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)

logger = logging.getLogger(__name__)

_PARTIAL = 'static_analysis/_ai_analysis.html'
_PAGE = 'static_analysis/ai_dashboard.html'
# The AI Security Analysis is ADMIN-ONLY.
_ADMIN_AI_PERM = 'admin.ai.view'


def _is_ai_admin(request):
    if is_auth_disabled():
        return True
    return has_any_permission(effective_user(request), [_ADMIN_AI_PERM])


# level -> (bar width %, badge severity tone) for the risk chart. Presentation
# only; the level itself is already validated against RISK_LEVELS at parse time.
_RISK_VIS = {
    'none': (10, 'passed'), 'low': (34, 'low'), 'medium': (58, 'medium'),
    'high': (82, 'high'), 'critical': (100, 'critical'), 'unknown': (4, 'neutral'),
}


def _risk_for_display(raw):
    """Attach a bar width + badge tone to each validated risk record."""
    out = []
    for r in python_list(raw):
        if not isinstance(r, dict):
            continue
        level = str(r.get('level', 'unknown'))
        pct, tone = _RISK_VIS.get(level, _RISK_VIS['unknown'])
        out.append({
            'dimension': r.get('dimension', ''), 'level': level,
            'rationale': r.get('rationale', ''), 'pct': pct, 'tone': tone,
        })
    return out


# Per-level RISK contribution (0-100). The overall AI risk score is a
# DETERMINISTIC aggregate of the model's categorical levels — the model never
# emits the number itself, so it can't be hallucinated. Higher = more risk.
_RISK_SCORE = {'none': 0, 'low': 25, 'medium': 50, 'high': 75, 'critical': 100}


def _risk_score(risk_records):
    """Overall AI risk score out of 100 (higher = more risk), aggregated from
    the classified dimensions only. Returns None when nothing was classified."""
    vals = [_RISK_SCORE[r['level']] for r in risk_records
            if isinstance(r, dict) and r.get('level') in _RISK_SCORE]
    if not vals:
        return None
    return round(sum(vals) / len(vals))


def _score_tone(score):
    """Severity tone for the risk-score dial (mirrors the bar palette)."""
    if score is None:
        return 'neutral'
    if score >= 75:
        return 'critical'
    if score >= 50:
        return 'high'
    if score >= 25:
        return 'medium'
    return 'passed'


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
    risk = _risk_for_display(row.RISK_CLASSIFICATION)
    score = _risk_score(risk)
    return 'done', {
        'checksum': checksum,
        'ai_status': 'done',
        'ai_summary': row.EXEC_SUMMARY,
        'ai_findings': python_list(row.FINDING_EXPLANATIONS),
        'ai_secrets': row.SECRETS_TRIAGE,
        'ai_risk': risk,
        'ai_risk_score': score,
        'ai_risk_tone': _score_tone(score),
        'ai_anomalies': python_list(row.ANOMALIES),
        'ai_model': row.MODEL_USED,
    }


# States where the model never produced a report -> the dashboard is disabled
# and the user is bounced out (per requirement: "if model not generated any
# report, user cannot enter"). 'running'/'pending'/'done' are allowed through.
_DASHBOARD_BLOCKED = ('disabled', 'invalid', 'none', 'failed')


@login_required
@require_permission(_ADMIN_AI_PERM)
def ai_dashboard(request, checksum):
    """Standalone admin-only AI Security Analysis page.

    Disabled unless the model has produced (or is producing) a report — a
    blocked state redirects the operator back to the scans list.
    """
    try:
        status, ctx = _enrichment_ctx(checksum)
        if status in _DASHBOARD_BLOCKED:
            messages.info(
                request, 'AI analysis is not available for this scan yet.')
            return redirect('recent')
        ctx['ai_page_status'] = status
        return render(request, _PAGE, ctx)
    except Exception:
        logger.exception('Failed to render AI dashboard for %s', checksum)
        return redirect('recent')


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


def _both_roles_configured():
    """True when generate + classify each have an active, usable endpoint.

    is_active is scoped PER ROLE in the DB (see GraniteClient._resolve_target,
    which filters on role=role, is_active=True) — the two rows are meant to be
    active at the same time, one per role. A stale class docstring on
    ModelIntegration suggests a single global "active row", which is not how
    the fixed generate/classify Integrations UI actually saves.
    """
    try:
        from django.apps import apps
        model_cls = apps.get_model('rbac', 'ModelIntegration')
    except LookupError:
        return False
    for role in ('generate', 'classify'):
        row = model_cls.objects.filter(role=role, is_active=True).first()
        if not row or not (row.base_url or '').strip() or not (row.model_name or '').strip():
            return False
    return True


def _report_exists(checksum):
    return (StaticAnalyzerAndroid.objects.filter(MD5=checksum).exists()
            or StaticAnalyzerIOS.objects.filter(MD5=checksum).exists())


def ai_run_status(checksum):
    """State of the manual "Run AI analysis" trigger for a scan.

    'unavailable' — AI disabled, no report yet, or generate/classify aren't
                     both configured.
    'running'      — enrichment already in flight; don't offer a duplicate.
    'ready'        — safe to trigger.
    Best-effort: never raises.
    """
    if not getattr(settings, 'MOBINSPECT_AI_ENABLED', False):
        return 'unavailable'
    try:
        if (not is_md5(checksum)
                or not _report_exists(checksum)
                or not _both_roles_configured()):
            return 'unavailable'
        row = AIEnrichment.objects.filter(MD5=checksum).only('STATUS').first()
    except Exception:
        return 'unavailable'
    if row and row.STATUS in ('pending', 'running'):
        return 'running'
    return 'ready'


@login_required
@require_permission(_ADMIN_AI_PERM)
def ai_run(request, checksum):
    """POST-only: manually (re)trigger AI enrichment for a scan.

    Enabled only when both model roles are configured and no enrichment is
    already in flight for this scan (ai_run_status == 'ready'), so this
    can't be used to pile up duplicate background runs.
    """
    referer = request.META.get('HTTP_REFERER', '')
    if url_has_allowed_host_and_scheme(
            referer, allowed_hosts={request.get_host()}):
        back = redirect(referer)
    else:
        back = redirect('recent')

    if request.method != 'POST':
        return back
    if not is_md5(checksum):
        messages.error(request, 'Invalid scan reference.')
        return redirect('recent')
    if ai_run_status(checksum) != 'ready':
        messages.error(
            request, 'AI analysis is not available for this scan right now.')
        return back

    from mobsf.StaticAnalyzer.views.common.llm.tasks import enrich_in_background
    enrich_in_background(checksum)
    audit.record(request, 'ai.run.manual', target_type='scan', target_id=checksum)
    messages.success(
        request, 'AI analysis started — refresh in a moment to see results.')
    return back
