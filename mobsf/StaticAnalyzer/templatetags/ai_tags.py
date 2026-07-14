# -*- coding: utf_8 -*-
"""Template helpers for the admin AI Security Analysis surface."""
from django import template
from django.conf import settings

from mobsf.StaticAnalyzer.models import AIEnrichment
from mobsf.StaticAnalyzer.views.common.llm.views import (
    ai_run_status as _ai_run_status,
)

register = template.Library()


@register.simple_tag
def ai_dashboard_ready(md5):
    """True when the AI Dashboard is enterable for this scan.

    The button (and page) are disabled unless AI is enabled AND the model has
    produced — or is producing — a report for this scan. When the model never
    generated a report (no row / failed), the button is hidden so the operator
    cannot enter a dead dashboard. Best-effort: never raises.
    """
    if not getattr(settings, 'MOBINSPECT_AI_ENABLED', False):
        return False
    try:
        row = (AIEnrichment.objects
               .filter(MD5=md5).only('STATUS').first())
    except Exception:
        return False
    return bool(row) and row.STATUS in ('done', 'running', 'pending')


@register.simple_tag
def ai_run_status(md5):
    """'unavailable' | 'running' | 'ready' — state of the manual "Run AI
    analysis" trigger button for this scan. See views.ai_run_status."""
    try:
        return _ai_run_status(md5)
    except Exception:
        return 'unavailable'
