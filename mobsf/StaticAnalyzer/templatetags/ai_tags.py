# -*- coding: utf_8 -*-
"""Template helpers for the admin AI Security Analysis surface."""
import re

from django import template
from django.conf import settings
from django.utils.html import escape
from django.utils.safestring import mark_safe

from mobsf.StaticAnalyzer.models import AIEnrichment
from mobsf.StaticAnalyzer.views.common.llm.views import (
    ai_run_status as _ai_run_status,
)

register = template.Library()

# ── Safe AI-output formatting ────────────────────────────────────────────────
# The model emits light markdown (**bold**, `code`, "- " bullets, "1." lists,
# "## " headers). We render a TINY whitelisted subset so the dashboard reads
# cleanly instead of showing raw '**' etc.
#
# SECURITY: the input is UNTRUSTED model output derived from a possibly
# malicious app. Every string is html-escaped FIRST (escape()), and only THEN
# are our own fixed tags injected into the already-escaped text. Nothing the
# model wrote can become live markup, so mark_safe() here only re-marks tags we
# generated — it never trusts app/model content. This preserves the same
# no-raw-HTML guarantee the template comment requires.
_BULLET_RE = re.compile(r'^\s*[-*•]\s+(.*)$')
_NUM_RE = re.compile(r'^\s*\d{1,3}[.)]\s+(.*)$')
_HEAD_RE = re.compile(r'^\s*#{1,6}\s+(.*\S)\s*$')


def _inline(escaped):
    """Inline formatting on ALREADY-ESCAPED text: **bold** and `code` only."""
    escaped = re.sub(r'\*\*(?=\S)(.+?)(?<=\S)\*\*', r'<strong>\1</strong>', escaped)
    escaped = re.sub(r'`(?=\S)(.+?)(?<=\S)`', r'<code>\1</code>', escaped)
    return escaped


@register.filter
def ai_inline(value):
    """Inline-only safe formatting (bold/code) for short AI strings."""
    if not value:
        return ''
    return mark_safe(_inline(escape(str(value))))


@register.filter
def ai_richtext(value):
    """Render AI text as clean HTML: paragraphs, bullet/numbered lists, bold,
    inline code. Escape-first + whitelist-only (see module note). Never raises.
    """
    if not value:
        return ''
    raw = str(value).replace('\r\n', '\n').replace('\r', '\n')
    out, para, items = [], [], []

    def flush_para():
        if para:
            out.append('<p>' + '<br>'.join(_inline(x) for x in para) + '</p>')
            para.clear()

    def flush_list():
        if items:
            out.append('<ul>' + ''.join(
                '<li>' + _inline(x) + '</li>' for x in items) + '</ul>')
            items.clear()

    for line in raw.split('\n'):
        esc = escape(line)
        if not esc.strip():
            flush_para(); flush_list()
            continue
        mb = _BULLET_RE.match(esc) or _NUM_RE.match(esc)
        mh = _HEAD_RE.match(esc)
        if mb:
            flush_para()
            items.append(mb.group(1).strip())
        elif mh:
            flush_para(); flush_list()
            out.append('<p class="ai-h"><strong>'
                       + _inline(mh.group(1).strip()) + '</strong></p>')
        else:
            flush_list()
            para.append(esc.strip())
    flush_para(); flush_list()
    return mark_safe(''.join(out))


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
