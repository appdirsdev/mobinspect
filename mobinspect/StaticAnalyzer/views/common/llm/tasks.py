# -*- coding: utf_8 -*-
"""Background AI enrichment task.

Runs on a decoupled daemon thread AFTER a scan completes. Reads the COMPLETE
static-analysis context for the scan, builds one comprehensive prompt, asks the
local Granite model for a full security report in a single pass, and stores it
on AIEnrichment. Fully wrapped: any failure sets STATUS='failed' and is
swallowed — it can never affect the scan, the report, or the score.
"""
import logging
import threading
import time

from django.conf import settings
from django.db import close_old_connections
from django.utils import timezone

from mobinspect.MobInspect.utils import is_md5
from mobinspect.StaticAnalyzer.models import (
    AIEnrichment,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)
from mobinspect.StaticAnalyzer.views.common.llm import prompts as P
from mobinspect.StaticAnalyzer.views.common.llm.client import GraniteClient

logger = logging.getLogger(__name__)


def enrich_in_background(checksum):
    """Run enrichment in a daemon thread, DECOUPLED from the scan queue.

    Local work is only HTTP to the model host (inference runs there), so the
    thread's footprint is negligible and it never occupies a scan worker.
    """
    def _runner():
        close_old_connections()
        try:
            ai_enrich_task(checksum)
        finally:
            close_old_connections()

    try:
        threading.Thread(
            target=_runner, name=f'ai-enrich-{checksum[:8]}', daemon=True).start()
    except Exception:
        logger.exception('Failed to start AI enrichment thread for %s', checksum)


def _load_context(checksum):
    """Return (context_dict, platform) for the scan, or (None, None)."""
    android = StaticAnalyzerAndroid.objects.filter(MD5=checksum).first()
    if android:
        from mobinspect.StaticAnalyzer.views.android.db_interaction import (
            get_context_from_db_entry as adb)
        return adb([android]), 'Android'
    ios = StaticAnalyzerIOS.objects.filter(MD5=checksum).first()
    if ios:
        from mobinspect.StaticAnalyzer.views.ios.db_interaction import (
            get_context_from_db_entry as idb)
        return idb([ios]), 'iOS'
    return None, None


def _counts(ctx):
    """Compact deterministic finding-count summary for prompt grounding."""
    parts = []
    code = (ctx.get('code_analysis') or {}).get('summary') or {}
    if code:
        parts.append('code ' + ', '.join(
            f'{k}={code.get(k, 0)}' for k in ('high', 'warning', 'info')))
    man = (ctx.get('manifest_analysis') or {}).get('manifest_summary') or {}
    if man:
        parts.append('manifest ' + ', '.join(
            f'{k}={man.get(k, 0)}' for k in ('high', 'warning')))
    tr = ctx.get('trackers') or {}
    if tr.get('trackers'):
        parts.append(f'trackers={tr.get("detected_trackers") or len(tr["trackers"])}')
    secrets = ctx.get('secrets') or []
    if secrets:
        parts.append(f'secrets={len(secrets)}')
    return '; '.join(parts) or 'no findings'


def _triage_secrets(ctx):
    """Stage 2 — run the CLASSIFICATION model over MASKED secret candidates.

    Short, structured triage (real credential vs likely false positive) using
    the `classify` role, kept fully separate from the generation report. Only
    masked values (prefix + length) ever leave the box — never the literal.
    Returns sanitized advisory text, or '' when there are no secrets, the
    classify endpoint is disabled/unreachable, or anything fails. Never raises.
    """
    try:
        secrets = ctx.get('secrets') or []
        if not secrets:
            return ''
        n = int(getattr(settings, 'MOBINSPECT_AI_MAX_ITEMS', 25))
        masked = [P.redact_secret(s) for s in secrets[:n]]
        clf = GraniteClient(role='classify')
        if not clf.enabled:
            return ''
        system, prompt = P.build_secret_prompt(masked)
        raw = clf.generate(
            system, prompt,
            num_predict=int(getattr(settings, 'MOBINSPECT_AI_TRIAGE_TOKENS', 400)))
        return P.sanitize_output(raw) if raw else ''
    except Exception:
        logger.exception('AI secret triage (classification) failed')
        return ''


def _classify_risk(profile):
    """Stage 3 — CLASSIFICATION model rates the app's risk per security dimension
    (categorical none..critical, NEVER a numeric score). Returns a validated,
    ordered list over the fixed dimensions, or [] on any failure. Never raises.
    """
    try:
        clf = GraniteClient(role='classify')
        if not clf.enabled:
            return []
        system, prompt = P.build_risk_classification_prompt(profile)
        raw = clf.generate(
            system, prompt,
            num_predict=int(getattr(settings, 'MOBINSPECT_AI_TRIAGE_TOKENS', 400)))
        return P.parse_risk_classification(raw) if raw else []
    except Exception:
        logger.exception('AI risk classification failed')
        return []


def _detect_anomalies(profile, counts):
    """Stage 4 — CLASSIFICATION model correlates findings into notable anomalies
    + suggestions. Returns a validated list, or [] on any failure. Never raises.
    """
    try:
        clf = GraniteClient(role='classify')
        if not clf.enabled:
            return []
        system, prompt = P.build_anomaly_prompt(profile, counts)
        raw = clf.generate(
            system, prompt,
            num_predict=int(getattr(settings, 'MOBINSPECT_AI_TRIAGE_TOKENS', 400)))
        return P.parse_anomalies(raw) if raw else []
    except Exception:
        logger.exception('AI anomaly detection failed')
        return []


def ai_enrich_task(checksum):
    """Best-effort background enrichment. Never raises; never touches the scan."""
    if not getattr(settings, 'MOBINSPECT_AI_ENABLED', False):
        return
    if not checksum or not is_md5(checksum):
        return
    try:
        ctx, platform = _load_context(checksum)
        if not ctx:
            return

        # Aggregate wall-clock budget for the whole run: the supplementary
        # classification stages are skipped once the report has consumed it,
        # so enrichment can't hold model connections open unbounded.
        deadline = time.monotonic() + int(
            getattr(settings, 'MOBINSPECT_AI_TOTAL_BUDGET', 300))

        AIEnrichment.objects.update_or_create(
            MD5=checksum,
            defaults={'STATUS': 'running', 'UPDATED_AT': timezone.now()})

        client = GraniteClient()
        model = client.model or getattr(
            settings, 'MOBINSPECT_AI_MODEL_GENERATE', 'granite4:3b')
        report_tokens = int(getattr(settings, 'MOBINSPECT_AI_REPORT_TOKENS', 1200))

        profile = P.build_apk_profile(ctx)
        counts = _counts(ctx)
        system, prompt = P.build_report_prompt(profile, counts, platform)
        raw = client.generate(system, prompt, model=model, num_predict=report_tokens)
        sections = P.parse_report(raw) if raw else []

        # Supplementary CLASSIFICATION stages — each runs only when the report
        # succeeded AND the run budget still remains (deadline re-checked before
        # every stage, so a slow earlier stage causes later ones to be skipped):
        #   2 · secret triage   3 · per-dimension risk   4 · anomalies + fixes
        secrets_triage = ''
        risk_class = []
        anomalies = []
        if sections and time.monotonic() < deadline:
            secrets_triage = _triage_secrets(ctx)
        if sections and time.monotonic() < deadline:
            risk_class = _classify_risk(profile)
        if sections and time.monotonic() < deadline:
            anomalies = _detect_anomalies(profile, counts)

        summary = ''
        for s in sections:
            if 'SUMMARY' in s['heading'].upper():
                summary = s['body']
                break
        if not summary and sections:
            summary = sections[0]['body']

        AIEnrichment.objects.update_or_create(
            MD5=checksum,
            defaults={
                'STATUS': 'done' if sections else 'failed',
                'EXEC_SUMMARY': summary,
                'FINDING_EXPLANATIONS': sections,
                'SECRETS_TRIAGE': secrets_triage,
                'RISK_CLASSIFICATION': risk_class,
                'ANOMALIES': anomalies,
                'MODEL_USED': model,
                'UPDATED_AT': timezone.now(),
            })
        logger.info('AI enrichment complete for %s (%d sections)',
                    checksum, len(sections))
    except Exception:
        logger.exception('AI enrichment failed for %s', checksum)
        try:
            AIEnrichment.objects.update_or_create(
                MD5=checksum,
                defaults={'STATUS': 'failed', 'UPDATED_AT': timezone.now()})
        except Exception:
            pass
