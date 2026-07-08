# -*- coding: utf_8 -*-
"""Background AI enrichment task.

Runs on the django-q worker AFTER a scan has completed and persisted. Reads
scan results from the DB, asks the local Granite model to explain them, and
stores prose on AIEnrichment. Fully wrapped: any failure sets STATUS='failed'
and is swallowed — it can never affect the scan or the report.
"""
import logging
import threading
import time
from collections import Counter

from django.conf import settings
from django.db import close_old_connections
from django.utils import timezone

from mobsf.MobSF.utils import is_md5, python_dict, python_list
from mobsf.StaticAnalyzer.models import (
    AIEnrichment,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)
from mobsf.StaticAnalyzer.views.common.llm import prompts as P
from mobsf.StaticAnalyzer.views.common.llm.client import GraniteClient

logger = logging.getLogger(__name__)

_SEV_ORDER = {'high': 0, 'warning': 1, 'hotspot': 2}
_SKIP_SEV = {'good', 'info', 'secure', ''}


def _cvss(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _code_findings(db_row):
    """Extract meaningful code-analysis findings + grounding metadata from a scan row.

    The CODE_ANALYSIS DB field stores the findings dict directly, keyed by rule
    id (e.g. ``android_logging``) — it is NOT wrapped in a ``findings`` key.
    """
    findings = python_dict(db_row.CODE_ANALYSIS) or {}
    out = []
    if not isinstance(findings, dict):
        return out
    for rule_id, cd in findings.items():
        if not isinstance(cd, dict):
            continue
        meta = cd.get('metadata', {}) or {}
        sev = meta.get('severity', '')
        if sev in _SKIP_SEV:
            continue
        out.append({
            'title': meta.get('description', rule_id),
            'section': 'code',
            'severity': sev,
            'cvss': meta.get('cvss', ''),
            'cwe': meta.get('cwe', ''),
            'owasp': meta.get('owasp-mobile', ''),
            'masvs': meta.get('masvs', ''),
        })
    return out


def enrich_in_background(checksum):
    """Launch enrichment in a daemon thread, fully DECOUPLED from the scan queue.

    Local work here is only HTTP calls to the remote model box (inference runs
    there, not locally), so the thread's footprint is negligible and it can
    never occupy a scan worker or delay/serialize scans. Fail-closed.
    """
    def _runner():
        close_old_connections()
        try:
            ai_enrich_task(checksum)
        finally:
            close_old_connections()

    try:
        threading.Thread(
            target=_runner,
            name=f'ai-enrich-{checksum[:8]}',
            daemon=True).start()
    except Exception:
        logger.exception('Failed to start AI enrichment thread for %s', checksum)


def ai_enrich_task(checksum):
    """Best-effort background enrichment. Never raises; never touches the scan."""
    if not getattr(settings, 'MOBINSPECT_AI_ENABLED', False):
        return
    if not checksum or not is_md5(checksum):
        return
    try:
        android = StaticAnalyzerAndroid.objects.filter(MD5=checksum).first()
        ios = None if android else StaticAnalyzerIOS.objects.filter(
            MD5=checksum).first()
        db_row = android or ios
        if not db_row:
            return
        # Read secrets from the RESOLVED row so iOS scans are covered too.
        secrets = python_list(db_row.SECRETS)

        AIEnrichment.objects.update_or_create(
            MD5=checksum,
            defaults={'STATUS': 'running', 'UPDATED_AT': timezone.now()})

        client = GraniteClient()
        gen_model = getattr(settings, 'MOBINSPECT_AI_MODEL_GENERATE', 'granite4:8b')
        cls_model = getattr(settings, 'MOBINSPECT_AI_MODEL_CLASSIFY', gen_model)
        max_items = int(getattr(settings, 'MOBINSPECT_AI_MAX_ITEMS', 25))

        findings = _code_findings(db_row)
        counts = dict(Counter(f['severity'] for f in findings))
        findings.sort(key=lambda f: (
            _SEV_ORDER.get(f['severity'], 9), -_cvss(f.get('cvss'))))
        findings = findings[:max_items]

        # Aggregate wall-clock budget: enrichment shares the scan worker pool,
        # so a slow endpoint + many findings must never occupy a worker
        # indefinitely and starve real scans. Stop enriching once exceeded.
        budget = int(getattr(settings, 'MOBINSPECT_AI_TOTAL_BUDGET', 300))
        deadline = time.monotonic() + budget

        explanations = []
        for finding in findings:
            if time.monotonic() > deadline:
                logger.warning(
                    'AI enrichment budget (%ss) reached for %s; stopping early',
                    budget, checksum)
                break
            system, prompt = P.build_finding_prompt(finding)
            text = client.generate(system, prompt, model=gen_model)
            if text:
                explanations.append({
                    'section': finding['section'],
                    'title': P.sanitize_output(finding['title'], 200),
                    'severity': finding['severity'],
                    'cwe': str(finding.get('cwe', '')),
                    'explanation': P.sanitize_output(text),
                })

        summary = ''
        if findings and time.monotonic() <= deadline:
            system, prompt = P.build_summary_prompt(findings, counts)
            raw = client.generate(system, prompt, model=gen_model)
            summary = P.sanitize_output(raw) if raw else ''

        triage = ''
        if secrets and time.monotonic() <= deadline:
            masked = [P.redact_secret(s) for s in secrets[:max_items]]
            system, prompt = P.build_secret_prompt(masked)
            raw = client.generate(system, prompt, model=cls_model)
            triage = P.sanitize_output(raw) if raw else ''

        AIEnrichment.objects.update_or_create(
            MD5=checksum,
            defaults={
                'STATUS': 'done',
                'EXEC_SUMMARY': summary,
                'FINDING_EXPLANATIONS': explanations,
                'SECRETS_TRIAGE': triage,
                'MODEL_USED': gen_model,
                'UPDATED_AT': timezone.now(),
            })
        logger.info(
            'AI enrichment complete for %s (%d explanations)',
            checksum, len(explanations))
    except Exception:
        logger.exception('AI enrichment failed for %s', checksum)
        try:
            AIEnrichment.objects.update_or_create(
                MD5=checksum,
                defaults={'STATUS': 'failed', 'UPDATED_AT': timezone.now()})
        except Exception:
            pass
