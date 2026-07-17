# -*- coding: utf_8 -*-
"""
REAL-EXECUTION coverage tests for
mobinspect/StaticAnalyzer/views/common/llm/views.py (AI Security Analysis).

Follows the fixture/setup conventions of mobinspect/RBAC/test_cov_views.py and
mobinspect/RBAC/tests/test_permissions.py: users/roles are built directly against
the real (migration-seeded) Permission catalog, auth is driven through the
real Django test Client via `force_login`, and pure helpers are also
exercised directly (mirroring how `_validate_host_port` is unit-tested in
mobinspect/RBAC/test_cov_views.py).

Scope: this module (`views.py`) never touches the network, a device, or a
real model — it only reads `AIEnrichment` rows written by the (separately
tested) background task. So there is nothing to mock here for the "external
boundary" rule; the boundary (Ollama HTTP) lives in client.py/tasks.py, out
of scope for this file. What *is* security-critical and covered here:

  * `ai_dashboard` is gated by the `admin.ai.view` permission (403 for any
    authenticated user lacking it, redirect-to-login for anonymous).
  * `ai_report` (the htmx polling partial) NEVER reveals a 403 fragment to
    a non-admin — it always degrades to a silent 204 so nothing renders.
  * `_enrichment_ctx` correctly classifies disabled / invalid / none /
    pending / running / failed / done, including on adversarial
    (non-md5, injection-shaped) checksum input.
  * `_is_ai_admin` honors the dev auth-bypass, the superuser fast-path, and
    real RBAC permission checks.
  * Every exception path (`except Exception`) degrades safely rather than
    leaking a 500.
  * The templates driving both endpoints never use `|safe` / `mark_safe` on
    model-derived (i.e. untrusted, LLM-generated from attacker-controlled
    app content) values, and a hostile payload placed in AI-derived fields
    is round-tripped HTML-escaped, never raw, in the rendered response.
"""
import inspect
import os
import re
from unittest.mock import MagicMock

import pytest

from django.contrib.auth.models import AnonymousUser, Group
from django.test import RequestFactory, override_settings
from django.urls import reverse

from mobinspect.RBAC.models import (
    AuditEvent,
    ModelIntegration,
    Permission,
    Role,
    RoleAssignment,
)
from mobinspect.StaticAnalyzer.models import (
    AIEnrichment,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)
from mobinspect.StaticAnalyzer.views.common.llm import views


# A syntactically valid md5-looking checksum; no real scan required since
# views.py only reads AIEnrichment (keyed by MD5), never the scan tables.
CHK = 'a' * 32


# ───────────────────────────────────────────── helpers / fixtures
def _make_role(name, codenames=(), is_system=False):
    group, _ = Group.objects.get_or_create(name=name)
    role, _ = Role.objects.get_or_create(
        group=group,
        defaults={'name': name, 'is_system': is_system},
    )
    role.name = name
    role.is_system = is_system
    role.save()
    if codenames:
        perms = list(Permission.objects.filter(codename__in=codenames))
        role.permissions.set(perms)
    return role


@pytest.fixture
def ai_admin(db, django_user_model):
    """User holding ONLY the `admin.ai.view` permission."""
    user = django_user_model.objects.create_user(
        username='cov_ai_admin', password='pw',
    )
    role = _make_role('CovAIAdmin', ['admin.ai.view'])
    RoleAssignment.objects.create(user=user, role=role)
    return user


@pytest.fixture
def plain_user(db, django_user_model):
    """A logged-in user holding NO RBAC permissions at all."""
    return django_user_model.objects.create_user(
        username='cov_ai_plain', password='pw',
    )


@pytest.fixture
def superuser(db, django_user_model):
    return django_user_model.objects.create_user(
        username='cov_ai_root', password='pw',
        is_staff=True, is_superuser=True,
    )


@pytest.fixture
def admin_client(client, ai_admin):
    client.force_login(ai_admin)
    return client


@pytest.fixture
def plain_client(client, plain_user):
    client.force_login(plain_user)
    return client


@pytest.fixture
def su_client(client, superuser):
    client.force_login(superuser)
    return client


# ═══════════════════════════════════════════════ _enrichment_ctx (pure-ish)
@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=False)
def test_enrichment_ctx_disabled_short_circuits_before_db():
    """AI off → 'disabled' without even checking is_md5 or hitting the DB."""
    status, ctx = views._enrichment_ctx('this is not even a checksum')
    assert status == 'disabled'
    assert ctx == {'checksum': 'this is not even a checksum'}


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
@pytest.mark.parametrize('bad_checksum', [
    'too-short',
    'g' * 32,                       # right length, not hex
    CHK + 'a',                      # 33 chars
    CHK.upper(),                    # uppercase not accepted by MD5_REGEX
    '',
    "'; DROP TABLE static_analyzer_aienrichment; --",
    '../../../../etc/passwd',
    '<script>alert(1)</script>' + 'a' * 6,
    '127.0.0.1:11434/api/generate',
])
def test_enrichment_ctx_rejects_adversarial_non_md5_checksums(bad_checksum):
    """Non-md5 / injection-shaped input never reaches the ORM query.

    Every value here is syntactically hostile (SQLi-shaped, path-traversal,
    XSS-shaped, SSRF-host-shaped) but none of it matches the strict
    ^[0-9a-f]{32}$ checksum grammar, so the view must classify it 'invalid'
    without raising and without a DB lookup succeeding on it.
    """
    status, ctx = views._enrichment_ctx(bad_checksum)
    assert status == 'invalid'
    assert ctx == {'checksum': bad_checksum}


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_enrichment_ctx_none_when_no_row_yet():
    status, ctx = views._enrichment_ctx(CHK)
    assert status == 'none'
    assert ctx == {'checksum': CHK}


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
@pytest.mark.parametrize('raw_status', ['pending', 'running'])
def test_enrichment_ctx_pending_and_running_passthrough(raw_status):
    AIEnrichment.objects.create(MD5=CHK, STATUS=raw_status)
    status, ctx = views._enrichment_ctx(CHK)
    assert status == raw_status
    assert ctx == {'checksum': CHK, 'ai_status': raw_status}


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_enrichment_ctx_failed_row():
    AIEnrichment.objects.create(MD5=CHK, STATUS='failed')
    status, ctx = views._enrichment_ctx(CHK)
    assert status == 'failed'
    assert ctx == {'checksum': CHK, 'ai_status': 'failed'}


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_enrichment_ctx_done_row_builds_full_context():
    AIEnrichment.objects.create(
        MD5=CHK,
        STATUS='done',
        EXEC_SUMMARY='Executive summary text.',
        FINDING_EXPLANATIONS=str([
            {'heading': 'Insecure storage', 'body': 'Keys stored in plaintext.'},
        ]),
        SECRETS_TRIAGE='One API key found; looks like a test fixture.',
        MODEL_USED='granite4:3b',
    )
    status, ctx = views._enrichment_ctx(CHK)
    assert status == 'done'
    assert ctx['checksum'] == CHK
    assert ctx['ai_status'] == 'done'
    assert ctx['ai_summary'] == 'Executive summary text.'
    assert ctx['ai_findings'] == [
        {'heading': 'Insecure storage', 'body': 'Keys stored in plaintext.'},
    ]
    assert ctx['ai_secrets'] == 'One API key found; looks like a test fixture.'
    assert ctx['ai_model'] == 'granite4:3b'


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_enrichment_ctx_done_row_default_empty_findings():
    """FINDING_EXPLANATIONS default ('') round-trips through python_list()."""
    AIEnrichment.objects.create(MD5=CHK, STATUS='done')
    status, ctx = views._enrichment_ctx(CHK)
    assert status == 'done'
    assert ctx['ai_findings'] == []


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_enrichment_ctx_unknown_status_falls_through_to_done_shape():
    """Any STATUS not in the known set is treated as the terminal 'done'
    shape (defensive default — matches the `else` branch in the source)."""
    AIEnrichment.objects.create(MD5=CHK, STATUS='some-future-status')
    status, ctx = views._enrichment_ctx(CHK)
    assert status == 'done'
    assert ctx['ai_status'] == 'done'


# ═══════════════════════════════════════════════ _is_ai_admin (pure-ish)
class _FakeRequest:
    """Minimal duck-typed request — only the attrs the resolver reads."""

    def __init__(self, user=None, api_user=None):
        self.user = user
        if api_user is not None:
            self.api_user = api_user


@pytest.mark.django_db
@override_settings(DISABLE_AUTHENTICATION='1')
def test_is_ai_admin_true_when_auth_disabled_even_for_anonymous():
    req = _FakeRequest(user=AnonymousUser())
    assert views._is_ai_admin(req) is True


@pytest.mark.django_db
def test_is_ai_admin_true_for_holder_of_permission(ai_admin):
    req = _FakeRequest(user=ai_admin)
    assert views._is_ai_admin(req) is True


@pytest.mark.django_db
def test_is_ai_admin_false_for_plain_user(plain_user):
    req = _FakeRequest(user=plain_user)
    assert views._is_ai_admin(req) is False


@pytest.mark.django_db
def test_is_ai_admin_false_for_anonymous():
    req = _FakeRequest(user=AnonymousUser())
    assert views._is_ai_admin(req) is False


@pytest.mark.django_db
def test_is_ai_admin_true_for_superuser_fast_path(superuser):
    req = _FakeRequest(user=superuser)
    assert views._is_ai_admin(req) is True


# ═══════════════════════════════════════════════ ai_dashboard — admin gate
@pytest.mark.django_db
def test_ai_dashboard_anonymous_redirects_to_login(client):
    resp = client.get(reverse('ai_dashboard', args=[CHK]))
    assert resp.status_code == 302
    assert 'login' in resp['Location']


@pytest.mark.django_db
def test_ai_dashboard_denied_for_plain_user_403(plain_client):
    resp = plain_client.get(reverse('ai_dashboard', args=[CHK]))
    assert resp.status_code == 403


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_dashboard_allowed_for_superuser(su_client):
    """Superuser fast-path also satisfies require_permission('admin.ai.view')."""
    AIEnrichment.objects.create(MD5=CHK, STATUS='done', MODEL_USED='granite4:3b')
    resp = su_client.get(reverse('ai_dashboard', args=[CHK]))
    assert resp.status_code == 200


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=False)
def test_ai_dashboard_admin_disabled_status(admin_client):
    # AI off -> no report -> dashboard disabled -> operator bounced to scans.
    resp = admin_client.get(reverse('ai_dashboard', args=[CHK]))
    assert resp.status_code == 302
    assert reverse('recent') in resp.url


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_dashboard_admin_none_status(admin_client):
    # No enrichment row (model never ran) -> cannot enter -> redirect.
    resp = admin_client.get(reverse('ai_dashboard', args=[CHK]))
    assert resp.status_code == 302
    assert reverse('recent') in resp.url


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_dashboard_admin_done_status_escapes_hostile_payload(admin_client):
    """A malicious AI-derived (i.e. attacker-influenced app content) summary
    must render HTML-escaped, never raw — the page must never use |safe."""
    payload = '<script>alert(document.cookie)</script>'
    AIEnrichment.objects.create(
        MD5=CHK,
        STATUS='done',
        EXEC_SUMMARY=payload,
        FINDING_EXPLANATIONS=str([
            {'heading': payload, 'body': payload},
        ]),
        SECRETS_TRIAGE=payload,
        MODEL_USED='granite4:3b',
    )
    resp = admin_client.get(reverse('ai_dashboard', args=[CHK]))
    assert resp.status_code == 200
    assert resp.context['ai_page_status'] == 'done'
    body = resp.content.decode('utf-8')
    # Never present raw — would be a stored-XSS if it were.
    assert payload not in body
    # Must be present HTML-escaped (autoescaped Django output).
    assert '&lt;script&gt;' in body


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_dashboard_admin_pending_status(admin_client):
    AIEnrichment.objects.create(MD5=CHK, STATUS='pending')
    resp = admin_client.get(reverse('ai_dashboard', args=[CHK]))
    assert resp.status_code == 200
    assert resp.context['ai_page_status'] == 'pending'


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_dashboard_admin_failed_status(admin_client):
    # Report generation failed -> dashboard disabled -> redirect, cannot enter.
    AIEnrichment.objects.create(MD5=CHK, STATUS='failed')
    resp = admin_client.get(reverse('ai_dashboard', args=[CHK]))
    assert resp.status_code == 302
    assert reverse('recent') in resp.url


@pytest.mark.django_db
def test_ai_dashboard_exception_path_redirects_out(admin_client, monkeypatch):
    """Any unexpected exception building context must redirect out, never 500."""
    def _boom(_checksum):
        raise RuntimeError('boom')

    monkeypatch.setattr(views, '_enrichment_ctx', _boom)
    resp = admin_client.get(reverse('ai_dashboard', args=[CHK]))
    assert resp.status_code == 302
    assert reverse('recent') in resp.url


# ═══════════════════════════════════════════════ ai_report — htmx partial
@pytest.mark.django_db
def test_ai_report_anonymous_redirects_to_login(client):
    resp = client.get(reverse('ai_report', args=[CHK]))
    assert resp.status_code == 302
    assert 'login' in resp['Location']


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_report_non_admin_always_204_never_a_403_fragment(plain_client):
    """The whole point of the htmx endpoint: a non-admin NEVER sees a 403
    fragment (which would leak that AI exists / leak partial HTML) — just
    silence, even though data exists for this checksum."""
    AIEnrichment.objects.create(
        MD5=CHK, STATUS='done', EXEC_SUMMARY='top secret exec summary')
    resp = plain_client.get(reverse('ai_report', args=[CHK]))
    assert resp.status_code == 204
    assert resp.content == b''
    assert b'top secret exec summary' not in resp.content


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=False)
def test_ai_report_admin_204_when_ai_disabled(admin_client):
    resp = admin_client.get(reverse('ai_report', args=[CHK]))
    assert resp.status_code == 204


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_report_admin_204_for_invalid_checksum_via_direct_call(ai_admin):
    """URL routing itself enforces ^[0-9a-f]{32}$ on `checksum`, so the
    'invalid' branch inside ai_report can't be reached through the real
    router with a malformed value. Call the (still fully decorated) view
    directly with a RequestFactory request to exercise that branch — no
    template render happens on this path (plain 204), so no middleware is
    required beyond `request.user`."""
    rf = RequestFactory()
    req = rf.get('/ai/report/not-a-checksum/')
    req.user = ai_admin
    resp = views.ai_report(req, 'not-a-checksum<script>')
    assert resp.status_code == 204


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_report_admin_pending_state_when_no_row_yet(admin_client):
    """status == 'none' renders the partial with a synthetic pending state
    (keeps polling) rather than 204, to avoid a hidden-until-reload race."""
    resp = admin_client.get(reverse('ai_report', args=[CHK]))
    assert resp.status_code == 200
    body = resp.content.decode('utf-8')
    assert 'ai-analysis' in body
    assert f'/ai/report/{CHK}/' in body
    assert 'hx-trigger="load delay:5s"' in body


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
@pytest.mark.parametrize('raw_status', ['pending', 'running'])
def test_ai_report_admin_analyzing_state(admin_client, raw_status):
    AIEnrichment.objects.create(MD5=CHK, STATUS=raw_status)
    resp = admin_client.get(reverse('ai_report', args=[CHK]))
    assert resp.status_code == 200
    assert b'Analyzing the complete static-analysis results' in resp.content


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_report_admin_failed_state(admin_client):
    AIEnrichment.objects.create(MD5=CHK, STATUS='failed')
    resp = admin_client.get(reverse('ai_report', args=[CHK]))
    assert resp.status_code == 200
    assert b'AI analysis is currently unavailable' in resp.content


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_report_admin_done_state_renders_and_escapes(admin_client):
    payload = '<img src=x onerror=alert(1)>'
    AIEnrichment.objects.create(
        MD5=CHK,
        STATUS='done',
        EXEC_SUMMARY='Clean summary.',
        FINDING_EXPLANATIONS=str([
            {'heading': payload, 'body': 'Body text with ' + payload},
        ]),
        SECRETS_TRIAGE='no secrets found',
        MODEL_USED='granite4:3b',
    )
    resp = admin_client.get(reverse('ai_report', args=[CHK]))
    assert resp.status_code == 200
    body = resp.content.decode('utf-8')
    assert payload not in body
    assert '&lt;img src=x onerror=alert(1)&gt;' in body
    assert 'granite4:3b' in body


@pytest.mark.django_db
def test_ai_report_admin_exception_path_returns_204(admin_client, monkeypatch):
    """Any unexpected exception must degrade to silent 204, never a 500 and
    never a partially-rendered fragment."""
    def _boom(_checksum):
        raise RuntimeError('boom')

    monkeypatch.setattr(views, '_enrichment_ctx', _boom)
    resp = admin_client.get(reverse('ai_report', args=[CHK]))
    assert resp.status_code == 204


@pytest.mark.django_db
def test_ai_report_superuser_disabled_is_still_204(su_client):
    """Superuser satisfies _is_ai_admin via the RBAC superuser fast-path
    (independent of the require_permission-gated ai_dashboard route), but
    that alone doesn't manufacture content: AI disabled still means 204."""
    with override_settings(MOBINSPECT_AI_ENABLED=False):
        resp = su_client.get(reverse('ai_report', args=[CHK]))
    assert resp.status_code == 204


@pytest.mark.django_db
def test_ai_report_superuser_enabled_gets_real_content(su_client):
    """Superuser + AI enabled + a real row -> 200 with rendered content,
    exercising the ai_report path end-to-end for the superuser fast-path
    (distinct from the RBAC-role-based admin_client coverage above)."""
    with override_settings(MOBINSPECT_AI_ENABLED=True):
        AIEnrichment.objects.create(
            MD5=CHK, STATUS='done', EXEC_SUMMARY='ok', MODEL_USED='granite4:3b')
        resp = su_client.get(reverse('ai_report', args=[CHK]))
    assert resp.status_code == 200
    assert b'granite4:3b' in resp.content


# ═══════════════════════════════════════════════ template hygiene (never |safe)
def test_templates_never_use_safe_filter_or_mark_safe():
    """Static, source-level guardrail: the two templates this module renders
    must never mark AI-derived (untrusted, model-generated-from-attacker-
    controlled-app-content) values as safe. A future edit that adds `|safe`
    or `{% autoescape off %}` around ai_summary/ai_findings/ai_secrets would
    reintroduce a stored-XSS primitive; catch it here at the source level so
    it fails even if a future functional test forgets to inject a payload.
    """
    views_dir = inspect.getfile(views)
    # views.py -> .../llm/ -> up to the templates root.
    templates_root = os.path.normpath(
        os.path.join(os.path.dirname(views_dir), '..', '..', '..', '..',
                     'templates', 'static_analysis'))
    for name in ('ai_dashboard.html', '_ai_analysis.html'):
        path = os.path.join(templates_root, name)
        assert os.path.isfile(path), f'expected template not found: {path}'
        with open(path, 'r', encoding='utf-8') as fh:
            body = fh.read()
        # Strip {% comment %}...{% endcomment %} blocks first: this file
        # deliberately documents the "never use |safe" rule in prose inside
        # one, and a bare substring check would flag its own warning text.
        code = re.sub(
            r'{%\s*comment\s*%}.*?{%\s*endcomment\s*%}', '', body,
            flags=re.S)
        assert '|safe' not in code, f'{name} must never use the |safe filter'
        assert 'mark_safe' not in code, f'{name} must never call mark_safe'
        assert 'autoescape off' not in code, (
            f'{name} must never disable autoescaping')


# ═══════════════════════════════════════════════ constants sanity
def test_admin_permission_constant_matches_seeded_catalog():
    """Pins the codename the whole module's security model rests on."""
    assert views._ADMIN_AI_PERM == 'admin.ai.view'


@pytest.mark.django_db
def test_admin_permission_is_seeded_in_catalog():
    """If migration 0002/0010 regress and drop this codename, admin.ai.view
    would resolve to an unassignable permission and silently lock everyone
    out of (or worse, in to) the AI dashboard. Fail loudly here instead."""
    assert Permission.objects.filter(
        codename=views._ADMIN_AI_PERM).exists()


# ═══════════════ render layer: secrets-triage panel + risk chart ════════════
@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_report_renders_secrets_triage_panel(admin_client):
    sentinel = 'SENTINEL-triage-content-4242'
    AIEnrichment.objects.create(
        MD5=CHK, STATUS='done', EXEC_SUMMARY='clean summary',
        FINDING_EXPLANATIONS=str([{'heading': 'H', 'body': 'B'}]),
        SECRETS_TRIAGE=sentinel, MODEL_USED='granite4:3b')
    body = admin_client.get(reverse('ai_report', args=[CHK])).content.decode('utf-8')
    assert sentinel in body                    # the triage content actually renders
    assert 'Secrets triage' in body            # heading
    assert 'classification model' in body      # source label


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_report_hides_secrets_panel_when_empty(admin_client):
    AIEnrichment.objects.create(
        MD5=CHK, STATUS='done', EXEC_SUMMARY='clean',
        FINDING_EXPLANATIONS=str([{'heading': 'Finding H', 'body': 'Finding B'}]),
        SECRETS_TRIAGE='', MODEL_USED='granite4:3b')
    body = admin_client.get(reverse('ai_report', args=[CHK])).content.decode('utf-8')
    assert 'Secrets triage' not in body        # panel hidden
    assert 'Finding B' in body                 # report still renders


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_report_renders_risk_classification_chart(admin_client):
    risk = [
        {'dimension': 'Network Security', 'level': 'critical', 'rationale': 'cleartext-everywhere'},
        {'dimension': 'Permissions', 'level': 'high', 'rationale': ''},
        {'dimension': 'Secrets & Credentials', 'level': 'unknown', 'rationale': ''},
    ]
    AIEnrichment.objects.create(
        MD5=CHK, STATUS='done', EXEC_SUMMARY='clean',
        FINDING_EXPLANATIONS=str([{'heading': 'H', 'body': 'B'}]),
        RISK_CLASSIFICATION=str(risk), MODEL_USED='granite4:3b')
    body = admin_client.get(reverse('ai_report', args=[CHK])).content.decode('utf-8')
    assert 'Risk classification' in body
    assert 'Network Security' in body
    assert 'critical' in body
    assert 'mi-risk-critical' in body          # severity-colored bar class
    assert 'cleartext-everywhere' in body      # rationale rendered


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_report_hides_risk_chart_when_empty(admin_client):
    AIEnrichment.objects.create(
        MD5=CHK, STATUS='done', EXEC_SUMMARY='clean',
        FINDING_EXPLANATIONS=str([{'heading': 'H', 'body': 'B'}]),
        RISK_CLASSIFICATION=str([]), MODEL_USED='granite4:3b')
    body = admin_client.get(reverse('ai_report', args=[CHK])).content.decode('utf-8')
    assert 'Risk classification' not in body


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_report_risk_chart_escapes_hostile_rationale(admin_client):
    payload = '<script>alert(1)</script>'
    AIEnrichment.objects.create(
        MD5=CHK, STATUS='done',
        FINDING_EXPLANATIONS=str([{'heading': 'H', 'body': 'B'}]),
        RISK_CLASSIFICATION=str([
            {'dimension': 'Network Security', 'level': 'high', 'rationale': payload}]),
        MODEL_USED='granite4:3b')
    body = admin_client.get(reverse('ai_report', args=[CHK])).content.decode('utf-8')
    assert payload not in body
    assert '&lt;script&gt;' in body            # autoescaped, never raw


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_risk_for_display_maps_pct_and_tone():
    AIEnrichment.objects.create(
        MD5=CHK, STATUS='done',
        RISK_CLASSIFICATION=str([
            {'dimension': 'Network Security', 'level': 'critical', 'rationale': 'x'},
            {'dimension': 'Permissions', 'level': 'unknown', 'rationale': ''},
        ]))
    _, ctx = views._enrichment_ctx(CHK)
    by = {r['dimension']: r for r in ctx['ai_risk']}
    assert by['Network Security']['tone'] == 'critical'
    assert by['Network Security']['pct'] == 100
    assert by['Permissions']['tone'] == 'neutral'   # 'unknown' -> neutral bar


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_risk_for_display_handles_offmap_and_malformed_entries():
    AIEnrichment.objects.create(
        MD5=CHK, STATUS='done',
        RISK_CLASSIFICATION=str([
            {'dimension': 'Network Security', 'level': 'weird-level', 'rationale': 'x'},
            'not-a-dict',                        # non-dict entry -> skipped
            {'dimension': 'Permissions'},        # no 'level' key -> unknown
        ]))
    _, ctx = views._enrichment_ctx(CHK)
    dims = {r['dimension']: r for r in ctx['ai_risk']}
    assert dims['Network Security']['tone'] == 'neutral'   # off-map -> neutral
    assert dims['Network Security']['pct'] == 4
    assert dims['Network Security']['level'] == 'weird-level'  # preserved
    assert dims['Permissions']['level'] == 'unknown'
    assert len(ctx['ai_risk']) == 2                        # non-dict skipped


# ═══════════════════ risk score + anomalies + dashboard gating ══════════════
def test_risk_score_aggregates_classified_levels():
    assert views._risk_score([{'level': 'critical'}, {'level': 'medium'}]) == 75
    assert views._risk_score([{'level': 'high'}, {'level': 'unknown'}]) == 75  # unknown excl
    assert views._risk_score([{'level': 'unknown'}]) is None
    assert views._risk_score([]) is None
    assert views._risk_score(['not-a-dict']) is None


def test_score_tone_thresholds():
    assert views._score_tone(None) == 'neutral'
    assert views._score_tone(10) == 'passed'
    assert views._score_tone(30) == 'medium'
    assert views._score_tone(60) == 'high'
    assert views._score_tone(90) == 'critical'


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_dashboard_done_renders_risk_score_dial(admin_client):
    AIEnrichment.objects.create(
        MD5=CHK, STATUS='done',
        RISK_CLASSIFICATION=str([
            {'dimension': 'Network Security', 'level': 'critical', 'rationale': 'x'},
            {'dimension': 'Permissions', 'level': 'high', 'rationale': ''},
            {'dimension': 'Code Security', 'level': 'medium', 'rationale': ''},
        ]), MODEL_USED='granite4:3b')
    body = admin_client.get(reverse('ai_dashboard', args=[CHK])).content.decode('utf-8')
    assert 'AI risk score' in body
    assert '/100' in body
    assert '75' in body                 # (100+75+50)/3
    assert 'mi-score-critical' in body  # 75 -> critical tone


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_report_renders_anomalies_and_escapes(admin_client):
    payload = '<script>alert(1)</script>'
    AIEnrichment.objects.create(
        MD5=CHK, STATUS='done',
        FINDING_EXPLANATIONS=str([{'heading': 'H', 'body': 'B'}]),
        ANOMALIES=str([{'anomaly': 'surveillance-combo ' + payload,
                        'suggestion': 'drop unused perms'}]),
        MODEL_USED='granite4:3b')
    body = admin_client.get(reverse('ai_report', args=[CHK])).content.decode('utf-8')
    assert 'Anomalies' in body
    assert 'surveillance-combo' in body and 'drop unused perms' in body
    assert payload not in body and '&lt;script&gt;' in body


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_dashboard_ready_tag_hidden_then_shown():
    from mobinspect.StaticAnalyzer.templatetags.ai_tags import ai_dashboard_ready
    assert ai_dashboard_ready(CHK) is False           # no row -> hidden
    AIEnrichment.objects.create(MD5=CHK, STATUS='failed')
    assert ai_dashboard_ready(CHK) is False           # failed -> hidden
    AIEnrichment.objects.filter(MD5=CHK).update(STATUS='done')
    assert ai_dashboard_ready(CHK) is True             # done -> shown


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=False)
def test_ai_dashboard_ready_tag_false_when_ai_disabled():
    from mobinspect.StaticAnalyzer.templatetags.ai_tags import ai_dashboard_ready
    AIEnrichment.objects.create(MD5=CHK, STATUS='done')
    assert ai_dashboard_ready(CHK) is False


# ═══════════ manual "Run AI analysis" trigger: _both_roles_configured ═══════
def _configure_both_roles(**overrides):
    defaults = {'base_url': 'http://127.0.0.1:11434', 'model_name': 'granite4:3b'}
    defaults.update(overrides)
    ModelIntegration.objects.create(
        role=ModelIntegration.ROLE_GENERATE, label='Generation model', **defaults)
    ModelIntegration.objects.create(
        role=ModelIntegration.ROLE_CLASSIFY, label='Classification model', **defaults)


@pytest.mark.django_db
def test_both_roles_configured_false_with_no_rows():
    assert views._both_roles_configured() is False


@pytest.mark.django_db
def test_both_roles_configured_false_with_only_one_role():
    ModelIntegration.objects.create(
        role=ModelIntegration.ROLE_GENERATE,
        base_url='http://127.0.0.1:11434', model_name='granite4:3b')
    assert views._both_roles_configured() is False


@pytest.mark.django_db
def test_both_roles_configured_true_when_both_active():
    _configure_both_roles()
    assert views._both_roles_configured() is True


@pytest.mark.django_db
def test_both_roles_configured_false_when_one_role_inactive():
    """is_active is scoped per-role — deactivating just the classify row must
    fail the check even though generate is still fully configured."""
    _configure_both_roles()
    ModelIntegration.objects.filter(
        role=ModelIntegration.ROLE_CLASSIFY).update(is_active=False)
    assert views._both_roles_configured() is False


@pytest.mark.django_db
def test_both_roles_configured_false_when_model_name_blank():
    _configure_both_roles()
    ModelIntegration.objects.filter(
        role=ModelIntegration.ROLE_CLASSIFY).update(model_name='')
    assert views._both_roles_configured() is False


@pytest.mark.django_db
def test_both_roles_configured_false_when_base_url_blank():
    _configure_both_roles()
    ModelIntegration.objects.filter(
        role=ModelIntegration.ROLE_GENERATE).update(base_url='')
    assert views._both_roles_configured() is False


# ═══════════════════════════════════════ _report_exists
@pytest.mark.django_db
def test_report_exists_false_when_no_scan_row():
    assert views._report_exists(CHK) is False


@pytest.mark.django_db
def test_report_exists_true_for_android_row():
    StaticAnalyzerAndroid.objects.create(MD5=CHK, FILE_NAME='a.apk')
    assert views._report_exists(CHK) is True


@pytest.mark.django_db
def test_report_exists_true_for_ios_row():
    StaticAnalyzerIOS.objects.create(MD5=CHK, FILE_NAME='a.ipa')
    assert views._report_exists(CHK) is True


# ═══════════════════════════════════════ ai_run_status
@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=False)
def test_ai_run_status_unavailable_when_ai_disabled():
    assert views.ai_run_status(CHK) == 'unavailable'


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_run_status_unavailable_without_a_report():
    _configure_both_roles()
    assert views.ai_run_status(CHK) == 'unavailable'


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_run_status_unavailable_without_both_roles():
    StaticAnalyzerAndroid.objects.create(MD5=CHK, FILE_NAME='a.apk')
    assert views.ai_run_status(CHK) == 'unavailable'


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_run_status_unavailable_for_bad_checksum():
    _configure_both_roles()
    assert views.ai_run_status('not-a-checksum-at-all') == 'unavailable'


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_run_status_ready_when_everything_configured_and_no_row_yet():
    StaticAnalyzerAndroid.objects.create(MD5=CHK, FILE_NAME='a.apk')
    _configure_both_roles()
    assert views.ai_run_status(CHK) == 'ready'


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
@pytest.mark.parametrize('prior_status', ['done', 'failed'])
def test_ai_run_status_ready_after_a_prior_run_finished(prior_status):
    StaticAnalyzerAndroid.objects.create(MD5=CHK, FILE_NAME='a.apk')
    _configure_both_roles()
    AIEnrichment.objects.create(MD5=CHK, STATUS=prior_status)
    assert views.ai_run_status(CHK) == 'ready'


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
@pytest.mark.parametrize('in_flight_status', ['pending', 'running'])
def test_ai_run_status_running_when_already_in_flight(in_flight_status):
    """Must never offer a duplicate trigger while one is still going."""
    StaticAnalyzerAndroid.objects.create(MD5=CHK, FILE_NAME='a.apk')
    _configure_both_roles()
    AIEnrichment.objects.create(MD5=CHK, STATUS=in_flight_status)
    assert views.ai_run_status(CHK) == 'running'


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_run_status_never_raises_on_unexpected_error(monkeypatch):
    StaticAnalyzerAndroid.objects.create(MD5=CHK, FILE_NAME='a.apk')
    _configure_both_roles()

    def _boom(*a, **kw):
        raise RuntimeError('boom')

    monkeypatch.setattr(AIEnrichment.objects, 'filter', _boom)
    assert views.ai_run_status(CHK) == 'unavailable'


# ═══════════════════════════ ai_run view (POST-only manual trigger)
_TASKS_MODULE = 'mobinspect.StaticAnalyzer.views.common.llm.tasks.enrich_in_background'


@pytest.mark.django_db
def test_ai_run_anonymous_redirects_to_login(client):
    resp = client.post(reverse('ai_run', args=[CHK]))
    assert resp.status_code == 302
    assert 'login' in resp['Location']


@pytest.mark.django_db
def test_ai_run_denied_for_plain_user_403(plain_client):
    resp = plain_client.post(reverse('ai_run', args=[CHK]))
    assert resp.status_code == 403


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_run_get_request_never_triggers_enrichment(admin_client, monkeypatch):
    StaticAnalyzerAndroid.objects.create(MD5=CHK, FILE_NAME='a.apk')
    _configure_both_roles()
    mock_enrich = MagicMock()
    monkeypatch.setattr(_TASKS_MODULE, mock_enrich)
    resp = admin_client.get(reverse('ai_run', args=[CHK]))
    assert resp.status_code == 302
    mock_enrich.assert_not_called()


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_run_not_ready_shows_error_and_never_enriches(admin_client, monkeypatch):
    # AI enabled but neither role configured -> ai_run_status != 'ready'.
    mock_enrich = MagicMock()
    monkeypatch.setattr(_TASKS_MODULE, mock_enrich)
    resp = admin_client.post(reverse('ai_run', args=[CHK]), follow=True)
    assert resp.status_code == 200
    mock_enrich.assert_not_called()
    msgs = [str(m) for m in resp.context['messages']]
    assert any('not available' in m for m in msgs)


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_run_ready_triggers_enrichment_and_audits(admin_client, monkeypatch):
    StaticAnalyzerAndroid.objects.create(MD5=CHK, FILE_NAME='a.apk')
    _configure_both_roles()
    mock_enrich = MagicMock()
    monkeypatch.setattr(_TASKS_MODULE, mock_enrich)
    resp = admin_client.post(reverse('ai_run', args=[CHK]))
    assert resp.status_code == 302
    mock_enrich.assert_called_once_with(CHK)
    assert AuditEvent.objects.filter(
        action='ai.run.manual', target_id=CHK).exists()


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_run_wont_duplicate_while_already_running(admin_client, monkeypatch):
    StaticAnalyzerAndroid.objects.create(MD5=CHK, FILE_NAME='a.apk')
    _configure_both_roles()
    AIEnrichment.objects.create(MD5=CHK, STATUS='running')
    mock_enrich = MagicMock()
    monkeypatch.setattr(_TASKS_MODULE, mock_enrich)
    resp = admin_client.post(reverse('ai_run', args=[CHK]), follow=True)
    mock_enrich.assert_not_called()
    msgs = [str(m) for m in resp.context['messages']]
    assert any('not available' in m for m in msgs)


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_run_redirects_back_to_a_safe_referer(admin_client, monkeypatch):
    StaticAnalyzerAndroid.objects.create(MD5=CHK, FILE_NAME='a.apk')
    _configure_both_roles()
    monkeypatch.setattr(_TASKS_MODULE, MagicMock())
    resp = admin_client.post(
        reverse('ai_run', args=[CHK]),
        HTTP_REFERER=f'/static_analyzer/{CHK}/')
    assert resp.status_code == 302
    assert resp.url == f'/static_analyzer/{CHK}/'


@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_run_falls_back_to_recent_for_an_unsafe_referer(admin_client, monkeypatch):
    """A referer pointing off-host must never be followed — falls back to
    the Recent Scans page instead of an open redirect."""
    StaticAnalyzerAndroid.objects.create(MD5=CHK, FILE_NAME='a.apk')
    _configure_both_roles()
    monkeypatch.setattr(_TASKS_MODULE, MagicMock())
    resp = admin_client.post(
        reverse('ai_run', args=[CHK]),
        HTTP_REFERER='http://evil.example.com/phish')
    assert resp.status_code == 302
    assert reverse('recent') in resp.url


# ═══════════════════════════ ai_tags.ai_run_status wrapper tag
@pytest.mark.django_db
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_ai_run_status_tag_matches_the_view_helper():
    from mobinspect.StaticAnalyzer.templatetags.ai_tags import (
        ai_run_status as tag_ai_run_status,
    )
    assert tag_ai_run_status(CHK) == 'unavailable'
    StaticAnalyzerAndroid.objects.create(MD5=CHK, FILE_NAME='a.apk')
    _configure_both_roles()
    assert tag_ai_run_status(CHK) == 'ready'


@pytest.mark.django_db
def test_ai_run_status_tag_never_raises(monkeypatch):
    from mobinspect.StaticAnalyzer.templatetags import ai_tags

    def _boom(_checksum):
        raise RuntimeError('boom')

    monkeypatch.setattr(ai_tags, '_ai_run_status', _boom)
    assert ai_tags.ai_run_status(CHK) == 'unavailable'
