"""
MobInspect — design system playground.

DEBUG-only route used to verify the design tokens, components, and
theme behavior. Returns 404 in production.
"""
import os

from django.conf import settings
from django.http import Http404
from django.shortcuts import render


def playground(request):
    # Defense in depth: require both DEBUG and the explicit env opt-in flag,
    # AND require the user to be a superuser. Operators occasionally toggle
    # DEBUG on production during incidents — that alone must not expose us.
    enabled = (
        settings.DEBUG
        and os.environ.get('MOBINSPECT_ENABLE_PLAYGROUND', '0') == '1'
    )
    if not enabled:
        raise Http404
    if request.user.is_authenticated and not request.user.is_superuser:
        raise Http404
    context = {
        'title': 'Playground',
        'version': getattr(settings, 'VERSION', ''),
        'kpis': [
            {'label': 'Total scans',       'value': '1,247', 'delta': '12%', 'up': True,  'subtitle': 'last 7 days'},
            {'label': 'Critical findings', 'value': '34',    'delta': '8%',  'up': False, 'subtitle': 'last 7 days'},
            {'label': 'Avg AppSec score',  'value': '72',    'delta': '3',   'up': True,  'subtitle': 'out of 100'},
            {'label': 'Scans this week',   'value': '47',    'delta': '5',   'up': True,  'subtitle': 'vs same period'},
        ],
        'findings': [
            {'severity': 'critical', 'rule': 'Hardcoded API key in source',     'location': 'src/auth/Token.java:42',         'cwe': 'CWE-798'},
            {'severity': 'high',     'rule': 'Insecure SSLContext (TLSv1)',     'location': 'src/net/HttpClient.java:118',    'cwe': 'CWE-326'},
            {'severity': 'high',     'rule': 'WebView allows file:// access',   'location': 'src/ui/AboutActivity.java:71',   'cwe': 'CWE-749'},
            {'severity': 'medium',   'rule': 'World-readable shared prefs',     'location': 'AndroidManifest.xml',            'cwe': 'CWE-732'},
            {'severity': 'low',      'rule': 'Debuggable application',          'location': 'AndroidManifest.xml',            'cwe': 'CWE-489'},
            {'severity': 'passed',   'rule': 'App signed with v3 signature',    'location': 'META-INF/CERT.SF',               'cwe': '—'},
        ],
    }
    return render(request, 'playground.html', context)
