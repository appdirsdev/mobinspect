# -*- coding: utf_8 -*-
"""Offline-safe client for a local Granite endpoint (Ollama /api/generate).

Every failure path returns None. This client never raises and is never called
on the scan path. Endpoint is operator-configured (MOBINSPECT_AI_BASE_URL) and
pinned to a loopback/private (enclave) host; redirects are refused; the socket
has explicit timeouts and the response body is byte-capped.
"""
import ipaddress
import json
import logging
import socket
from urllib.parse import urlparse

import requests

from django.conf import settings

logger = logging.getLogger(__name__)


def parse_ai_endpoint(url):
    """Parse + validate an AI endpoint URL. Returns the parsed result or None.

    Safe against urlparse().port raising ValueError on non-numeric / out-of-range
    ports (e.g. ':99999', ':abc') — those return None rather than propagating.
    """
    try:
        parsed = urlparse((url or '').strip())
        port = parsed.port  # lazy property; raises ValueError on a bad port
    except ValueError:
        return None
    except Exception:
        return None
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or not port:
        return None
    return parsed


def _host_is_enclave(host):
    """True only if the host resolves exclusively to loopback/private addresses."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    if not infos:
        return False
    for info in infos:
        ip = info[4][0].split('%')[0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.is_link_local or not (addr.is_loopback or addr.is_private):
            return False
    return True


class GraniteClient:
    """Talk to a local Granite model. Returns text or None; never raises."""

    def __init__(self, role='generate'):
        self.enabled = bool(getattr(settings, 'MOBINSPECT_AI_ENABLED', False))
        self.role = role if role in ('generate', 'classify') else 'generate'
        self.base_url, self.model = self._resolve_target(self.role)

    @staticmethod
    def _resolve_target(role='generate'):
        """Endpoint + model for a role: prefer the DB ModelIntegration, else settings.

        Each role (generate / classify) has at most one configured endpoint in
        the Integrations section, which wins over the env/settings fallback.
        Uses apps.get_model so this works whether or not the RBAC
        ModelIntegration model/migration is present yet.
        """
        settings_model = (
            'MOBINSPECT_AI_MODEL_CLASSIFY' if role == 'classify'
            else 'MOBINSPECT_AI_MODEL_GENERATE')
        default_model = getattr(settings, settings_model, 'granite4:3b')
        try:
            from django.apps import apps
            model_cls = apps.get_model('rbac', 'ModelIntegration')
            row = model_cls.objects.filter(role=role, is_active=True).first()
            if row and (row.base_url or '').strip():
                return (row.base_url.strip().rstrip('/'),
                        (row.model_name or '').strip())
            # A classify-only feature with no classify endpoint configured should
            # reuse the generate host (one Ollama serving several models is the
            # common case) rather than dialing the localhost default and failing
            # on every scan.
            if role == 'classify':
                gen = model_cls.objects.filter(
                    role='generate', is_active=True).first()
                if gen and (gen.base_url or '').strip():
                    return (gen.base_url.strip().rstrip('/'), default_model)
        except Exception:
            pass
        return (getattr(settings, 'MOBINSPECT_AI_BASE_URL', '').strip().rstrip('/'),
                default_model)

    def _validate_endpoint(self):
        parsed = parse_ai_endpoint(self.base_url)
        if not parsed:
            return None
        hostport = f'{parsed.hostname}:{parsed.port}'
        allow = getattr(settings, 'MOBINSPECT_AI_ALLOWED_HOSTS', [])
        if allow and hostport not in allow:
            logger.error('AI endpoint %s not in MOBINSPECT_AI_ALLOWED_HOSTS', hostport)
            return None
        if not _host_is_enclave(parsed.hostname):
            logger.error(
                'AI endpoint host %s is not loopback/private; refusing (SSRF guard)',
                parsed.hostname)
            return None
        return parsed

    def generate(self, system, prompt, model=None, num_predict=None):
        """Return the model's text response, or None on any failure."""
        if not self.enabled:
            return None
        if not self._validate_endpoint():
            return None
        model = model or self.model or getattr(
            settings, 'MOBINSPECT_AI_MODEL_GENERATE', 'granite4:3b')
        url = f'{self.base_url}/api/generate'
        payload = {
            'model': model,
            'system': system,
            'prompt': prompt,
            'stream': False,
            # Keep the model resident between calls to avoid reload latency.
            'keep_alive': getattr(settings, 'MOBINSPECT_AI_KEEP_ALIVE', '10m'),
            'options': {
                # Context WINDOW (input+output). Must be large enough for the
                # complete static-analysis prompt or Ollama truncates it.
                'num_ctx': int(getattr(settings, 'MOBINSPECT_AI_NUM_CTX', 8192)),
                # Max tokens to GENERATE.
                'num_predict': int(
                    num_predict or getattr(settings, 'MOBINSPECT_AI_NUM_PREDICT', 768)),
                'temperature': 0.2,
                'top_p': float(getattr(settings, 'MOBINSPECT_AI_TOP_P', 0.9)),
            },
        }
        verify = getattr(settings, 'MOBINSPECT_AI_TLS_VERIFY', True)
        ca_bundle = getattr(settings, 'MOBINSPECT_AI_CA_BUNDLE', '')
        if verify and ca_bundle:
            verify = ca_bundle
        timeout = (
            int(getattr(settings, 'MOBINSPECT_AI_CONNECT_TIMEOUT', 5)),
            int(getattr(settings, 'MOBINSPECT_AI_READ_TIMEOUT', 60)),
        )
        cap = int(getattr(settings, 'MOBINSPECT_AI_MAX_RESPONSE_BYTES', 2 * 1024 * 1024))
        resp = None
        try:
            resp = requests.post(
                url,
                json=payload,
                timeout=timeout,
                stream=True,
                allow_redirects=False,
                verify=verify)
            if resp.status_code in (301, 302, 303, 307, 308):
                logger.error('AI endpoint attempted a redirect; refusing')
                return None
            if resp.status_code != 200:
                logger.error('AI endpoint returned HTTP %s', resp.status_code)
                return None
            raw = bytearray()
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    raw.extend(chunk)
                    if len(raw) > cap:
                        logger.error('AI response exceeded byte ceiling; aborting')
                        return None
            data = json.loads(raw.decode('utf-8', 'ignore'))
            text = data.get('response')
            if not isinstance(text, str) or not text.strip():
                return None
            return text
        except Exception as exp:
            # Never log bodies; only the failure type.
            logger.warning('AI generate failed: %s', type(exp).__name__)
            return None
        finally:
            try:
                if resp is not None:
                    resp.close()
            except Exception:
                pass
