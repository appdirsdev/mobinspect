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

    def __init__(self):
        self.enabled = bool(getattr(settings, 'MOBINSPECT_AI_ENABLED', False))
        self.base_url = getattr(
            settings, 'MOBINSPECT_AI_BASE_URL', '').strip().rstrip('/')

    def _validate_endpoint(self):
        try:
            parsed = urlparse(self.base_url)
        except Exception:
            return None
        if parsed.scheme not in ('http', 'https'):
            return None
        if not parsed.hostname or not parsed.port:
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

    def generate(self, system, prompt, model=None):
        """Return the model's text response, or None on any failure."""
        if not self.enabled:
            return None
        if not self._validate_endpoint():
            return None
        model = model or getattr(
            settings, 'MOBINSPECT_AI_MODEL_GENERATE', 'granite4:8b')
        url = f'{self.base_url}/api/generate'
        payload = {
            'model': model,
            'system': system,
            'prompt': prompt,
            'stream': False,
            'options': {
                'num_predict': int(getattr(settings, 'MOBINSPECT_AI_NUM_PREDICT', 768)),
                'temperature': 0.2,
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
