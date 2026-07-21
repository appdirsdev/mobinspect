"""Shared configuration for the whole tests_e2e suite (UI + API).

Both ``ui/`` and ``api/`` read the same environment variables so a single
target (local dev, a staging box, or a deployed instance) drives the entire
run:

    MOBINSPECT_UI_BASE        base URL of a running server (default 127.0.0.1:8000)
    MOBINSPECT_ADMIN_USERNAME / MOBINSPECT_ADMIN_PASSWORD   admin session creds
    MOBINSPECT_ADMIN_API_KEY  a per-user RBAC API key (mi_... prefix) with the
                              Administrator role — NOT the global sha256 key,
                              which fails every RBAC-gated endpoint.
"""
import os

BASE_URL = os.environ.get('MOBINSPECT_UI_BASE', 'http://127.0.0.1:8000').rstrip('/')
ADMIN_USERNAME = os.environ.get('MOBINSPECT_ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('MOBINSPECT_ADMIN_PASSWORD', 'admin')
ADMIN_API_KEY = os.environ.get('MOBINSPECT_ADMIN_API_KEY', '')
