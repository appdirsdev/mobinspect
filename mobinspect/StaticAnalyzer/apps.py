# -*- coding: utf_8 -*-
"""App config for StaticAnalyzer.

Registers the AI-enrichment django-q signal in ready(). The import is guarded
so a problem in the (optional, additive) AI package can never prevent the app
— or the scanner — from starting.
"""
import logging

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class StaticAnalyzerConfig(AppConfig):
    name = 'mobinspect.StaticAnalyzer'

    def ready(self):
        try:
            from mobinspect.StaticAnalyzer.views.common.llm import signals  # noqa: F401
        except Exception:
            logger.exception('AI enrichment signal not registered; continuing')
