"""MobInspect — Analytics app."""
from django.apps import AppConfig


class AnalyticsConfig(AppConfig):
    default_auto_field = 'django.db.models.AutoField'
    name = 'mobsf.Analytics'
    label = 'analytics'
    verbose_name = 'MobInspect Analytics'
