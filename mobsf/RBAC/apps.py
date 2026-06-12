"""MobInspect — RBAC app config."""
from django.apps import AppConfig


class RBACConfig(AppConfig):
    default_auto_field = 'django.db.models.AutoField'
    name = 'mobsf.RBAC'
    label = 'rbac'
    verbose_name = 'Role-Based Access Control'

    def ready(self):
        # Register signal receivers at startup. Importing the module is
        # sufficient — the @receiver decorators self-connect. Covers:
        #   * Role/Group sync (RBAC bookkeeping)
        #   * RoleAssignment ↔ User.groups mirroring
        #   * django.contrib.auth login/logout/login-failed audit hooks
        from mobsf.RBAC import signals  # noqa: F401
