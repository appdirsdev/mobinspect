"""
MobInspect — RBAC template context processor.

Adds:
  mi_permissions  — request.mi_permissions (or empty set)
  mi_roles        — request.mi_roles (or empty list)
  mi_is_admin     — convenience: True if user holds 'Administrator' role
"""


def rbac_context(request):
    perms = getattr(request, 'mi_permissions', None)
    roles = getattr(request, 'mi_roles', None)
    return {
        'mi_permissions': perms if perms is not None else frozenset(),
        'mi_roles':       roles if roles is not None else [],
        'mi_is_admin':    bool(roles) and 'Administrator' in roles,
    }
