# ADR 0001 — Use Django Groups as the RBAC foundation

**Status**: Accepted
**Date**: 2026-05-05

## Context

MobInspect needs dynamic, industry-standard RBAC. The candidate approaches are:

1. **Pure Django auth** — `User`, `Group`, `Permission`. Groups serve as roles.
2. **Custom RBAC tables** — `Role`, `Permission`, `RoleAssignment` decoupled from Django auth.
3. **`django-guardian`** — object-level permissions on top of Django auth.
4. **External authz** — OPA, Casbin, etc.

Upstream MobInspect already uses option 1 in a minimal form (`mobinspect/MobInspect/views/authorization.py:38-50`).

## Decision

Adopt a **hybrid**: a thin layer of custom models (`Role`, `Permission`, `RoleAssignment`, `AuditEvent`) where each `Role` **wraps** a Django `Group` via a 1:1 relationship.

- Custom layer carries presentation metadata (color, icon, description, system flag) and product-specific permission catalog
- Django `Group` carries the actual `auth.Permission` set; existing `@permission_required` decorators keep working
- `RoleAssignment` lets us add expiry / audit metadata that Django's plain `User.groups` M2M can't carry

## Consequences

### Pros
- Existing decorators continue to work; reduces refactor blast radius
- SAML group → role mapping is trivial (`Group.objects.get(name=...).role`)
- Familiar to any Django developer; future contributors won't be surprised
- Permissions remain queryable via Django's `user.has_perm('codename')`
- No new dependencies

### Cons
- Two slightly redundant tables (`auth_group_permissions` + our `Role.permissions`). We treat the custom one as the source of truth and sync to Django Groups on save.
- Object-level permissions are not supported (deferred to a future ADR if needed)

## Alternatives considered

### Option 2: Custom RBAC tables, no Django auth
Cleaner conceptually but every existing decorator and SAML hook would need rewriting. Not worth the churn.

### Option 3: django-guardian
Solves a problem we don't have (per-row permissions). Doubles the auth model complexity for users.

### Option 4: External authz
Adds a network hop for every permission check, plus deployment complexity. Overkill for a self-hosted security tool.
