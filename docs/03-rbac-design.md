# 03 — RBAC Design

## Goal

Replace the current 2-role / 3-permission model with a **dynamic, industry-standard RBAC** layer where:

- Admins create, edit, and delete roles in the product UI (no code changes, no migrations)
- Permissions are a curated, granular catalog covering every meaningful action
- Roles bundle permissions; users hold one or more roles
- Enforcement is **uniform** across web views, REST API, and template-level UI hiding
- Defaults ship out of the box so the product is usable on day one

## Current state (upstream MobSF)

`mobsf/MobSF/views/authorization.py:38-50` defines:

```python
PERM_CAN_SCAN = 'can_scan'
PERM_CAN_SUPPRESS = 'can_suppress'
PERM_CAN_DELETE = 'can_delete'

class Permissions(Enum):
    SCAN = 'StaticAnalyzer.can_scan'
    SUPPRESS = 'StaticAnalyzer.can_suppress'
    DELETE = 'StaticAnalyzer.can_delete'
```

Roles (Django `Group`s):
- **Maintainer** — gets all three permissions
- **Viewer** — read-only

Roles are populated from SAML group claims (`MOBSF_IDP_MAINTAINER_GROUP`, `MOBSF_IDP_VIEWER_GROUP`) or manually via the rudimentary `users.html` UI. There is no role CRUD, no custom roles, no permission discovery.

## Target state (MobInspect)

### Conceptual model

```
┌───────┐ * ┌──────────────────┐ *  ┌──────┐ * ┌──────────────┐
│ User  │───│ RoleAssignment    │────│ Role │───│  Permission  │
└───────┘    └──────────────────┘    └──────┘    └──────────────┘
                  │                       │              │
                  ▼                       ▼              ▼
             granted_by              system flag   codename, name,
             granted_at              color/icon    category, scope
             expires_at?
```

### Models

```python
# mobinspect/RBAC/models.py

class Permission(models.Model):
    """
    Catalog entry. Seeded via data migration; admins cannot create
    new permissions because permissions are tied to code paths.
    """
    codename = models.SlugField(max_length=100, unique=True)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=50, db_index=True)
    # e.g. 'scan', 'report', 'admin', 'api', 'rbac', 'integration'
    scope = models.CharField(max_length=20, default='action')
    # 'action' (do something) | 'resource' (see something)
    is_dangerous = models.BooleanField(default=False)
    # UI flag — show with red badge in the role editor

    class Meta:
        ordering = ['category', 'codename']

class Role(models.Model):
    """
    A named bundle of permissions. Wraps a Django Group for
    interop with existing decorators.
    """
    group = models.OneToOneField(
        'auth.Group',
        on_delete=models.CASCADE,
        related_name='role',
    )
    name = models.CharField(max_length=80, unique=True)
    description = models.TextField(blank=True)
    color = models.CharField(max_length=7, default='#64748B')  # slate-500
    icon = models.CharField(max_length=40, default='shield')   # Lucide name
    is_system = models.BooleanField(default=False)
    # System roles cannot be deleted or renamed; permissions can still be edited
    permissions = models.ManyToManyField(Permission, related_name='roles')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class RoleAssignment(models.Model):
    """
    A user holds one or more roles. Multiple roles → union of permissions.
    """
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE,
                             related_name='role_assignments')
    role = models.ForeignKey(Role, on_delete=models.CASCADE,
                             related_name='assignments')
    granted_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL,
                                    null=True, related_name='+')
    granted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    # Optional time-bound access — useful for contractors

    class Meta:
        unique_together = [('user', 'role')]
```

### Why wrap Django `Group` instead of replacing it?

- Existing decorators like `@permission_required` keep working unchanged
- Django admin (if ever re-enabled) shows familiar UI
- SAML group → role mapping is trivial: lookup `Group` by name, follow `.role`
- Easier upstream merges: we don't fork Django's auth model

### Permission catalog (initial)

Seeded by `mobinspect/RBAC/migrations/0002_seed_permissions.py`:

| Category | Codename | Description | Dangerous |
|----------|----------|-------------|-----------|
| **scan** | `scan.create` | Upload binaries and start static/dynamic scans | |
| scan | `scan.view` | View any scan and its report | |
| scan | `scan.view_own` | View only scans I uploaded | |
| scan | `scan.delete` | Delete scans | ✓ |
| scan | `scan.rescan` | Re-run analysis on an existing scan | |
| scan | `scan.export.pdf` | Download PDF reports | |
| scan | `scan.export.json` | Download JSON reports | |
| **finding** | `finding.suppress` | Mark findings as suppressed | |
| finding | `finding.unsuppress` | Reverse a suppression | |
| finding | `finding.comment` | Add comments to findings | |
| **dynamic** | `dynamic.android.run` | Run Android dynamic analysis | |
| dynamic | `dynamic.ios.run` | Run iOS dynamic analysis | |
| dynamic | `dynamic.frida.script` | Upload custom Frida scripts | ✓ |
| **integration** | `integration.virustotal.use` | Submit hashes to VirusTotal | |
| integration | `integration.virustotal.upload` | Upload binaries to VirusTotal | ✓ |
| integration | `integration.malware.lookup` | Use external malware DBs | |
| **api** | `api.use` | Use REST API at all | |
| api | `api.key.create` | Create new API keys for self | |
| api | `api.key.create_for_others` | Create keys on behalf of other users | ✓ |
| **analytics** | `analytics.view` | See the analytics dashboard | |
| analytics | `analytics.export` | Export analytics data | |
| **admin** | `admin.user.view` | List users | |
| admin | `admin.user.create` | Create new users | ✓ |
| admin | `admin.user.delete` | Delete users | ✓ |
| admin | `admin.user.reset_password` | Reset another user's password | ✓ |
| **rbac** | `rbac.role.view` | List roles and their permissions | |
| rbac | `rbac.role.manage` | Create, edit, delete roles & assignments | ✓ |
| **settings** | `settings.view` | View global settings | |
| settings | `settings.manage` | Modify global settings | ✓ |

This is the v1 catalog. Adding a permission later = data migration + decorator on the new endpoint. Removing one = data migration that removes role mappings.

### Default seeded roles

| Role | System | Permissions |
|------|--------|-------------|
| **Administrator** | ✓ | Everything |
| **Security Analyst** | ✓ | All `scan.*`, `finding.*`, `dynamic.*`, `analytics.view`, `api.use`, `api.key.create`, `integration.*` (except upload) |
| **Viewer** | ✓ | `scan.view`, `scan.export.pdf`, `scan.export.json`, `analytics.view` |
| **API User** | ✓ | `api.use`, `scan.create`, `scan.view`, `scan.export.json`, `finding.suppress` |

System roles are immutable in identity (cannot be deleted/renamed) but their permission sets can be edited by any user with `rbac.role.manage`.

### Enforcement points

#### 1. View decorators

```python
from mobinspect.RBAC.decorators import require_permission

@require_permission('scan.create')
def upload(request):
    ...
```

Replaces today's `@permission_required(Permissions.SCAN)`. The new decorator:
- Honors `settings.DISABLE_AUTHENTICATION` (dev only)
- Honors `request.api` (delegates to API middleware)
- Returns **403 with structured JSON** for API, **403 page** for web
- Logs denial events to a new `audit_log` table for compliance

#### 2. API middleware

`mobinspect/MobInspect/middleware/api.py` (was `views/api/api_middleware.py`):
- Resolves API key → user → roles → permission set (cached per request)
- Each `@api_view` declares required permissions; middleware enforces

#### 3. Template tags

```django
{% load rbac %}

{% can 'scan.create' %}
  <a href="{% url 'upload' %}" class="btn btn-primary">New Scan</a>
{% endcan %}

{% has_role 'Administrator' as is_admin %}
{% if is_admin %}
  ...
{% endif %}
```

No more permission-shaped holes in the UI: buttons users can't use simply aren't rendered.

#### 4. Context processor

`mobinspect.RBAC.context.rbac_context` injects on every template render:
- `request.user.permissions_set` — frozenset of codenames the user has
- `request.user.role_names` — for badge display in the topbar

### Audit log

```python
class AuditEvent(models.Model):
    actor = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=80, db_index=True)
    # 'role.create', 'role.delete', 'role.assign', 'role.unassign',
    # 'permission.grant', 'permission.revoke', 'denied.<perm>'
    target_type = models.CharField(max_length=50, blank=True)
    target_id = models.CharField(max_length=80, blank=True)
    metadata = models.JSONField(default=dict)
    ip_address = models.GenericIPAddressField(null=True)
    user_agent = models.CharField(max_length=400, blank=True)
    occurred_at = models.DateTimeField(auto_now_add=True, db_index=True)
```

Surfaces in Settings → Audit Log, filterable by actor / action / date.

### Data migration plan

1. **0001_initial** — create `Role`, `Permission`, `RoleAssignment`, `AuditEvent` tables
2. **0002_seed_permissions** — populate the catalog above
3. **0003_seed_default_roles** — create the four system roles + their permission mappings
4. **0004_migrate_existing_users** — every user with `is_staff=True` → Administrator; everyone else → Viewer; existing Maintainer/Viewer Django Groups → matched to new system roles by name
5. **0005_link_existing_groups** — `Group.role` OneToOne backfilled

### What about object-level permissions?

Out of scope. If two analysts can both `scan.view`, they both see all scans. We may add ownership checks (`scan.view_own`) as a permission, but enforced at the queryset level, not via `django-guardian`. If true row-level isolation becomes a requirement, we'll revisit with an ADR.

### What about API keys per user?

Today, MobSF stores a single global API key. In Phase 1 we make API keys per-user, with the key inheriting the user's roles. This unlocks revocable per-user API access without code changes.

```python
class ApiKey(models.Model):
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    name = models.CharField(max_length=80)  # human label, e.g. "ci-pipeline"
    key_hash = models.CharField(max_length=128)  # hashed at rest
    last_used_at = models.DateTimeField(null=True)
    expires_at = models.DateTimeField(null=True)
    revoked_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
```

### Open questions (track in ADRs as decided)

- **Multi-role users** — union of permissions, agreed. What about conflicting expirations? → Most-recent expiry wins, document this.
- **Role hierarchy / inheritance** — *Not in v1.* Composing roles is more flexible than inheritance and easier for analysts to reason about.
- **Per-app permissions** — should "Security Analyst" be scoped to a specific app/team? *Not in v1.* If demand emerges, we add a `RoleAssignment.scope` JSON field, not a new model.
