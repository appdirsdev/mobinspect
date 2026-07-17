# 05 — Information Architecture

## Sitemap

```
MobInspect
├── Sign in
│   ├── Username + password
│   ├── SSO (SAML2)
│   ├── Forgot password
│   └── (admin-created accounts only — no public signup)
│
├── Dashboard                       ← landing page after login
│   ├── KPI strip            (4 metrics with deltas)
│   ├── Scan trends          (line chart, 30/60/90d toggle)
│   ├── Severity breakdown   (donut)
│   ├── Top vulnerable apps  (table)
│   ├── Recent activity      (timeline)
│   └── Fleet health         (gauge — % of apps scanned in last 30d)
│
├── Scans
│   ├── New scan             (drag-drop upload, ANDROID/iOS/WINDOWS auto-detect)
│   ├── All scans            (sortable, filterable table)
│   ├── My scans             (filtered to request.user, role-gated)
│   ├── Failed scans         (admin only)
│   └── Scan detail
│       ├── Static report
│       │   ├── App info / certificates
│       │   ├── Permissions
│       │   ├── Code analysis findings
│       │   ├── Binary analysis (native libs)
│       │   ├── Network security
│       │   ├── Trackers / firebase / SBOM
│       │   ├── Source tree browser
│       │   └── Suppressions
│       ├── Dynamic report
│       │   ├── API monitor
│       │   ├── Frida logs
│       │   ├── Logcat / System logs
│       │   └── Screenshots
│       └── AppSec scorecard
│
├── Compare                         ← diff two scans
│
├── Analytics                       (role-gated: analytics.view)
│   ├── Trends                      (line / area, multiple metrics overlaid)
│   ├── Severity over time          (stacked area)
│   ├── Top CWEs                    (bar)
│   ├── Coverage                    (table — apps × last scan age)
│   └── Throughput                  (queue depth, scan duration percentiles)
│
├── Settings
│   ├── My profile
│   ├── My API keys                 (create / revoke)
│   ├── Theme                       (light / dark / system)
│   ├── Notifications
│   ├── ── divider ──
│   ├── Users                       (admin only — admin.user.view)
│   ├── Roles & permissions         (admin only — rbac.role.view)
│   ├── Audit log                   (admin only)
│   ├── Integrations
│   │   ├── VirusTotal
│   │   ├── SAML / SSO
│   │   ├── Upstream proxy
│   │   └── Webhooks                [NEW]
│   ├── 3rd-party tools             (paths to JADX, apktool, etc.)
│   └── About                       (version, system info, license)
│
└── API docs                        (Swagger-style, generated from urls.py)
```

## Navigation model

### Sidebar (left, collapsible)

Always-visible items, ordered by frequency-of-use for the **Security Analyst** role (the most common):

| Icon | Label | Permission | Route |
|------|-------|-----------|-------|
| `gauge` | Dashboard | — (all logged-in users) | `dashboard` |
| `upload` | New Scan | `scan.create` | `upload` |
| `layers` | Scans | `scan.view` or `scan.view_own` | `scans:list` |
| `git-compare` | Compare | `scan.view` | `compare` |
| `bar-chart-3` | Analytics | `analytics.view` | `analytics:trends` |
| — divider — | | | |
| `settings` | Settings | (always visible — children gated) | `settings:profile` |

A search field at the top (`⌘K` / `Ctrl+K`) opens a global command palette: jump to any scan by hash, app name, or finding.

### Topbar (right cluster)

- Notifications bell — recent scan completions, role grants
- Theme toggle (sun / moon / monitor for system)
- User menu — name + role badge → profile, API keys, sign out

### Breadcrumbs

Auto-generated from the URL conf, shown on all pages except Dashboard and auth.

`Scans / com.example.app — abcd1234… / Code analysis`

### Empty states

Every list view ships an empty state:

| View | Empty state copy |
|------|------------------|
| Scans | "No scans yet. Upload an APK, IPA, or AAB to get started." + CTA |
| My scans | "You haven't started any scans. New scan →" |
| Findings | "No findings at this severity. Try widening the filter." |
| Analytics (no data) | "Analytics warm up after your first scan completes." |
| Audit log | "No audit events recorded." |

## Page inventory — current → target

| Current template | Lines | Target page | Phase |
|------------------|-------|-------------|-------|
| `auth/login.html` | — | `auth/sign_in.html` | 2.1 |
| `auth/change_password.html` | — | `settings/security.html` (folded into profile) | 2.1 |
| `auth/register.html` | — | `admin/users/create.html` | 2.1 |
| `auth/users.html` | — | `admin/users/list.html` | 2.1 |
| `general/home.html` | — | `home/upload.html` *(replaces — today's home is just an upload form)* | 2.1 |
| `general/recent.html` | — | `scans/list.html` | 2.2 |
| `general/tasks.html` | — | `scans/tasks.html` (drawer in scan list) | 2.2 |
| `general/view.html` | — | `scans/view.html` | 2.2 |
| `general/about.html` | — | `settings/about.html` | 2.3 |
| `general/apidocs.html` | — | `settings/api_docs.html` (kept as-is, restyled) | 2.3 |
| `general/error.html` | — | `errors/generic.html` (with new `403/404/500`) | 2.3 |
| `general/dynamic.html` | — | `dynamic/select.html` | 2.3 |
| `general/donate.html` | — | **REMOVED** (upstream MobInspect donations) |
| `general/zip.html` | — | `scans/zip.html` | 2.3 |
| `static_analysis/android_binary_analysis.html` | — | `reports/android/binary.html` | 2.2 |
| `static_analysis/android_source_analysis.html` | — | `reports/android/source.html` | 2.2 |
| `static_analysis/ios_binary_analysis.html` | — | `reports/ios/binary.html` | 2.2 |
| `static_analysis/ios_source_analysis.html` | — | `reports/ios/source.html` | 2.2 |
| `static_analysis/windows_binary_analysis.html` | — | `reports/windows/binary.html` | 2.3 |
| `static_analysis/appsec_dashboard.html` | — | `reports/appsec.html` | 2.2 |
| `static_analysis/compare.html` | — | `scans/compare.html` | 2.2 |
| `static_analysis/source_tree.html` | — | `reports/shared/source_tree.html` | 2.2 |
| `static_analysis/treeview_file.html` | — | `reports/shared/treeview_file.html` | 2.2 |
| `static_analysis/treeview_folder.html` | — | `reports/shared/treeview_folder.html` | 2.2 |
| `dynamic_analysis/android/*.html` | — | `dynamic/android/*.html` | 2.3 |
| `dynamic_analysis/ios/*.html` | — | `dynamic/ios/*.html` | 2.3 |
| `dynamic_analysis/ios/device/*.html` | — | `dynamic/ios_device/*.html` | 2.3 |
| `pdf/*_report.html` | — | unchanged (used for PDF export only) |
| `403.html` `404.html` `500.html` | — | `errors/*.html` | 2.3 |
| — | — | `analytics/trends.html` | 2.4 (new) |
| — | — | `analytics/severity.html` | 2.4 (new) |
| — | — | `analytics/coverage.html` | 2.4 (new) |
| — | — | `settings/profile.html` | 2.5 (new) |
| — | — | `settings/api_keys.html` | 2.5 (new) |
| — | — | `settings/audit_log.html` | 2.5 (new) |
| — | — | `rbac/roles/list.html` | 2.5 (new) |
| — | — | `rbac/roles/edit.html` | 2.5 (new) |
| — | — | `rbac/permissions.html` | 2.5 (new) |

Phase numbering matches [08 — Roadmap](08-roadmap.md).

## Routing changes (target)

The `mobinspect.MobInspect.urls` module gains:

```python
# Dashboard (replaces today's `/` which is the upload form)
re_path(r'^$', dashboard.index, name='dashboard'),
re_path(r'^upload/$', scanning.upload, name='upload'),  # was '/'
re_path(r'^scans/$', scans.list_view, name='scans:list'),

# RBAC
re_path(r'^rbac/roles/$', rbac.roles_list, name='rbac:roles_list'),
re_path(r'^rbac/roles/new/$', rbac.role_create, name='rbac:role_create'),
re_path(r'^rbac/roles/(?P<id>[0-9]+)/$', rbac.role_edit, name='rbac:role_edit'),
re_path(r'^rbac/permissions/$', rbac.permissions_browse, name='rbac:permissions'),

# Analytics
re_path(r'^analytics/trends/$', analytics.trends, name='analytics:trends'),
re_path(r'^analytics/severity/$', analytics.severity, name='analytics:severity'),
re_path(r'^analytics/coverage/$', analytics.coverage, name='analytics:coverage'),

# Settings
re_path(r'^settings/profile/$', settings_views.profile, name='settings:profile'),
re_path(r'^settings/api-keys/$', settings_views.api_keys, name='settings:api_keys'),
re_path(r'^settings/audit-log/$', settings_views.audit_log, name='settings:audit_log'),
```

Existing routes (`/login`, `/api/v1/...`, `/static_analyzer/...`, etc.) keep their paths to avoid breaking external integrations.

## URL philosophy

- Lowercase, hyphens (not underscores) for new URLs
- Plural collections (`/scans/`, `/roles/`) — singular for actions (`/upload`, `/login`)
- API stays at `/api/v1/` — bumped to `/api/v2/` only if a breaking change happens
- Static content served from `/static/mobinspect/` — clear separation from `/static/adminlte/` during migration
