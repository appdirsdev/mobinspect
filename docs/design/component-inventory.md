# Component Inventory

Every UI component the redesign requires. Each one becomes a Django include under `mobsf/templates/components/<name>.html`.

Status: `□` not started · `▣` in progress · `■` done

## Inputs

- □ `button` — variants: primary / secondary / ghost / danger / link · sizes: sm / md / lg · loading state · icon-leading / icon-trailing
- □ `icon_button` — square, icon-only, optional badge dot
- □ `input` — text input with label, hint, error, optional leading/trailing icon
- □ `textarea` — auto-resize, char counter
- □ `select` — native styled, plus searchable variant via Alpine
- □ `checkbox` — with label and hint
- □ `radio` — with label
- □ `toggle` — animated thumb
- □ `file_upload` — drag-drop dropzone, multi-file, progress
- □ `search` — global search bar with `⌘K` hint
- □ `color_picker` — for role color (preset palette only)
- □ `icon_picker` — for role icon (Lucide grid)

## Containers

- □ `card` — header / body / footer slots; optional actions slot
- □ `panel` — borderless, full-bleed
- □ `modal` — focus-trapped, ESC-to-close, sizes sm / md / lg
- □ `drawer` — slide-in from right, used for finding details
- □ `tabs` — horizontal, animated underline, keyboard-navigable
- □ `accordion` — for collapsible sections in long reports
- □ `disclosure` — single expand/collapse

## Data display

- □ `table` — sortable headers, sticky header, row hover, bulk-select checkbox
- □ `pagination` — page-size selector, jump-to-page
- □ `badge` — variants: severity (critical/high/medium/low/passed/unknown), role, status
- □ `tag` — removable, color-coded
- □ `pill` — non-interactive label
- □ `metric` — large number + delta arrow + sparkline
- □ `chart_line` — Chart.js line wrapper (theme-aware)
- □ `chart_bar` — Chart.js bar wrapper
- □ `chart_donut` — Chart.js doughnut wrapper
- □ `chart_area` — Chart.js stacked area wrapper
- □ `gauge` — half-donut for fleet health
- □ `code_block` — syntax-highlighted, copy button, expandable
- □ `kbd` — keyboard hint pill (`⌘K`)
- □ `avatar` — initials or image, sizes xs / sm / md / lg
- □ `progress_bar` — determinate / indeterminate
- □ `score_donut` — AppSec score 0–100, severity-themed ring

## Feedback

- □ `toast` — top-right stack, auto-dismiss with hover-pause
- □ `alert` — inline persistent message (info/warning/error/success)
- □ `empty_state` — icon + title + body + optional CTA
- □ `skeleton_text` — single-line placeholder
- □ `skeleton_card` — card-shaped placeholder
- □ `skeleton_table` — N rows of placeholder
- □ `tooltip` — Alpine-driven, on hover/focus, positioned
- □ `popover` — click-triggered, used for filter menus
- □ `confirm_dialog` — modal preset for destructive actions

## Navigation

- □ `sidebar` — collapsible, role-aware items, collapsible sections
- □ `topbar` — search, notifications, theme toggle, user menu
- □ `breadcrumbs` — auto-generated
- □ `command_palette` — `⌘K` global search
- □ `notification_bell` — badge with unread count, click to open drawer

## Domain-specific

- □ `severity_badge` — color + label + CVSS score
- □ `role_badge` — role color + name + icon
- □ `permission_chip` — codename + category color, used in role editor
- □ `app_card` — icon + name + version + recent scan summary + score
- □ `finding_row` — used in static analysis report tables
- □ `scan_status_pill` — pending / running / done / failed
- □ `cvss_vector` — formatted vector with subscore breakdown on hover
- □ `cwe_link` — clickable CWE id with external link icon
- □ `masvs_link` — clickable MASVS id

## Layout primitives

- □ `page_header` — title + breadcrumbs + action slot
- □ `section_header` — secondary title + optional action
- □ `divider` — horizontal rule with optional label
- □ `flex_row` — common flex wrapper with gap
- □ `stat_strip` — KPI row container

## Implementation order

Match the component build order to Phase 2 page rollout:

1. **Phase 0**: button, input, card, badge, lucide tag, theme toggle, toast — enough to render the playground
2. **Phase 1**: table, modal, confirm_dialog, tooltip, alert, role_badge, permission_chip, color/icon pickers — for the RBAC admin
3. **Phase 2.1**: sidebar, topbar, breadcrumbs, page_header, alert, empty_state, skeleton_*
4. **Phase 2.2**: tabs, drawer, code_block, severity_badge, finding_row, score_donut, scan_status_pill
5. **Phase 2.3**: app_card, accordion, cvss_vector, cwe_link, masvs_link
6. **Phase 2.4**: chart_*, gauge, metric, stat_strip
7. **Phase 2.5**: command_palette, notification_bell, popover, file_upload (refresh)
