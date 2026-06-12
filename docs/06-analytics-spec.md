# 06 — Analytics Specification

## Goal

Give every user — analyst, manager, auditor — a fast, glanceable view of:

1. **What's happening now?** (dashboard KPI strip)
2. **How are we trending?** (time series)
3. **Where's the risk concentrated?** (severity, top CWEs, top apps)
4. **Are we keeping up?** (throughput, coverage, queue depth)

Analytics is **read-only** and gated by `analytics.view`. Export is gated by `analytics.export`.

## Dashboard layout

```
┌────────────────────────────────────────────────────────────────────────────┐
│  Topbar (search · notifications · theme · user)                            │
├──────────┬─────────────────────────────────────────────────────────────────┤
│          │  ┌─────────┬─────────┬─────────┬─────────┐                      │
│ Sidebar  │  │ Total   │ Critical│ Avg     │ Scans   │  ← KPI strip         │
│          │  │ scans   │ findings│ AppSec  │ this    │                      │
│          │  │  1,247  │   34 ↓  │   72/100│  week   │                      │
│          │  │ +12% ▲  │ -8% ▼   │ +3 ▲    │  47 ▲   │                      │
│          │  └─────────┴─────────┴─────────┴─────────┘                      │
│          │                                                                 │
│          │  ┌──────────────────────────────┬───────────────────────────┐   │
│          │  │ Scan trends         30d 60d  │ Severity breakdown        │   │
│          │  │  ▁▂▃▅▇▆▅▄▃▂▁▂▃▅▇█▆▅▄▃▂▁     │  ◯ critical ◯ high ◯ med  │   │
│          │  │ (line)                       │  ◯ low ◯ passed (donut)   │   │
│          │  └──────────────────────────────┴───────────────────────────┘   │
│          │                                                                 │
│          │  ┌──────────────────────────────┬───────────────────────────┐   │
│          │  │ Top vulnerable apps          │ Recent activity (timeline)│   │
│          │  │ com.example.app    score 41  │ • scan completed 2m ago   │   │
│          │  │ com.example.bank   score 53  │ • role granted 17m ago    │   │
│          │  │ com.example.health score 67  │ • finding suppressed 1h   │   │
│          │  └──────────────────────────────┴───────────────────────────┘   │
│          │                                                                 │
│          │  ┌────────────────────────────────────────────────────────────┐ │
│          │  │ Fleet health    72% of apps scanned in last 30 days        │ │
│          │  │ (gauge + per-app age table)                                │ │
│          │  └────────────────────────────────────────────────────────────┘ │
└──────────┴─────────────────────────────────────────────────────────────────┘
```

## Widgets

### KPI strip

Four metrics, each: large number · period delta · sparkline.

| Metric | Source | Period | Cache |
|--------|--------|--------|-------|
| Total scans | `count(StaticAnalyzerAndroid + StaticAnalyzerIOS + StaticAnalyzerWindows)` | last 7d vs prior 7d | 5 min |
| Critical findings | `count(Finding) where severity='critical'` | last 7d vs prior 7d | 5 min |
| Average AppSec score | `avg(AppSecScore)` over scans in period | last 7d vs prior 7d | 5 min |
| Scans this week | week-to-date scan count | WTD vs same period last week | 1 min |

### Scan trends (line)

- X: time bucket (day for ≤30d, week for ≤90d, month otherwise)
- Y: scan count
- Two series: total scans, scans with critical findings (overlaid)
- Toggles: 7d / 30d / 90d / 1y
- Source: `StaticAnalyzer*.objects.annotate(d=TruncDay('TIMESTAMP')).values('d').annotate(c=Count('id'))`

### Severity breakdown (donut)

- Findings in the selected period (default: last 30d), grouped by severity
- Click slice → filtered findings list
- Source: aggregate of code-analysis findings + binary findings + manifest findings

### Top vulnerable apps (table)

- Columns: App icon · Package · Latest scan date · AppSec score · Critical / High count · → link
- Default sort: AppSec score asc (worst first)
- 10 rows, "View all" → analytics → coverage

### Recent activity (timeline)

- Last 20 events from `AuditEvent` + scan completion events, merged
- Icons differentiate event types
- Relative timestamps (2m ago) with absolute on hover

### Fleet health (gauge + table)

- Gauge: % of distinct apps scanned in last 30d, color-coded by threshold
- Below: per-app last-scan age, sortable

## Analytics pages

### Trends

- Same data as dashboard scan trends but with multiple overlay options
- Toggleable series: total scans, critical findings, suppressed findings, average score, queue depth

### Severity over time

- Stacked area chart, severities on Y, time on X
- Highlights spikes; clicking a spike opens findings filtered to that day + severity

### Top CWEs

- Horizontal bar chart of top 20 CWE / OWASP MASVS categories by occurrence
- Period selector (30 / 90 / 365d)

### Coverage

- Per-app table with: app, package, last scan, scan age, # scans, current score
- Filters: scan age > N days, score < N, never-scanned

### Throughput

- Queue depth over time (line)
- Scan duration percentiles (p50/p90/p99) by analyzer type
- Failure rate

## Data model — additions

To make analytics fast, two materialized aggregates:

```python
# mobinspect/Analytics/models.py

class DailyScanRollup(models.Model):
    """One row per day per platform — populated by a daily django-q2 job."""
    day = models.DateField(db_index=True)
    platform = models.CharField(max_length=10)  # android | ios | windows
    scan_count = models.PositiveIntegerField(default=0)
    critical_count = models.PositiveIntegerField(default=0)
    high_count = models.PositiveIntegerField(default=0)
    medium_count = models.PositiveIntegerField(default=0)
    low_count = models.PositiveIntegerField(default=0)
    avg_score = models.FloatField(null=True)
    failed_count = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = [('day', 'platform')]

class FindingFact(models.Model):
    """Denormalized finding row, populated when a scan completes."""
    scan_md5 = models.CharField(max_length=32, db_index=True)
    platform = models.CharField(max_length=10, db_index=True)
    package = models.CharField(max_length=200, db_index=True)
    severity = models.CharField(max_length=20, db_index=True)
    cwe = models.CharField(max_length=20, blank=True, db_index=True)
    masvs = models.CharField(max_length=20, blank=True)
    rule_id = models.CharField(max_length=100, blank=True)
    title = models.CharField(max_length=400)
    is_suppressed = models.BooleanField(default=False)
    occurred_at = models.DateTimeField(db_index=True)
```

These tables are derived — they can be rebuilt from primary scan data at any time. A management command `mobinspect rebuild_analytics` does this.

## Performance budget

- Dashboard initial render: **≤200 ms p95** server time, **≤800 ms p95** TTFB
- Each widget can be fetched independently via HTMX so a slow query doesn't block the rest of the page
- All widget endpoints cache for 60s by default; KPIs cache for 5 min
- No N+1: every endpoint uses a single aggregated query

## Export

- `analytics.export` permission required
- CSV download per widget (timeseries → CSV with date column)
- Full dashboard PDF export uses the same `pdfkit` pipeline already in use for scan reports
