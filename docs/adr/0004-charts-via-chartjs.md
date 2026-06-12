# ADR 0004 — Charts via Chart.js

**Status**: Accepted
**Date**: 2026-05-05

## Context

The analytics dashboard needs charts: line, area, donut, bar, gauge. Options:

1. **Chart.js 4**
2. **ApexCharts**
3. **D3.js** (custom)
4. **ECharts**
5. **Recharts / Visx** (React-only — eliminated by ADR 0003)

## Decision

**Chart.js 4** with `chartjs-plugin-zoom` for time-series interaction.

## Reasoning

| Criterion | Chart.js | ApexCharts | D3 | ECharts |
|-----------|----------|-----------|-----|---------|
| Bundle size | ~70 KB | ~140 KB | ~80 KB (core only) | ~330 KB |
| Theme via CSS vars | ✓ (we wrote a wrapper) | partial | manual | manual |
| Mature | ✓ | ✓ | ✓ | ✓ |
| MIT license | ✓ | ✓ | ✓ | Apache-2 |
| Built-in chart types we need | ✓ | ✓ | ✗ (build it) | ✓ |
| Active maintenance | ✓ | ✓ | ✓ | ✓ (Apache foundation) |

Chart.js wins on **bundle size** and **theming ergonomics** for our specific list of charts. ApexCharts has prettier defaults but is twice the size and harder to theme.

D3 is overkill — we want charts, not bespoke dataviz primitives.

## Theming integration

A single wrapper at `mobsf/static/mobinspect/js/chart-theme.js` reads CSS variables from the active theme:

```js
const styles = getComputedStyle(document.documentElement);
Chart.defaults.color = styles.getPropertyValue('--text-secondary');
Chart.defaults.borderColor = styles.getPropertyValue('--border-subtle');
Chart.defaults.font.family = 'Inter, system-ui, sans-serif';
```

Charts re-render on theme change (we listen to a `theme:change` custom event from the theme toggle).

## Consequences

### Pros
- Small bundle, mature, well-documented
- Theme-aware via CSS variables — a single change in `tailwind.config.js` propagates
- Plugin ecosystem for niche needs (zoom, annotations, gradients)

### Cons
- Default Chart.js look is dated; we override most defaults via the wrapper
- No native gauge type — we use a half-donut hack for the fleet-health gauge
- For very large datasets (>10k points), Chart.js performance degrades. Not a concern at our scale.

## Versioning

Pinned to a specific minor version in the vendored copy under `static/mobinspect/vendor/chart.js`. Upgrades go through a deliberate audit step.
