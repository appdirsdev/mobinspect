/**
 * MobInspect — Chart.js theme integration.
 *
 * Reads CSS variables from the active theme and applies them to
 * Chart.js global defaults. Re-runs when the theme changes.
 *
 * Load order: chart.umd.min.js  →  theme.js  →  chart-theme.js
 */
(function () {
  'use strict';

  if (typeof Chart === 'undefined') return;

  function readVar(name) {
    const v = getComputedStyle(document.documentElement)
      .getPropertyValue(name).trim();
    return v ? `rgb(${v.replace(/\s+/g, ' ')})` : null;
  }

  function applyTheme() {
    Chart.defaults.font.family =
      'Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
    Chart.defaults.font.size = 12;
    Chart.defaults.color           = readVar('--text-secondary') || '#64748B';
    Chart.defaults.borderColor     = readVar('--border-subtle')  || '#E2E8F0';
    Chart.defaults.scale.grid.color = readVar('--border-subtle') || '#E2E8F0';
    Chart.defaults.plugins.tooltip.backgroundColor = readVar('--surface-4') || '#1F2937';
    Chart.defaults.plugins.tooltip.titleColor      = readVar('--text-primary') || '#0F172A';
    // Body uses text-PRIMARY (not secondary) for AA contrast on the dark
    // tooltip background — secondary measured ~3.2:1 on surface-4.
    Chart.defaults.plugins.tooltip.bodyColor       = readVar('--text-primary') || '#0F172A';
    // Honor reduced-motion app-wide: Chart.js entrance animations can't be
    // reached by the CSS reduced-motion rule (they run on <canvas>), so gate
    // them here. Only DISABLE for reduced motion (a valid `false`); never
    // replace the animation object wholesale with a plain {duration,easing}
    // literal — that strips Chart.js's internal animation structure and
    // throws "this._fn is not a function", blanking the canvas.
    if (window.matchMedia &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      Chart.defaults.animation = false;
    }
    Chart.defaults.plugins.tooltip.borderColor     = readVar('--border-default') || '#CBD5E1';
    Chart.defaults.plugins.tooltip.borderWidth     = 1;
    Chart.defaults.plugins.tooltip.padding         = 12;
    Chart.defaults.plugins.tooltip.cornerRadius    = 10;
    Chart.defaults.plugins.tooltip.titleFont       = { weight: '600' };
    Chart.defaults.plugins.tooltip.bodySpacing     = 4;
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.legend.labels.boxHeight = 6;

    // Re-render any existing charts.
    if (Chart.instances) {
      Object.values(Chart.instances).forEach((c) => c.update('none'));
    }
  }

  // Initial application.
  if (document.readyState !== 'loading') {
    applyTheme();
  } else {
    document.addEventListener('DOMContentLoaded', applyTheme);
  }

  // Re-apply on theme change.
  window.addEventListener('mi:theme-change', applyTheme);
})();
