/**
 * MobInspect — theme manager.
 *
 * Reads/writes localStorage('mi-theme') with values:
 *   'light' | 'dark' | 'system'
 *
 * The no-flicker bootstrap (set <html data-theme=...> before paint)
 * is inlined in <head>; see mobsf/MobSF/templatetags/theme.py.
 *
 * This file adds the user-facing toggle behavior + Chart.js refresh hook.
 */
(function () {
  'use strict';

  const STORAGE_KEY = 'mi-theme';
  const VALID = ['light', 'dark', 'system'];

  function systemPref() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches
      ? 'dark'
      : 'light';
  }

  function resolve(value) {
    return value === 'system' ? systemPref() : value;
  }

  function apply(value) {
    const effective = resolve(value);
    document.documentElement.setAttribute('data-theme', effective);
    document.documentElement.setAttribute('data-theme-pref', value);
    // Notify listeners (Chart.js wrapper, etc.)
    window.dispatchEvent(new CustomEvent('mi:theme-change', {
      detail: { value, effective },
    }));
  }

  function get() {
    const v = localStorage.getItem(STORAGE_KEY);
    return VALID.includes(v) ? v : 'system';
  }

  function set(value) {
    if (!VALID.includes(value)) return;
    localStorage.setItem(STORAGE_KEY, value);
    apply(value);
  }

  function cycle() {
    const order = ['light', 'dark', 'system'];
    const current = get();
    const next = order[(order.indexOf(current) + 1) % order.length];
    set(next);
    return next;
  }

  // Re-apply when system pref changes if user is in 'system' mode.
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener(
    'change',
    () => { if (get() === 'system') apply('system'); },
  );

  window.MI = window.MI || {};
  window.MI.theme = { get, set, cycle, apply, resolve, systemPref };
})();
